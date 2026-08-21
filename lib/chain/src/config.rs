use std::{env, fs, path::PathBuf};

use clap::Parser;
use rand::RngCore;
use serde::Deserialize;
use yu_sdk::KeyPair;

// ────────────────────── Defaults ──────────────────────

const DEFAULT_HTTP_URL: &str = "http://localhost:7999";
const DEFAULT_WS_URL: &str = "ws://localhost:8999";

// ────────────────────── Config File Layout ──────────────────────

#[derive(Debug, Default, Deserialize)]
pub struct ClientConfig {
    #[serde(default)]
    pub chain: ChainConfig,
    #[serde(default)]
    pub keypair: KeypairConfig,
    /// Local data directory for mnemonic, notes.json, orders.json, etc.
    /// Defaults to `~/.invisibook`.
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
    /// Optional explicit path to the 2-party settlement helper binary.
    /// When unset, `settle2p_bin()` falls back to the env var / exe-adjacent
    /// lookup chain.
    #[serde(default)]
    pub settle2p_bin: Option<PathBuf>,
    /// Settlement flavor: "split" (default; compare-only MPC + per-side
    /// Groth16 legs) or "merged" (one collaborative proof for compare +
    /// both settle legs). Benchmark switch; see `settle2p_mode()`.
    #[serde(default)]
    pub settle2p_mode: Option<String>,
}

fn default_data_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".invisibook")
}

#[derive(Debug, Deserialize)]
pub struct ChainConfig {
    #[serde(default = "default_http_url")]
    pub http_url: String,
    #[serde(default = "default_ws_url")]
    pub ws_url: String,
    #[serde(default = "default_chain_id")]
    pub chain_id: u64,
}

#[derive(Debug, Default, Deserialize)]
pub struct KeypairConfig {
    #[serde(default)]
    pub mnemonic: String,
}

fn default_chain_id() -> u64 {
    1926
}

fn default_http_url() -> String {
    DEFAULT_HTTP_URL.to_string()
}
fn default_ws_url() -> String {
    DEFAULT_WS_URL.to_string()
}

impl Default for ChainConfig {
    fn default() -> Self {
        Self {
            http_url: default_http_url(),
            ws_url: default_ws_url(),
            chain_id: default_chain_id(),
        }
    }
}

// ────────────────────── CLI Arguments ──────────────────────

#[derive(Debug, Parser)]
#[command(about = "Invisibook client")]
pub struct CliArgs {
    /// Path to config file
    #[arg(short, long)]
    pub config: Option<String>,

    /// Chain HTTP RPC URL
    #[arg(long)]
    pub http_url: Option<String>,

    /// Chain WebSocket URL
    #[arg(long)]
    pub ws_url: Option<String>,

    /// BIP-39 mnemonic phrase (12 or 24 words)
    #[arg(long)]
    pub mnemonic: Option<String>,

    /// Local data directory (mnemonic, notes.json, etc.)
    #[arg(long)]
    pub data_dir: Option<PathBuf>,
}

// ────────────────────── Loading ──────────────────────

impl ClientConfig {
    /// Loads config by merging: defaults → config file → CLI args.
    /// Config file search order: explicit path > `./invisibook.toml` > `~/.invisibook/config.toml`.
    /// If no mnemonic is found, a random 24-word mnemonic is generated.
    pub fn load(path: Option<&str>) -> Self {
        let mut cfg = Self::load_file(path).unwrap_or_default();

        // Generate a random 24-word mnemonic if none was configured (32 bytes entropy)
        if cfg.keypair.mnemonic.is_empty() {
            let mut entropy = [0u8; 32];
            rand::rng().fill_bytes(&mut entropy);
            let m = bip39::Mnemonic::from_entropy(&entropy).expect("failed to generate mnemonic");
            cfg.keypair.mnemonic = m.to_string();
        }

        cfg
    }

    /// Loads config from CLI args, merging on top of file/defaults.
    /// Call this from binaries that accept command-line arguments.
    pub fn load_with_args() -> Self {
        let args = CliArgs::parse();
        let mut cfg = Self::load(args.config.as_deref());

        // CLI args override file/defaults
        if let Some(url) = args.http_url {
            cfg.chain.http_url = url;
        }
        if let Some(url) = args.ws_url {
            cfg.chain.ws_url = url;
        }
        if let Some(m) = args.mnemonic {
            cfg.keypair.mnemonic = m;
        }
        if let Some(d) = args.data_dir {
            cfg.data_dir = d;
        }

        cfg
    }

    /// Path to the mnemonic file inside the data directory.
    pub fn mnemonic_path(&self) -> PathBuf {
        self.data_dir.join("mnemonic")
    }

    /// Path to the note ledger inside the data directory (this file IS the
    /// wallet's money — see `note_store`).
    pub fn notes_path(&self) -> PathBuf {
        self.data_dir.join("notes.json")
    }

    /// Path to the order-opening ledger inside the data directory.
    pub fn orders_path(&self) -> PathBuf {
        self.data_dir.join("orders.json")
    }

    /// Resolves the 2-party settlement helper binary path, in order:
    /// the `settle2p_bin` config field, the `INVISIBOOK_SETTLE2P_BIN` env
    /// var, then a file named `settle2p_session` next to the current
    /// executable (only if it exists). Returns `None` if nothing matches.
    pub fn settle2p_bin(&self) -> Option<PathBuf> {
        if let Some(p) = &self.settle2p_bin {
            return Some(p.clone());
        }
        if let Ok(p) = env::var("INVISIBOOK_SETTLE2P_BIN") {
            return Some(PathBuf::from(p));
        }
        if let Ok(exe) = env::current_exe() {
            if let Some(dir) = exe.parent() {
                let candidate = dir.join("settle2p_session");
                if candidate.exists() {
                    return Some(candidate);
                }
            }
        }
        None
    }

    /// Resolves the settlement flavor: the `settle2p_mode` config field,
    /// then the `INVISIBOOK_SETTLE2P_MODE` env var, defaulting to "split".
    /// Returns the normalized lowercase mode string.
    pub fn settle2p_mode(&self) -> String {
        let raw = self
            .settle2p_mode
            .clone()
            .or_else(|| env::var("INVISIBOOK_SETTLE2P_MODE").ok())
            .unwrap_or_else(|| "split".to_string());
        raw.trim().to_lowercase()
    }

    /// Directory for 2-party settlement key material inside the data
    /// directory. Creating the directory is the caller's responsibility.
    pub fn settle2p_keys_dir(&self) -> PathBuf {
        self.data_dir.join("settle2p-keys")
    }

    /// Directory for 2-party settlement session state inside the data
    /// directory. Creating the directory is the caller's responsibility.
    pub fn settle2p_sessions_dir(&self) -> PathBuf {
        self.data_dir.join("settle2p").join("sessions")
    }

    /// Derives a 32-byte ed25519 seed from the mnemonic at index 0, path m/44'/60'/0'/0'/0'.
    pub fn seed(&self) -> Result<[u8; 32], Box<dyn std::error::Error>> {
        self.seed_at_index(0)
    }

    /// Derives a 32-byte ed25519 seed from the mnemonic at the given address index.
    /// Path: m/44'/60'/0'/0'/index' (all hardened, coin_type=60).
    pub fn seed_at_index(&self, index: u32) -> Result<[u8; 32], Box<dyn std::error::Error>> {
        let m = bip39::Mnemonic::parse(&self.keypair.mnemonic)?;
        let bip39_seed = m.to_seed("");
        Ok(crate::hd::derive_ed25519_key(&bip39_seed, 60, index))
    }

    /// Parses the mnemonic and returns a yu-sdk KeyPair for address index 0.
    pub fn keypair(&self) -> Result<KeyPair, Box<dyn std::error::Error>> {
        let seed = self.seed()?;
        Ok(KeyPair::from_ed25519_bytes(&seed))
    }

    /// Build a KeyPair directly from a 32-byte seed (for key import use).
    pub fn keypair_from_seed(seed: &[u8; 32]) -> Result<KeyPair, Box<dyn std::error::Error>> {
        Ok(KeyPair::from_ed25519_bytes(seed))
    }

    // ── internal ──

    fn load_file(path: Option<&str>) -> Option<Self> {
        if let Some(p) = path {
            let content = fs::read_to_string(p).ok()?;
            return toml::from_str(&content).ok();
        }

        // Try ./invisibook.toml
        let local = PathBuf::from("./invisibook.toml");
        if local.exists() {
            let content = fs::read_to_string(&local).ok()?;
            return toml::from_str(&content).ok();
        }

        // Try ~/.invisibook/config.toml
        if let Some(home) = dirs::home_dir() {
            let home_cfg = home.join(".invisibook").join("config.toml");
            if home_cfg.exists() {
                let content = fs::read_to_string(&home_cfg).ok()?;
                return toml::from_str(&content).ok();
            }
        }

        None
    }
}
