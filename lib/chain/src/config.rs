use std::fs;
use std::path::PathBuf;

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
    pub private_key: String,
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

    /// Hex-encoded ed25519 private key (64 hex chars)
    #[arg(long)]
    pub private_key: Option<String>,
}

// ────────────────────── Loading ──────────────────────

impl ClientConfig {
    /// Loads config by merging: defaults → config file → CLI args.
    /// Config file search order: explicit path > `./invisibook.toml` > `~/.invisibook/config.toml`.
    /// If no config file is found, defaults are used.
    pub fn load(path: Option<&str>) -> Self {
        let mut cfg = Self::load_file(path).unwrap_or_default();

        // Generate a random keypair if none was configured
        if cfg.keypair.private_key.is_empty() {
            let mut seed = [0u8; 32];
            rand::rng().fill_bytes(&mut seed);
            cfg.keypair.private_key = hex::encode(seed);
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
        if let Some(key) = args.private_key {
            cfg.keypair.private_key = key;
        }

        cfg
    }

    /// Parses the hex-encoded ed25519 private key seed into a yu-sdk KeyPair.
    pub fn keypair(&self) -> Result<KeyPair, Box<dyn std::error::Error>> {
        let bytes = hex::decode(&self.keypair.private_key)?;
        let seed: [u8; 32] = bytes
            .try_into()
            .map_err(|_| "private_key must be exactly 32 bytes (64 hex chars)")?;
        Ok(KeyPair::from_ed25519_bytes(&seed))
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
