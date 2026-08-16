//! One trader of the FULL 2-party settlement session: MPC comparison,
//! fill reveal, output-commitment exchange, signature ferry, collaborative
//! prove, local verify — everything crypto over one QUIC connection.
//!
//! The host app drives this binary over piped stdio:
//! - stdout: JSON lines — `{"event":"phase","name":...,"msg":...}` progress,
//!   one `{"event":"need_sig",...}` request, and a final `{"event":"done"}`.
//! - stdin: exactly one line `{"sig":"<128-hex>"}` answering `need_sig`.
//!
//! Files written to --out-dir: `witness.json` (crash-recovery record,
//! written BEFORE the signature leaves this process), `result.json` (the
//! session product), `stats.json` (timings + peak RSS).
//!
//! DEV CAVEAT: Beaver triples come from the mock `PartyIDBeaverSource`;
//! production needs a real SPDZ offline phase.
//!
//! `--warm-keys` generates/loads the proving keys and exits — run it at app
//! startup to move the ~48 s cold key generation off the settlement path.

use std::{
    fs,
    io::{BufRead, Write as IoWrite},
    net::SocketAddr,
    path::PathBuf,
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow};
use ark_mpc::{MpcFabric, PARTY0, PARTY1, offline_prep::PartyIDBeaverSource};
use clap::{Parser, ValueEnum};
use cozk2p::{
    default_cache_dir, dev_keys,
    net::connect_retry,
    session::{NeedSig, SessionConfig, SessionInput, SigIo, run_session, sanity_check_input},
    stats::peak_rss_bytes,
};
use serde_json::json;

#[derive(Debug, Clone, Copy, ValueEnum)]
enum RoleArg {
    /// PARTY0 — the maker; dials the peer.
    TraderA,
    /// PARTY1 — the taker; listens for the peer.
    TraderB,
}

#[derive(Parser)]
#[command(about = "One trader of the full 2-party collaborative settlement session")]
struct Args {
    #[arg(long, value_enum, required_unless_present = "warm_keys")]
    role: Option<RoleArg>,
    /// Local QUIC bind address.
    #[arg(long, required_unless_present = "warm_keys")]
    listen: Option<SocketAddr>,
    /// Counterparty QUIC address (used by the dialer; the listener accepts
    /// whoever connects).
    #[arg(long, required_unless_present = "warm_keys")]
    peer: Option<SocketAddr>,
    /// SessionInput JSON (chain-sourced publics + this trader's witness).
    #[arg(long, required_unless_present = "warm_keys")]
    input: Option<PathBuf>,
    /// Output directory for witness.json / result.json / stats.json.
    #[arg(long, required_unless_present = "warm_keys")]
    out_dir: Option<PathBuf>,
    /// Proving/verifying key cache directory. Always pass this explicitly
    /// from the app (the compiled-in default points into the build tree).
    #[arg(long)]
    keys_dir: Option<PathBuf>,
    /// Generate/load the proving keys into the cache and exit.
    #[arg(long, default_value_t = false)]
    warm_keys: bool,
    /// Connect deadline in seconds for both dialer retries and the
    /// listener accept.
    #[arg(long, default_value_t = 60)]
    connect_deadline: u64,
}

/// Print one JSON line to stdout and flush immediately — stdout is
/// block-buffered when piped, and the host app parses line by line.
fn emit_line(value: serde_json::Value) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{value}");
    let _ = out.flush();
}

/// Emit a phase progress line.
fn emit_phase(name: &str, msg: &str) {
    emit_line(json!({"event": "phase", "name": name, "msg": msg}));
}

/// Stdio signature ferry: prints `need_sig` and waits for one stdin line.
/// The stdin read runs on a helper thread so it can be bounded by a
/// timeout; the process exits soon after either outcome, so a lingering
/// blocked reader thread is acceptable.
struct StdioSigIo {
    timeout: Duration,
}

impl SigIo for StdioSigIo {
    /// Request this trader's settlement signature from the host app.
    fn request_sig(&mut self, need: &NeedSig) -> Result<String> {
        emit_line(json!({
            "event": "need_sig",
            "cmp": need.cmp,
            "new_order_a": need.new_order_a,
            "new_order_b": need.new_order_b,
            "new_locked_a": need.new_locked_a,
            "new_locked_b": need.new_locked_b,
            "recv_a": need.recv_a,
            "recv_b": need.recv_b,
        }));

        let (tx, rx) = mpsc::channel::<std::io::Result<String>>();
        thread::spawn(move || {
            let stdin = std::io::stdin();
            let mut line = String::new();
            let result = stdin.lock().read_line(&mut line).map(|_| line);
            let _ = tx.send(result);
        });
        let line = rx
            .recv_timeout(self.timeout)
            .map_err(|_| anyhow!("timed out waiting for the host to provide a signature"))?
            .context("reading signature from stdin")?;

        #[derive(serde::Deserialize)]
        struct SigLine {
            sig: String,
        }
        let parsed: SigLine =
            serde_json::from_str(line.trim()).context("parsing signature line from host")?;
        Ok(parsed.sig)
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let args = Args::parse();
    let keys_dir = args.keys_dir.unwrap_or_else(default_cache_dir);

    if args.warm_keys {
        emit_phase("keys", "warming the proving-key cache");
        dev_keys(&keys_dir)?;
        emit_line(json!({"event": "done"}));
        return Ok(());
    }

    // Clap guarantees these are present when --warm-keys is absent.
    let role = args.role.expect("role required");
    let listen = args.listen.expect("listen required");
    let peer = args.peer.expect("peer required");
    let input_path = args.input.expect("input required");
    let out_dir = args.out_dir.expect("out-dir required");

    let party = match role {
        RoleArg::TraderA => PARTY0,
        RoleArg::TraderB => PARTY1,
    };

    let input: SessionInput =
        serde_json::from_str(&fs::read_to_string(&input_path).context("reading --input")?)
            .context("parsing SessionInput")?;

    // Fail fast on corrupt local records before any networking.
    sanity_check_input(&input)?;

    // Keys first so the peer never waits on our (possibly cold) keygen
    // while holding a connection open.
    emit_phase(
        "keys",
        "loading proving keys (first run generates them, ~1 min)",
    );
    let (pk, vk) = dev_keys(&keys_dir)?;

    emit_phase("connect", "connecting to the counterparty");
    let total_start = Instant::now();
    let net = connect_retry(party, listen, peer, args.connect_deadline).await?;
    // Mock Beaver source: dev only (see module docs).
    let fabric = MpcFabric::new(net, PartyIDBeaverSource::new(party));

    let mut sig_io = StdioSigIo {
        timeout: Duration::from_secs(120),
    };
    let result = run_session(
        fabric,
        party,
        &input,
        &mut sig_io,
        SessionConfig {
            pk: &pk,
            vk: &vk,
            out_dir: &out_dir,
        },
        |name, msg| emit_phase(name, msg),
    )
    .await?;
    let total_ms = total_start.elapsed().as_secs_f64() * 1e3;

    fs::create_dir_all(&out_dir)?;
    fs::write(
        out_dir.join("result.json"),
        serde_json::to_string_pretty(&result)?,
    )
    .context("writing result.json")?;
    let stats = json!({
        "role": input.role,
        "cmp": result.cmp,
        "build_ms": result.timings.build_ms,
        "prove_ms": result.timings.prove_ms,
        "open_ms": result.timings.open_ms,
        "total_ms": total_ms,
        "peak_rss_bytes": peak_rss_bytes(),
        "proof_size_bytes_compressed": result.proof_hex.len() / 2,
    });
    fs::write(
        out_dir.join("stats.json"),
        serde_json::to_string_pretty(&stats)?,
    )
    .context("writing stats.json")?;

    emit_line(json!({"event": "done"}));
    Ok(())
}
