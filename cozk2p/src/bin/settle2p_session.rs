//! One trader of the FULL 2-party settlement session: MPC comparison,
//! fill reveal, output-commitment exchange, signature ferry, collaborative
//! prove, local verify — everything crypto over one QUIC connection.
//!
//! The host app drives this binary over piped stdio:
//! - stdout: JSON lines — `{"event":"phase",...}` progress, one
//!   `{"event":"need_sig",...}` request, one `{"event":"compare_ready",...}`
//!   request (carries π_cmp + both sigs), one `{"event":"result_ready"}`
//!   (result.json is on disk; the host proves its own settle leg), one
//!   `{"event":"pair_ready","a":...,"b":...}` (both legs exchanged over the
//!   still-open QUIC fabric, ready for an atomic SettlePair), and a final
//!   `{"event":"done"}`.
//! - stdin: one line `{"sig":"<128-hex>"}` answering `need_sig`, one line
//!   `{"compare_confirmed":true}` after the host lands the compare on
//!   chain (the reveal happens ONLY after that confirmation, so no secret
//!   precedes the on-chain anchor), and one line `{"settle_leg":{...}}`
//!   answering `result_ready`.
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

use anyhow::{Context, Result, anyhow, ensure};
use ark_mpc::{MpcFabric, PARTY0, PARTY1, offline_prep::PartyIDBeaverSource};
use clap::{Parser, ValueEnum};
use cozk2p::{
    default_cache_dir, dev_keys,
    net::connect_retry,
    session::{
        CompareReady, NeedSig, SessionConfig, SessionInput, SettleLeg, SigIo, exchange_settle_legs,
        run_session, sanity_check_input,
    },
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
    /// Window for the host to land the compare on chain and confirm — longer
    /// than the signature window, since block confirmation can be slow.
    compare_timeout: Duration,
}

/// Read one line from stdin with a timeout on a helper thread. The process
/// exits soon after, so a lingering blocked reader is acceptable.
fn read_stdin_line(timeout: Duration, what: &str) -> Result<String> {
    let (tx, rx) = mpsc::channel::<std::io::Result<String>>();
    thread::spawn(move || {
        let stdin = std::io::stdin();
        let mut line = String::new();
        let result = stdin.lock().read_line(&mut line).map(|_| line);
        let _ = tx.send(result);
    });
    rx.recv_timeout(timeout)
        .map_err(|_| anyhow!("timed out waiting for the host: {what}"))?
        .with_context(|| format!("reading {what} from stdin"))
}

impl SigIo for StdioSigIo {
    /// Request this trader's compare signature from the host app.
    fn request_sig(&mut self, need: &NeedSig) -> Result<String> {
        emit_line(json!({
            "event": "need_sig",
            "cmp": need.cmp,
        }));
        let line = read_stdin_line(self.timeout, "a signature")?;
        #[derive(serde::Deserialize)]
        struct SigLine {
            sig: String,
        }
        let parsed: SigLine =
            serde_json::from_str(line.trim()).context("parsing signature line from host")?;
        Ok(parsed.sig)
    }

    /// Hand the compare artifacts to the host and BLOCK until it confirms the
    /// comparison landed on chain (both orders Settling). Only then does the
    /// session proceed to the reveal, so no secret precedes the on-chain
    /// anchor.
    fn confirm_compare_onchain(&mut self, ready: &CompareReady) -> Result<()> {
        emit_line(json!({
            "event": "compare_ready",
            "ready": ready,
        }));
        let line = read_stdin_line(self.compare_timeout, "the compare on-chain confirmation")?;
        #[derive(serde::Deserialize)]
        struct ConfirmLine {
            compare_confirmed: bool,
        }
        let parsed: ConfirmLine = serde_json::from_str(line.trim())
            .context("parsing compare confirmation line from host")?;
        ensure!(
            parsed.compare_confirmed,
            "host reported the compare did not land on chain — aborting before any reveal"
        );
        Ok(())
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
        compare_timeout: Duration::from_secs(300),
    };
    let result = run_session(
        fabric.clone(),
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

    fs::create_dir_all(&out_dir)?;
    fs::write(
        out_dir.join("result.json"),
        serde_json::to_string_pretty(&result)?,
    )
    .context("writing result.json")?;

    // ── Settle-leg exchange over the still-open fabric: the host reads
    //    result.json, proves ITS settle circuit, and hands the leg back;
    //    both parties then hold both legs, so either can submit the atomic
    //    SettlePair. ──
    emit_line(json!({"event": "result_ready"}));
    let leg_line = read_stdin_line(Duration::from_secs(600), "the settle leg")?;
    #[derive(serde::Deserialize)]
    struct LegLine {
        settle_leg: SettleLeg,
    }
    let parsed: LegLine =
        serde_json::from_str(leg_line.trim()).context("parsing settle leg line from host")?;
    emit_phase("leg-exchange", "exchanging settle legs with the peer");
    let leg_start = Instant::now();
    let (leg_a, leg_b) = exchange_settle_legs(&fabric, party, &parsed.settle_leg).await?;
    let leg_exchange_ms = leg_start.elapsed().as_secs_f64() * 1e3;
    emit_line(json!({"event": "pair_ready", "a": leg_a, "b": leg_b}));

    let total_ms = total_start.elapsed().as_secs_f64() * 1e3;
    let stats = json!({
        "role": input.role,
        "cmp": result.cmp,
        "build_ms": result.timings.build_ms,
        "prove_ms": result.timings.prove_ms,
        "open_ms": result.timings.open_ms,
        "verify_ms": result.verify_ms,
        // Chain/host latencies, kept OUT of the cryptographic phases above:
        // the F1 on-chain compare confirmation and the settle-leg round.
        "compare_onchain_wait_ms": result.onchain_wait_ms,
        "leg_exchange_ms": leg_exchange_ms,
        // Per-protocol-step wall clock (docs/settlement_protocol.md §2.2),
        // in protocol order.
        "steps": result.steps.steps,
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
