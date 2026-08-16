//! Experiment harness for the 2-party collaborative settlement. Measures,
//! on the same relation and keys:
//!
//! - single-prover jellyfish TurboPlonk baseline (a trusted prover holding
//!   both sides' secrets),
//! - the FULL 2-party session in-process (mock duplex network) — the same
//!   `run_session` the app drives: MPC compare, fill reveal, output-
//!   commitment exchange, signature ferry, then the collaborative prove,
//! - the FULL 2-party session as two OS processes over QUIC, spawning the
//!   same `settle2p_session` binary the app spawns (real transport,
//!   per-process peak RSS),
//!
//! reporting wall-clock, peak memory, and proof sizes. Run in release:
//!
//!   cargo run --release --bin bench_settle2p -- --runs 5 --out results.json

use std::{
    fs,
    io::Write as _,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::Instant,
};

use anyhow::{Context, Result, ensure};
use ark_mpc::{PARTY0, test_helpers::execute_mock_mpc};
use ark_serialize::CanonicalSerialize;
use clap::Parser;
use cozk2p::{
    SidePrivate, compute_public, default_cache_dir, dev_keys,
    poseidon::{commit, fr_to_hex},
    prove_single, sample_trade,
    session::{LockedCash, MyPrivate, NeedSig, SessionConfig, SessionInput, SigIo, run_session},
    setup::circuit_size,
    stats::peak_rss_bytes,
    verify_settle,
};
use serde_json::{Value, json};

/// A fixed 128-hex dummy signature. The session ferries signatures
/// opaquely (only the host app / chain verify them), so the benchmark can
/// feed a placeholder without affecting timing.
const DUMMY_SIG: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                         aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// In-process signature ferry that returns the fixed dummy signature.
struct DummySigIo;

impl SigIo for DummySigIo {
    fn request_sig(&mut self, _need: &NeedSig) -> Result<String> {
        Ok(DUMMY_SIG.to_string())
    }
}

/// The `Poseidon(v, r)` commitment hex the chain would hold for `(v, r)`.
fn commit_hex(amount: u64, random: &[u8; 32]) -> String {
    fr_to_hex(&commit(amount, random))
}

/// Build both traders' `SessionInput`s for a sample trade — the same
/// chain-sourced publics + per-side witnesses the app assembles, so the
/// benchmark drives the FULL session (compare + reveal + exchange + prove),
/// not just the prove. Token/id fields are placeholders (no chain here).
fn build_session_inputs(
    a: &SidePrivate,
    b: &SidePrivate,
    price: u64,
    a_is_seller: bool,
) -> (SessionInput, SessionInput) {
    let zero = commit_hex(0, &[0u8; 32]);
    let order_a = commit_hex(a.order_amount, &a.r_order);
    let order_b = commit_hex(b.order_amount, &b.r_order);
    let pad = |locked: &[(u64, [u8; 32])]| -> [String; 2] {
        let mut out = [zero.clone(), zero.clone()];
        for (i, (amt, r)) in locked.iter().take(2).enumerate() {
            out[i] = commit_hex(*amt, r);
        }
        out
    };
    let locked_a = pad(&a.locked);
    let locked_b = pad(&b.locked);
    let my_priv = |s: &SidePrivate| MyPrivate {
        order_amount: s.order_amount,
        r_order: hex::encode(s.r_order),
        locked: s
            .locked
            .iter()
            .map(|(amt, r)| LockedCash {
                amount: *amt,
                random: hex::encode(r),
            })
            .collect(),
    };
    // Seller locks/receives token1/token2; the buyer is the opposite leg.
    let (a_lock, a_recv) = if a_is_seller {
        ("ETH", "USDT")
    } else {
        ("USDT", "ETH")
    };
    let common =
        |role: &str, my_id: &str, cash: &str, lock: &str, recv: &str, my: MyPrivate| SessionInput {
            role: role.to_string(),
            order_a_id: "order-a".into(),
            order_b_id: "order-b".into(),
            my_order_id: my_id.into(),
            my_input_cash_ids: vec![cash.into()],
            my_lock_token: lock.into(),
            my_recv_token: recv.into(),
            price,
            a_is_seller,
            order_a: order_a.clone(),
            order_b: order_b.clone(),
            locked_a: locked_a.clone(),
            locked_b: locked_b.clone(),
            my,
        };
    (
        common("trader-a", "order-a", "a-cash", a_lock, a_recv, my_priv(a)),
        common("trader-b", "order-b", "b-cash", a_recv, a_lock, my_priv(b)),
    )
}

#[derive(Parser)]
#[command(about = "Benchmark settle2p: 2-party collaborative vs single prover")]
struct Args {
    /// Measured runs per configuration.
    #[arg(long, default_value_t = 3)]
    runs: usize,
    /// Base port for the 2-process QUIC mode (each run uses a fresh pair).
    #[arg(long, default_value_t = 23411)]
    base_port: u16,
    /// Skip the 2-process QUIC mode.
    #[arg(long)]
    skip_quic: bool,
    /// Where to write the JSON report.
    #[arg(long, default_value = "settle2p_bench.json")]
    out: PathBuf,
}

/// Mean of a slice; 0.0 when empty.
fn mean(xs: &[f64]) -> f64 {
    if xs.is_empty() {
        0.0
    } else {
        xs.iter().sum::<f64>() / xs.len() as f64
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let args = Args::parse();
    let (a, b, price, a_is_seller) = sample_trade();
    let public = compute_public(&a, &b, price, a_is_seller)?;

    println!("=== setup (cached after first run) ===");
    let t = Instant::now();
    let (pk, vk) = dev_keys(&default_cache_dir())?;
    let gates = circuit_size()?;
    println!(
        "keys ready in {:.1} ms ({} gates)",
        t.elapsed().as_secs_f64() * 1e3,
        gates
    );

    // ── Baseline: single prover (trusted party holding both secrets) ──
    println!("=== baseline: single-prover TurboPlonk ===");
    let mut single_ms = Vec::new();
    let mut verify_ms = Vec::new();
    let mut proof_compressed = 0usize;
    let mut proof_uncompressed = 0usize;
    for _ in 0..args.runs {
        let t = Instant::now();
        let proof = prove_single(&a, &b, &public, &pk)?;
        single_ms.push(t.elapsed().as_secs_f64() * 1e3);
        let t = Instant::now();
        verify_settle(&vk, &public, &proof)?;
        verify_ms.push(t.elapsed().as_secs_f64() * 1e3);
        proof_compressed = proof.compressed_size();
        proof_uncompressed = proof.uncompressed_size();
    }
    println!(
        "single prove: {:.0} ms, verify: {:.1} ms, proof {} B compressed",
        mean(&single_ms),
        mean(&verify_ms),
        proof_compressed
    );

    // ── Full 2-party session, in-process (mock duplex channels) ──
    // Now the ENTIRE settlement session the app runs: MPC comparison, fill
    // reveal, output-commitment exchange, signature ferry, then the same
    // collaborative prove. `total` therefore includes the compare/reveal
    // overhead the pure-prove numbers omitted.
    println!("=== co-zk 2-party FULL session, in-process (mock network) ===");
    let (input_a, input_b) = build_session_inputs(&a, &b, price, a_is_seller);
    let session_tmp = std::env::temp_dir().join(format!("bench_settle2p_{}", std::process::id()));
    fs::create_dir_all(&session_tmp)?;
    let mut mock_runs = Vec::new();
    for run in 0..args.runs {
        let dir_a = session_tmp.join(format!("mock_{run}_a"));
        let dir_b = session_tmp.join(format!("mock_{run}_b"));
        let t = Instant::now();
        let (r0, _r1) = execute_mock_mpc(|fabric| {
            let (input_a, input_b, pk, vk) =
                (input_a.clone(), input_b.clone(), pk.clone(), vk.clone());
            let (dir_a, dir_b) = (dir_a.clone(), dir_b.clone());
            async move {
                let party = fabric.party_id();
                let (input, dir) = if party == PARTY0 {
                    (input_a, dir_a)
                } else {
                    (input_b, dir_b)
                };
                let mut sig_io = DummySigIo;
                run_session(
                    fabric.clone(),
                    party,
                    &input,
                    &mut sig_io,
                    SessionConfig {
                        pk: &pk,
                        vk: &vk,
                        out_dir: &dir,
                    },
                    |_, _| {},
                )
                .await
                .expect("full session must succeed")
            }
        })
        .await;
        let total_ms = t.elapsed().as_secs_f64() * 1e3;
        let tim = r0.timings;
        // Everything in `total` that is not the prove's own phases: the MPC
        // compare, the fill reveal, the commitment/signature exchange.
        let session_overhead_ms = (total_ms - tim.build_ms - tim.prove_ms - tim.open_ms).max(0.0);
        mock_runs.push(json!({
            "total_ms": total_ms,
            "session_overhead_ms": session_overhead_ms,
            "build_ms": tim.build_ms,
            "prove_ms": tim.prove_ms,
            "open_ms": tim.open_ms,
        }));
        println!(
            "  run: total {:.0} ms (compare+reveal+exchange ~{:.0}, prove build {:.0}/prove {:.0}/open {:.0})",
            total_ms, session_overhead_ms, tim.build_ms, tim.prove_ms, tim.open_ms
        );
    }

    // ── Full 2-party session, two OS processes over QUIC ──
    // Spawns the SAME `settle2p_session` binary the app spawns, over real
    // QUIC, feeding each child the dummy signature on stdin when it asks.
    let mut quic_runs = Vec::new();
    if !args.skip_quic {
        println!("=== co-zk 2-party FULL session, 2 processes over QUIC (localhost) ===");
        let session_bin = std::env::current_exe()?
            .parent()
            .map(|d| d.join("settle2p_session"))
            .filter(|p| p.exists())
            .context(
                "settle2p_session binary not found — build with `cargo build --release --bins`",
            )?;
        let keys_dir = default_cache_dir();
        fs::write(
            session_tmp.join("a_input.json"),
            serde_json::to_string(&input_a)?,
        )?;
        fs::write(
            session_tmp.join("b_input.json"),
            serde_json::to_string(&input_b)?,
        )?;

        for run in 0..args.runs {
            // Fresh port pair per run to avoid rebind races.
            let pa = args.base_port + (run as u16) * 2;
            let pb = pa + 1;
            let t = Instant::now();
            let mut children: Vec<Child> = Vec::new();
            for (role, input_file, listen, peer) in [
                // Listener (trader-b) first, dialer (trader-a) second.
                ("trader-b", "b_input.json", pb, pa),
                ("trader-a", "a_input.json", pa, pb),
            ] {
                let out_dir = session_tmp.join(format!("out_{role}"));
                let mut cmd = Command::new(&session_bin);
                cmd.arg("--role")
                    .arg(role)
                    .arg("--listen")
                    .arg(format!("127.0.0.1:{listen}"))
                    .arg("--peer")
                    .arg(format!("127.0.0.1:{peer}"))
                    .arg("--input")
                    .arg(session_tmp.join(input_file))
                    .arg("--out-dir")
                    .arg(&out_dir)
                    .arg("--keys-dir")
                    .arg(&keys_dir)
                    .stdin(Stdio::piped());
                let mut child = cmd.spawn()?;
                // Pre-feed the signature: the child buffers it and reads the
                // one line when it reaches its need_sig request.
                let mut stdin = child.stdin.take().context("child stdin")?;
                writeln!(stdin, "{{\"sig\":\"{DUMMY_SIG}\"}}")?;
                drop(stdin);
                children.push(child);
            }
            let mut ok = true;
            for c in children.iter_mut() {
                ok &= c.wait()?.success();
            }
            ensure!(ok, "a party process failed");
            let total_ms = t.elapsed().as_secs_f64() * 1e3;

            // Read each party's result + stats; the proofs must be identical.
            let mut per_party = Vec::new();
            let mut proofs = Vec::new();
            for role in ["trader-a", "trader-b"] {
                let dir = session_tmp.join(format!("out_{role}"));
                let stats: Value =
                    serde_json::from_str(&fs::read_to_string(dir.join("stats.json"))?)?;
                per_party.push(stats);
                let result: Value =
                    serde_json::from_str(&fs::read_to_string(dir.join("result.json"))?)?;
                proofs.push(result["proof_hex"].as_str().unwrap_or_default().to_string());
            }
            ensure!(proofs[0] == proofs[1], "parties revealed different proofs");

            println!(
                "  run: total {total_ms:.0} ms (incl. process startup + key load + full session)"
            );
            quic_runs.push(json!({ "total_ms": total_ms, "per_party": per_party }));
        }
    }

    let report = json!({
        "circuit_gates": gates,
        "public_signals": 15,
        "proof_size_bytes": {
            "compressed": proof_compressed,
            "uncompressed": proof_uncompressed,
        },
        "vk_size_bytes_compressed": vk.compressed_size(),
        "baseline_single_prover": {
            "prove_ms": single_ms,
            "verify_ms": verify_ms,
        },
        "cozk2p_mock_inprocess": mock_runs,
        "cozk2p_quic_2process": quic_runs,
        "bench_process_peak_rss_bytes": peak_rss_bytes(),
    });
    fs::write(&args.out, serde_json::to_string_pretty(&report)?)?;
    println!("\nreport written to {}", args.out.display());
    Ok(())
}
