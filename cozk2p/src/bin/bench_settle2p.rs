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
    net::SocketAddr,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::Instant,
};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use anyhow::{Context, Result, ensure};
use ark_mpc::{PARTY0, test_helpers::execute_mock_mpc};
use ark_serialize::CanonicalSerialize;
use clap::Parser;
use cozk2p::{
    SidePrivate, combine_compare_proof_shares, compute_public, decode_compare_proof_share_hex,
    default_cache_dir, dev_keys, needed_collateral,
    poseidon::{commit, fr_to_hex},
    prove_single, sample_trade,
    session::{CompareReady, MyPrivate, NeedSig, SessionConfig, SessionInput, SigIo, run_session},
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

/// In-process signature ferry that returns the fixed dummy signature and
/// simulates the F1 on-chain compare confirmation with a configurable
/// blocking delay (0 by default — the session records the wait separately,
/// so the crypto phases stay uncontaminated either way).
struct DummySigIo {
    confirm_delay: std::time::Duration,
}

impl SigIo for DummySigIo {
    fn request_sig(&mut self, _need: &NeedSig) -> Result<String> {
        Ok(DUMMY_SIG.to_string())
    }

    /// In-process bench: no chain; sleep for the configured stand-in delay.
    fn confirm_compare_onchain(&mut self, _ready: &CompareReady) -> Result<()> {
        if !self.confirm_delay.is_zero() {
            std::thread::sleep(self.confirm_delay);
        }
        Ok(())
    }
}

/// The `Poseidon(v, r)` commitment hex the chain would hold for `(v, r)`.
fn commit_hex(amount: u64, random: &[u8; 32]) -> String {
    fr_to_hex(&commit(amount, random))
}

/// Build both traders' `SessionInput`s for a sample trade — the same
/// chain-sourced publics + per-side witnesses the app assembles, so the
/// benchmark drives the FULL session (compare + reveal + key exchange +
/// prove), not just the prove. Token/id fields are placeholders (no chain
/// here). Collateral backs each order at the execution price so the
/// session's sanity checks pass.
fn build_session_inputs(
    a: &SidePrivate,
    b: &SidePrivate,
    price_a: u64,
    price_b: u64,
    execution_price: u64,
    a_is_seller: bool,
) -> (SessionInput, SessionInput) {
    // Locked-only model: each order's single on-chain commitment is
    // P2(needed(q, side), r_locked) — the same equation the relation and
    // the session use.
    let collateral = |amt: u64, price: u64, is_seller: bool| {
        needed_collateral(amt, price, is_seller).expect("sample collateral fits u64")
    };
    let locked_amt_a = collateral(a.order_amount, price_a, a_is_seller);
    let locked_amt_b = collateral(b.order_amount, price_b, !a_is_seller);
    let locked_a = commit_hex(locked_amt_a, &a.r_locked);
    let locked_b = commit_hex(locked_amt_b, &b.r_locked);
    let my_priv = |s: &SidePrivate| MyPrivate {
        order_amount: s.order_amount,
        r_locked: hex::encode(s.r_locked),
    };
    // Fresh npk per side: any in-range field element works for the bench.
    let npk_hex = |seed: u8| fr_to_hex(&commit(seed as u64, &[seed; 32]));
    let secret_a = StaticSecret::from([0x31u8; 32]);
    let secret_b = StaticSecret::from([0x32u8; 32]);
    let public_a = X25519PublicKey::from(&secret_a);
    let public_b = X25519PublicKey::from(&secret_b);
    // Seller locks/receives token1/token2; the buyer is the opposite leg.
    let (a_lock, a_recv) = if a_is_seller {
        ("ETH", "USDT")
    } else {
        ("USDT", "ETH")
    };
    let common = |role: &str, my_id: &str, lock: &str, recv: &str, npk: String, my: MyPrivate| {
        SessionInput {
            role: role.to_string(),
            order_a_id: "order-a".into(),
            order_b_id: "order-b".into(),
            my_order_id: my_id.into(),
            my_lock_token: lock.into(),
            my_recv_token: recv.into(),
            price_a,
            price_b,
            execution_price,
            a_is_seller,
            locked_a: locked_a.clone(),
            locked_b: locked_b.clone(),
            my_recv_npk: npk,
            my_refund_npk: npk_hex(if role == "trader-a" { 0x61 } else { 0x62 }),
            transport_secret: hex::encode(if role == "trader-a" {
                secret_a.to_bytes()
            } else {
                secret_b.to_bytes()
            }),
            peer_transport_pubkey: hex::encode(if role == "trader-a" {
                public_b.as_bytes()
            } else {
                public_a.as_bytes()
            }),
            my,
        }
    };
    (
        common(
            "trader-a",
            "order-a",
            a_lock,
            a_recv,
            npk_hex(0x51),
            my_priv(a),
        ),
        common(
            "trader-b",
            "order-b",
            a_recv,
            a_lock,
            npk_hex(0x52),
            my_priv(b),
        ),
    )
}

#[derive(Parser)]
#[command(about = "Benchmark settle2p: 2-party collaborative vs single prover")]
struct Args {
    /// Measured runs per configuration.
    #[arg(long, default_value_t = 3)]
    runs: usize,
    /// Unmeasured runs before the measured ones, per configuration. They
    /// warm the key cache, the allocator, and the OS page cache.
    #[arg(long, default_value_t = 0)]
    warmup: usize,
    /// Base port for the 2-process QUIC mode (each run uses a fresh pair).
    #[arg(long, default_value_t = 23411)]
    base_port: u16,
    /// Address trader A dials instead of trader B's own port. Point it at a
    /// delay relay (experiments/netdelay) to measure the session under an
    /// emulated round-trip time. With this flag every run reuses the SAME
    /// port pair, so one relay serves the whole sweep.
    #[arg(long)]
    quic_peer_a: Option<SocketAddr>,
    /// Skip the 2-process QUIC mode.
    #[arg(long)]
    skip_quic: bool,
    /// Skip the single-prover baseline.
    #[arg(long)]
    skip_single: bool,
    /// Skip the in-process (mock network) 2-party mode.
    #[arg(long)]
    skip_mock: bool,
    /// Stand-in for the F1 on-chain compare confirmation in the mock mode:
    /// each party blocks this long in `confirm_compare_onchain`. Reported
    /// as `onchain_wait_ms`, SEPARATE from the cryptographic phases.
    #[arg(long, default_value_t = 0)]
    confirm_delay_ms: u64,
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
    let (a, b, price_a, price_b, a_is_seller) = sample_trade();
    let public = compute_public(&a, &b, price_a, price_b, a_is_seller)?;

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
    // Always run once even when skipped, so the report still carries the
    // proof/VK sizes of this relation.
    let single_runs = if args.skip_single { 1 } else { args.runs };
    let single_warmup = if args.skip_single { 0 } else { args.warmup };
    println!("=== baseline: single-prover TurboPlonk ===");
    let mut single_ms = Vec::new();
    let mut verify_ms = Vec::new();
    let mut proof_compressed = 0usize;
    let mut proof_uncompressed = 0usize;
    for _ in 0..single_warmup {
        let proof = prove_single(&a, &b, &public, &pk)?;
        verify_settle(&vk, &public, &proof)?;
    }
    for _ in 0..single_runs {
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
    if args.skip_single {
        // The one run above only sized the proof; drop its timings.
        single_ms.clear();
        verify_ms.clear();
    }

    // ── Full 2-party session, in-process (mock duplex channels) ──
    // Now the ENTIRE settlement session the app runs: MPC comparison, fill
    // reveal, output-commitment exchange, signature ferry, then the same
    // collaborative prove. `total` therefore includes the compare/reveal
    // overhead the pure-prove numbers omitted.
    println!("=== co-zk 2-party FULL session, in-process (mock network) ===");
    let execution_price = if a_is_seller { price_a } else { price_b };
    let (input_a, input_b) =
        build_session_inputs(&a, &b, price_a, price_b, execution_price, a_is_seller);
    let session_tmp = std::env::temp_dir().join(format!("bench_settle2p_{}", std::process::id()));
    fs::create_dir_all(&session_tmp)?;
    let mut mock_runs = Vec::new();
    let confirm_delay = std::time::Duration::from_millis(args.confirm_delay_ms);
    let mock_total = if args.skip_mock {
        0
    } else {
        args.warmup + args.runs
    };
    for run in 0..mock_total {
        let dir_a = session_tmp.join(format!("mock_{run}_a"));
        let dir_b = session_tmp.join(format!("mock_{run}_b"));
        let t = Instant::now();
        let (r0, _r1) = execute_mock_mpc(|fabric| {
            let (input_a, input_b, pk, vk) =
                (input_a.clone(), input_b.clone(), pk.clone(), vk.clone());
            let (dir_a, dir_b) = (dir_a.clone(), dir_b.clone());
            async move {
                let party = fabric.party_id();
                let i_am_a = party == PARTY0;
                let (input, dir) = if i_am_a {
                    (input_a, dir_a)
                } else {
                    (input_b, dir_b)
                };
                let mut sig_io = DummySigIo { confirm_delay };
                let result = run_session(
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
                .expect("full session must succeed");
                // Settlement proofs are now produced and submitted by each
                // host independently.  There is no post-session peer leg
                // exchange to emulate inside this cryptographic benchmark.
                (result, 0.0_f64)
            }
        })
        .await;
        let total_ms = t.elapsed().as_secs_f64() * 1e3;
        let (result, leg_exchange_ms) = r0;
        let tim = result.timings;
        let measured = run >= args.warmup;
        // Everything in `total` that is neither the prove's own phases nor
        // a host/chain wait: the MPC compare, the fill reveal, the
        // commitment/signature exchange.
        let session_overhead_ms = (total_ms
            - tim.build_ms
            - tim.prove_ms
            - tim.open_ms
            - result.onchain_wait_ms
            - leg_exchange_ms)
            .max(0.0);
        let record = json!({
            "total_ms": total_ms,
            "session_overhead_ms": session_overhead_ms,
            "build_ms": tim.build_ms,
            "prove_ms": tim.prove_ms,
            "share_export_ms": tim.open_ms,
            "open_ms": tim.open_ms,
            // Host/chain waits, NOT cryptography: the F1 on-chain compare
            // confirmation stand-in and the settle-leg round.
            "onchain_wait_ms": result.onchain_wait_ms,
            "leg_exchange_ms": leg_exchange_ms,
            "verify_ms": result.verify_ms,
        });
        if measured {
            mock_runs.push(record);
        }
        println!(
            "  run: total {:.0} ms (compare+reveal+exchange ~{:.0}, prove build {:.0}/prove {:.0}/share-export {:.0}, onchain-wait {:.0}, leg-exchange {:.0})",
            total_ms,
            session_overhead_ms,
            tim.build_ms,
            tim.prove_ms,
            tim.open_ms,
            result.onchain_wait_ms,
            leg_exchange_ms
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

        for run in 0..(args.warmup + args.runs) {
            // Fresh port pair per run to avoid rebind races; a relay run
            // keeps one pair so the relay's addresses stay valid.
            let pa = if args.quic_peer_a.is_some() {
                args.base_port
            } else {
                args.base_port + (run as u16) * 2
            };
            let pb = pa + 1;
            let t = Instant::now();
            let mut children: Vec<Child> = Vec::new();
            for (role, input_file, listen, peer) in [
                // Listener (trader-b) first, dialer (trader-a) second.
                ("trader-b", "b_input.json", pb, pa),
                ("trader-a", "a_input.json", pa, pb),
            ] {
                let out_dir = session_tmp.join(format!("out_{role}"));
                // Trader A's dial target is the relay when one is configured.
                let peer_addr = match args.quic_peer_a {
                    Some(relay) if role == "trader-a" => relay.to_string(),
                    _ => format!("127.0.0.1:{peer}"),
                };
                let mut cmd = Command::new(&session_bin);
                cmd.arg("--role")
                    .arg(role)
                    .arg("--listen")
                    .arg(format!("127.0.0.1:{listen}"))
                    .arg("--peer")
                    .arg(peer_addr)
                    .arg("--input")
                    .arg(session_tmp.join(input_file))
                    .arg("--out-dir")
                    .arg(&out_dir)
                    .arg("--keys-dir")
                    .arg(&keys_dir)
                    .stdin(Stdio::piped());
                let mut child = cmd.spawn()?;
                // Pre-feed every host reply in protocol order: the child
                // buffers them and consumes one line per request
                // (need_sig → compare_ready → result_ready).
                let mut stdin = child.stdin.take().context("child stdin")?;
                writeln!(stdin, "{{\"sig\":\"{DUMMY_SIG}\"}}")?;
                writeln!(stdin, "{{\"compare_confirmed\":true}}")?;
                writeln!(stdin, "{{\"settle_leg_submitted\":true}}")?;
                drop(stdin);
                children.push(child);
            }
            let mut ok = true;
            for c in children.iter_mut() {
                ok &= c.wait()?.success();
            }
            ensure!(ok, "a party process failed");
            let total_ms = t.elapsed().as_secs_f64() * 1e3;

            // Read each party's result + stats; their native shares must
            // reconstruct the standard proof verified by the chain.
            let mut per_party = Vec::new();
            let mut proof_shares = Vec::new();
            for role in ["trader-a", "trader-b"] {
                let dir = session_tmp.join(format!("out_{role}"));
                let stats: Value =
                    serde_json::from_str(&fs::read_to_string(dir.join("stats.json"))?)?;
                per_party.push(stats);
                let result: Value =
                    serde_json::from_str(&fs::read_to_string(dir.join("result.json"))?)?;
                proof_shares.push(
                    result["proof_share_hex"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                );
            }
            ensure!(
                proof_shares[0] != proof_shares[1],
                "parties emitted identical native proof shares"
            );
            let share_a = decode_compare_proof_share_hex(&proof_shares[0])?;
            let share_b = decode_compare_proof_share_hex(&proof_shares[1])?;
            let reconstructed = combine_compare_proof_shares(&share_a, &share_b)?;
            verify_settle(&vk, &public, &reconstructed)?;

            println!(
                "  run: total {total_ms:.0} ms (incl. process startup + key load + full session)"
            );
            if run >= args.warmup {
                quic_runs.push(json!({ "total_ms": total_ms, "per_party": per_party }));
            }
        }
    }

    let report = json!({
        "protocol_version": "native-final-kzg-spdz-share-v1",
        "circuit_gates": gates,
        "public_signals": public.to_vec().len(),
        "proof_size_bytes": {
            "compressed": proof_compressed,
            "uncompressed": proof_uncompressed,
        },
        "comparison_share_size_bytes_compressed": proof_compressed + 2,
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
