//! Experiment harness for the 2-party collaborative settlement prover.
//! Measures, on the same relation and keys:
//!
//! - single-prover jellyfish TurboPlonk baseline (a trusted prover holding
//!   both sides' secrets),
//! - the 2-party collaborative flow in-process (mock duplex network),
//! - the 2-party collaborative flow as two OS processes over QUIC
//!   (per-process peak RSS, real transport),
//!
//! reporting wall-clock, peak memory, and proof sizes. Run in release:
//!
//!   cargo run --release --bin bench_settle2p -- --runs 5 --out results.json

use std::{
    fs,
    path::PathBuf,
    process::{Child, Command},
    time::Instant,
};

use anyhow::{Context, Result, ensure};
use ark_mpc::{PARTY0, test_helpers::execute_mock_mpc};
use ark_serialize::CanonicalSerialize;
use clap::Parser;
use cozk2p::{
    SidePrivate, compute_public, default_cache_dir, dev_keys, prove::prove_collaborative_timed,
    prove_single, sample_trade, setup::circuit_size, stats::peak_rss_bytes, verify_settle,
};
use serde_json::{Value, json};

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

    // ── 2-party collaborative, in-process (mock duplex channels) ──
    println!("=== co-zk 2-party, in-process (mock network) ===");
    let mut mock_runs = Vec::new();
    for _ in 0..args.runs {
        let t = Instant::now();
        let (r0, _r1) = execute_mock_mpc(|fabric| {
            let (a, b, public, pk) = (a.clone(), b.clone(), public.clone(), pk.clone());
            async move {
                let party = fabric.party_id();
                let my: SidePrivate = if party == PARTY0 { a } else { b };
                prove_collaborative_timed(fabric.clone(), party, &my, &public, &pk)
                    .await
                    .expect("collaborative proving must succeed")
            }
        })
        .await;
        let total_ms = t.elapsed().as_secs_f64() * 1e3;
        let (proof, timings) = r0;
        verify_settle(&vk, &public, &proof)?;
        mock_runs.push(json!({
            "total_ms": total_ms,
            "build_ms": timings.build_ms,
            "prove_ms": timings.prove_ms,
            "open_ms": timings.open_ms,
        }));
        println!(
            "  run: total {:.0} ms (build {:.0}, prove {:.0}, open {:.0})",
            total_ms, timings.build_ms, timings.prove_ms, timings.open_ms
        );
    }

    // ── 2-party collaborative, two OS processes over QUIC ──
    let mut quic_runs = Vec::new();
    if !args.skip_quic {
        println!("=== co-zk 2-party, 2 processes over QUIC (localhost) ===");
        let party_bin = std::env::current_exe()?
            .parent()
            .map(|d| d.join("settle2p_party"))
            .filter(|p| p.exists())
            .context(
                "settle2p_party binary not found — build with `cargo build --release --bins`",
            )?;
        let tmp = std::env::temp_dir().join(format!("bench_settle2p_{}", std::process::id()));
        fs::create_dir_all(&tmp)?;
        fs::write(tmp.join("a_side.json"), serde_json::to_string(&a)?)?;
        fs::write(tmp.join("b_side.json"), serde_json::to_string(&b)?)?;
        fs::write(tmp.join("public.json"), serde_json::to_string(&public)?)?;

        for run in 0..args.runs {
            // Fresh port pair per run to avoid rebind races.
            let pa = args.base_port + (run as u16) * 2;
            let pb = pa + 1;
            let t = Instant::now();
            let mut children: Vec<Child> = Vec::new();
            for (role, side, listen, peer) in [
                // Listener (trader-b) first, dialer (trader-a) second.
                ("trader-b", "b_side.json", pb, pa),
                ("trader-a", "a_side.json", pa, pb),
            ] {
                let out_dir = tmp.join(format!("out_{role}"));
                let mut cmd = Command::new(&party_bin);
                cmd.arg("--role")
                    .arg(role)
                    .arg("--listen")
                    .arg(format!("127.0.0.1:{listen}"))
                    .arg("--peer")
                    .arg(format!("127.0.0.1:{peer}"))
                    .arg("--side-json")
                    .arg(tmp.join(side))
                    .arg("--public-json")
                    .arg(tmp.join("public.json"))
                    .arg("--out-dir")
                    .arg(&out_dir);
                children.push(cmd.spawn()?);
            }
            let mut ok = true;
            for c in children.iter_mut() {
                ok &= c.wait()?.success();
            }
            ensure!(ok, "a party process failed");
            let total_ms = t.elapsed().as_secs_f64() * 1e3;

            let mut per_party = Vec::new();
            for role in ["trader-a", "trader-b"] {
                let stats: Value = serde_json::from_str(&fs::read_to_string(
                    tmp.join(format!("out_{role}")).join("stats.json"),
                )?)?;
                per_party.push(stats);
            }
            // Both parties must have produced the identical proof.
            let pa_hex = fs::read_to_string(tmp.join("out_trader-a").join("proof.hex"))?;
            let pb_hex = fs::read_to_string(tmp.join("out_trader-b").join("proof.hex"))?;
            ensure!(pa_hex == pb_hex, "parties revealed different proofs");

            println!("  run: total {total_ms:.0} ms (incl. process startup + key load)");
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
