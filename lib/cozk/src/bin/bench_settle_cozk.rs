//! Experiment harness for the collaborative settlement prover. Measures, on
//! the same settle_cozk circuit and zkey:
//!
//! - single-prover baselines: rapidsnark (production prover) and the
//!   arkworks plain prover (same code path the MPC prover lifts),
//! - the 3-node REP3 collaborative flow, in-process (LocalNetwork) and as
//!   three OS processes over TCP (per-process peak RSS),
//!
//! reporting wall-clock per phase, per-party network traffic, peak memory,
//! and proof sizes. Build everything in release mode first:
//!
//!   cargo build --release -p cozk --bins
//!   cargo run --release -p cozk --bin bench_settle_cozk -- --out results.json

use std::{
    fs,
    io::BufReader,
    path::PathBuf,
    process::{Child, Command},
    time::Instant,
};

use anyhow::{Context, Result, anyhow, ensure};
use ark_bn254::{Bn254, Fr};
use ark_serialize::{CanonicalSerialize, Compress};
use clap::Parser;
use co_circom::{CheckElement, CircomGroth16Proof, CircomReduction, Groth16, Groth16ZKey, Witness};
use co_circom_types::SharedWitness;
use cozk::{
    default_circuit_path, default_link_dir, load_artifacts, peak_rss_bytes, run_local_settle,
};
use serde_json::{Value, json};
use zk::{
    setup::dev_setup_snarkjs,
    test_circuit::TestCircuitHandle,
    wallet::{
        SettleCoZkSide, SettleCoZkWitness, poseidon_commit, settle_cozk_locked_hashes,
        settle_cozk_public_json, settle_cozk_side_json,
    },
};

#[derive(Parser)]
#[command(about = "Benchmark settle_cozk: collaborative vs single-prover")]
struct Args {
    /// Number of measured runs per configuration.
    #[arg(long, default_value_t = 3)]
    runs: usize,
    /// Base TCP port for the 3-process mode (uses base, base+1, base+2).
    #[arg(long, default_value_t = 34411)]
    base_port: u16,
    /// Skip the 3-process TCP mode (e.g. when ports are unavailable).
    #[arg(long)]
    skip_tcp: bool,
    /// Where to write the JSON report.
    #[arg(long, default_value = "settle_cozk_bench.json")]
    out: PathBuf,
}

/// The benchmark trade: A (maker) sells 80 token1 at price 3, B buys 60.
fn sample_witness() -> SettleCoZkWitness {
    SettleCoZkWitness {
        a: SettleCoZkSide {
            order_amount: 80,
            r_order: [0xA1u8; 32],
            r_order_new: [0xA2u8; 32],
            locked: vec![(80, [0xA3u8; 32])],
            r_locked_new: [0xA4u8; 32],
            r_recv: [0xA5u8; 32],
        },
        b: SettleCoZkSide {
            order_amount: 60,
            r_order: [0xB1u8; 32],
            r_order_new: [0xB2u8; 32],
            locked: vec![(180, [0xB3u8; 32])],
            r_locked_new: [0xB4u8; 32],
            r_recv: [0xB5u8; 32],
        },
        price: 3,
        a_is_seller: true,
    }
}

/// Mean of a f64 slice; 0.0 for empty input.
fn mean(xs: &[f64]) -> f64 {
    if xs.is_empty() {
        0.0
    } else {
        xs.iter().sum::<f64>() / xs.len() as f64
    }
}

/// Compressed arkworks size (bytes) of a snarkjs-format Groth16 proof JSON.
fn proof_compressed_bytes(proof_json: &Value) -> Result<usize> {
    let circom_proof: CircomGroth16Proof<Bn254> = serde_json::from_value(proof_json.clone())?;
    let proof: ark_groth16::Proof<Bn254> = circom_proof.into();
    Ok(proof.serialized_size(Compress::Yes))
}

/// Peak RSS (bytes) of a command as reported by GNU time; None when
/// /usr/bin/time is unavailable.
fn peak_rss_of_command(cmd: &str, args: &[&str]) -> Option<u64> {
    let out = Command::new("/usr/bin/time")
        .arg("-v")
        .arg(cmd)
        .args(args)
        .output()
        .ok()?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    for line in stderr.lines() {
        if let Some(rest) = line
            .trim()
            .strip_prefix("Maximum resident set size (kbytes):")
        {
            return rest.trim().parse::<u64>().ok().map(|kb| kb * 1024);
        }
    }
    None
}

fn main() -> Result<()> {
    let args = Args::parse();
    let w = sample_witness();

    println!("=== setup (cached after first run) ===");
    let setup_start = Instant::now();
    let setup = dev_setup_snarkjs("settle_cozk").context("snarkjs setup")?;
    let handle = TestCircuitHandle::from_compiled(&setup.circuit_dir)?;
    let artifacts = load_artifacts(
        &default_circuit_path(),
        &default_link_dir(),
        &setup.zkey,
        &setup.vk_json,
    )?;
    println!(
        "setup ready in {:.1} ms ({} R1CS constraints)",
        setup_start.elapsed().as_secs_f64() * 1000.0,
        artifacts.matrices.num_constraints,
    );

    let a_private = settle_cozk_side_json(&w.a, "a")?;
    let b_private = settle_cozk_side_json(&w.b, "b")?;
    let public = settle_cozk_public_json(
        &poseidon_commit(w.a.order_amount, &w.a.r_order),
        &poseidon_commit(w.b.order_amount, &w.b.r_order),
        w.price,
        w.a_is_seller,
        &settle_cozk_locked_hashes(&w.a),
        &settle_cozk_locked_hashes(&w.b),
    );
    let full_input = zk::wallet::settle_cozk_input_json(&w)?;

    // ── Baseline 1: rapidsnark (production single prover) ──
    println!("=== baseline: rapidsnark single prover ===");
    let mut witgen_ms = Vec::new();
    let mut rapidsnark_ms = Vec::new();
    let mut proof_json_bytes = 0usize;
    let mut wtns_path = PathBuf::new();
    for _ in 0..args.runs {
        let t = Instant::now();
        wtns_path = handle.gen_witness(&full_input)?;
        witgen_ms.push(t.elapsed().as_secs_f64() * 1000.0);
        let t = Instant::now();
        let (proof_json, _) = zk::prover::run_rapidsnark(&setup.zkey, &wtns_path)?;
        rapidsnark_ms.push(t.elapsed().as_secs_f64() * 1000.0);
        proof_json_bytes = serde_json::to_string(&proof_json)?.len();
    }
    // Peak RSS of the rapidsnark process itself (best effort).
    let rapidsnark_rss = peak_rss_of_command(
        "rapidsnark",
        &[
            setup.zkey.to_str().unwrap(),
            wtns_path.to_str().unwrap(),
            "/tmp/bench_cozk_proof.json",
            "/tmp/bench_cozk_public.json",
        ],
    );
    println!(
        "witness gen (node): {:.1} ms, rapidsnark prove: {:.1} ms",
        mean(&witgen_ms),
        mean(&rapidsnark_ms)
    );

    // ── Baseline 2: arkworks plain prover (the code path REP3 lifts) ──
    println!("=== baseline: arkworks plain prover ===");
    let zkey_file = fs::File::open(&setup.zkey)?;
    let zkey = Groth16ZKey::<Bn254>::from_reader(BufReader::new(zkey_file), CheckElement::No)
        .map_err(|e| anyhow!("parsing zkey: {e}"))?;
    let (matrices, pkey) = zkey.into();
    let witness = Witness::<Fr>::from_reader(fs::File::open(&wtns_path)?)
        .map_err(|e| anyhow!("parsing wtns: {e}"))?;
    let n_instance = matrices.num_instance_variables;
    let mut plain_ms = Vec::new();
    let mut proof_compressed = 0usize;
    for _ in 0..args.runs {
        let shared = SharedWitness {
            public_inputs: witness.values[..n_instance].to_vec(),
            witness: witness.values[n_instance..].to_vec(),
        };
        let t = Instant::now();
        let proof = Groth16::<Bn254>::plain_prove::<CircomReduction>(&pkey, &matrices, shared)
            .map_err(|e| anyhow!("plain prove: {e}"))?;
        plain_ms.push(t.elapsed().as_secs_f64() * 1000.0);
        proof_compressed = proof.serialized_size(Compress::Yes);
    }
    println!("arkworks plain prove: {:.1} ms", mean(&plain_ms));

    // ── Collaborative, in-process (LocalNetwork) ──
    println!("=== co-zk: 3 nodes in-process (LocalNetwork) ===");
    let mut local_runs = Vec::new();
    let mut local_proof_bytes = (0usize, 0usize);
    for _ in 0..args.runs {
        let t = Instant::now();
        let outcome = run_local_settle(&artifacts, &a_private, &b_private, &public)?;
        let total_ms = t.elapsed().as_secs_f64() * 1000.0;
        local_proof_bytes = (
            serde_json::to_string(&outcome.proof_json)?.len(),
            proof_compressed_bytes(&outcome.proof_json)?,
        );
        local_runs.push(json!({
            "total_ms": total_ms,
            "per_party": outcome.per_party.iter().map(|s| json!({
                "witness_ms": s.witness_ms,
                "prove_ms": s.prove_ms,
                "verify_ms": s.verify_ms,
                "witness_sent_bytes": s.witness_sent_bytes,
                "witness_recv_bytes": s.witness_recv_bytes,
                "prove_sent_bytes": s.prove_sent_bytes,
                "prove_recv_bytes": s.prove_recv_bytes,
            })).collect::<Vec<_>>(),
        }));
        println!(
            "  run: total {:.1} ms (party0 witness {:.1} ms, prove {:.1} ms, sent {} KiB)",
            total_ms,
            outcome.per_party[0].witness_ms,
            outcome.per_party[0].prove_ms,
            outcome.per_party[0].total_sent_bytes() / 1024,
        );
    }

    // ── Collaborative, 3 OS processes over TCP ──
    let mut tcp_runs = Vec::new();
    if !args.skip_tcp {
        println!("=== co-zk: 3 processes over TCP (localhost) ===");
        let party_bin = std::env::current_exe()?
            .parent()
            .map(|d| d.join("settle_cozk_party"))
            .filter(|p| p.exists());
        match party_bin {
            None => println!(
                "settle_cozk_party binary not found next to bench binary — build with `cargo build --release -p cozk --bins` (skipping TCP mode)"
            ),
            Some(bin) => {
                let tmp = tempdir()?;
                // Pre-share inputs offline (the co-circom `split-input` step):
                // each trader's private map is split into 3 REP3 shares and
                // node i receives share i of each trader. The MPC network then
                // carries only the co-snarks protocol — mixing input
                // distribution onto it deadlocks the protocol's framing.
                let a_shares =
                    cozk::split_trader_input(&a_private, &public, &artifacts.public_input_names)?;
                let b_shares =
                    cozk::split_trader_input(&b_private, &public, &artifacts.public_input_names)?;
                for i in 0..3 {
                    fs::write(
                        tmp.join(format!("share_a.{i}.json")),
                        serde_json::to_string(&a_shares[i])?,
                    )?;
                    fs::write(
                        tmp.join(format!("share_b.{i}.json")),
                        serde_json::to_string(&b_shares[i])?,
                    )?;
                }
                // The co-snarks TcpNetwork setup over loopback occasionally
                // races and one party wedges in the first witness-extension
                // round (it eventually errors out via the recv timeout). Each
                // measured run gets a few attempts on fresh ports.
                const MAX_ATTEMPTS: usize = 4;
                let mut attempt_counter: u16 = 0;
                for run in 0..args.runs {
                    let mut succeeded = false;
                    for attempt in 0..MAX_ATTEMPTS {
                        // Fresh ports every attempt: instantly rebinding the
                        // previous attempt's ports adds its own stale-socket
                        // races.
                        let base = args.base_port + attempt_counter * 3;
                        attempt_counter += 1;
                        let parties = format!(
                            "127.0.0.1:{},127.0.0.1:{},127.0.0.1:{}",
                            base,
                            base + 1,
                            base + 2
                        );
                        let t = Instant::now();
                        let mut children: Vec<Child> = Vec::new();
                        for (id, role) in ["trader-a", "trader-b", "helper"].into_iter().enumerate()
                        {
                            let out_dir = tmp.join(format!("out_{role}"));
                            let mut cmd = Command::new(&bin);
                            cmd.arg("--role")
                                .arg(role)
                                .arg("--listen")
                                .arg(format!("0.0.0.0:{}", base + id as u16))
                                .arg("--parties")
                                .arg(&parties)
                                .arg("--share-a-json")
                                .arg(tmp.join(format!("share_a.{id}.json")))
                                .arg("--share-b-json")
                                .arg(tmp.join(format!("share_b.{id}.json")))
                                .arg("--zkey")
                                .arg(&setup.zkey)
                                .arg("--vk")
                                .arg(&setup.vk_json)
                                .arg("--out-dir")
                                .arg(&out_dir);
                            children.push(cmd.spawn()?);
                        }
                        let all_ok = children
                            .into_iter()
                            .map(|mut c| c.wait().map(|s| s.success()).unwrap_or(false))
                            // Collect first so every child is waited on.
                            .collect::<Vec<_>>()
                            .into_iter()
                            .all(|ok| ok);
                        if !all_ok {
                            println!(
                                "  run {run}: attempt {attempt} failed (loopback setup race), retrying"
                            );
                            continue;
                        }
                        let total_ms = t.elapsed().as_secs_f64() * 1000.0;
                        let mut per_party = Vec::new();
                        for role in ["trader-a", "trader-b", "helper"] {
                            let stats: Value = serde_json::from_str(&fs::read_to_string(
                                tmp.join(format!("out_{role}")).join("stats.json"),
                            )?)?;
                            per_party.push(stats);
                        }
                        println!(
                            "  run {run}: total {total_ms:.1} ms (incl. process startup + zkey load)"
                        );
                        tcp_runs.push(json!({ "total_ms": total_ms, "per_party": per_party }));
                        succeeded = true;
                        break;
                    }
                    ensure!(
                        succeeded,
                        "TCP run {run} failed after {MAX_ATTEMPTS} attempts"
                    );
                }
            }
        }
    }

    let report = json!({
        "circuit": "settle_cozk",
        "constraints": artifacts.matrices.num_constraints,
        "public_signals": 15,
        "runs": args.runs,
        "proof_size_bytes": {
            "snarkjs_json": local_proof_bytes.0,
            "ark_compressed": local_proof_bytes.1,
            "rapidsnark_json": proof_json_bytes,
            "plain_ark_compressed": proof_compressed,
        },
        "baseline_single_prover": {
            "witness_gen_node_ms": witgen_ms,
            "rapidsnark_prove_ms": rapidsnark_ms,
            "rapidsnark_peak_rss_bytes": rapidsnark_rss,
            "arkworks_plain_prove_ms": plain_ms,
        },
        "cozk_local_3party": local_runs,
        "cozk_tcp_3process": tcp_runs,
        "bench_process_peak_rss_bytes": peak_rss_bytes(),
    });
    fs::write(&args.out, serde_json::to_string_pretty(&report)?)?;
    println!("\nreport written to {}", args.out.display());
    Ok(())
}

/// Create a unique scratch directory for this bench run.
fn tempdir() -> Result<PathBuf> {
    let dir = std::env::temp_dir().join(format!("bench_settle_cozk_{}", std::process::id()));
    fs::create_dir_all(&dir)?;
    Ok(dir)
}
