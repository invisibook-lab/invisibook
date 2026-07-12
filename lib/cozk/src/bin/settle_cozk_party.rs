//! One node of the 3-party collaborative settlement proving MPC, connected
//! over TCP. Run three instances (trader-a, trader-b, helper); each node
//! receives its REP3 share of BOTH traders' inputs (share `i` of each), runs
//! MPC witness extension + collaborative Groth16 proving, and locally
//! verifies the proof before writing it. Every node ends up with the
//! identical proof.
//!
//! Inputs are pre-split OFFLINE with `split_settle_cozk_input` (the
//! co-circom `split-input` step) and distributed over a side channel — the
//! MPC network carries only the co-snarks protocol. Node `i` gets
//! `share_a.i.json` and `share_b.i.json` (each share already carries the
//! shared public signals as Public entries, so no separate public file is
//! needed at this stage).
//!
//! Example (three shells, localhost):
//!   split_settle_cozk_input a_side.json b_side.json public.json shares/
//!   settle_cozk_party --role trader-a --listen 0.0.0.0:10331 \
//!       --parties 127.0.0.1:10331,127.0.0.1:10332,127.0.0.1:10333 \
//!       --share-a-json shares/share_a.0.json --share-b-json shares/share_b.0.json \
//!       --out-dir out_a
//!   settle_cozk_party --role trader-b ... --share-a-json shares/share_a.1.json ...
//!   settle_cozk_party --role helper  ... --share-a-json shares/share_a.2.json ...

use std::{fs, net::SocketAddr, path::PathBuf};

use anyhow::{Context, Result, anyhow, ensure};
use ark_bn254::Fr;
use clap::{Parser, ValueEnum};
use co_circom::Rep3SharedInput;
use cozk::{
    Role, default_circuit_path, default_link_dir, load_artifacts, peak_rss_bytes, prove_party,
    tcp_networks,
};
use serde_json::json;

#[derive(Debug, Clone, Copy, ValueEnum)]
enum RoleArg {
    TraderA,
    TraderB,
    Helper,
}

impl From<RoleArg> for Role {
    fn from(r: RoleArg) -> Self {
        match r {
            RoleArg::TraderA => Role::TraderA,
            RoleArg::TraderB => Role::TraderB,
            RoleArg::Helper => Role::Helper,
        }
    }
}

#[derive(Parser)]
#[command(about = "One REP3 node of the collaborative settle_cozk prover")]
struct Args {
    /// This node's role (trader-a = REP3 id 0, trader-b = 1, helper = 2).
    #[arg(long, value_enum)]
    role: RoleArg,
    /// Local bind address, e.g. 0.0.0.0:10331.
    #[arg(long)]
    listen: SocketAddr,
    /// Comma-separated host:port of parties 0,1,2 (in REP3 id order).
    #[arg(long, value_delimiter = ',')]
    parties: Vec<String>,
    /// This node's REP3 share of trader A's private input (share `id` of
    /// `split_settle_cozk_input`'s output).
    #[arg(long)]
    share_a_json: PathBuf,
    /// This node's REP3 share of trader B's private input.
    #[arg(long)]
    share_b_json: PathBuf,
    /// settle_cozk circom source (defaults to the in-repo template).
    #[arg(long)]
    circuit: Option<PathBuf>,
    /// snarkjs proving key (defaults to the dev-setup cache location).
    #[arg(long)]
    zkey: Option<PathBuf>,
    /// snarkjs verification key (defaults to the dev-setup cache location).
    #[arg(long)]
    vk: Option<PathBuf>,
    /// Output directory for proof.json / public.json / stats.json.
    #[arg(long)]
    out_dir: PathBuf,
}

/// Default artifact location produced by `zk::setup::dev_setup_snarkjs`.
fn default_build_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target/circuit-build/settle_cozk")
}

fn main() -> Result<()> {
    let args = Args::parse();
    let role: Role = args.role.into();
    ensure!(
        args.parties.len() == 3,
        "--parties must list exactly 3 host:port entries"
    );
    let party_addrs: [String; 3] = args
        .parties
        .clone()
        .try_into()
        .map_err(|_| anyhow!("--parties must list exactly 3 host:port entries"))?;

    let circuit = args.circuit.unwrap_or_else(default_circuit_path);
    let zkey = args
        .zkey
        .unwrap_or_else(|| default_build_dir().join("settle_cozk.zkey"));
    let vk = args
        .vk
        .unwrap_or_else(|| default_build_dir().join("vk.json"));
    let artifacts = load_artifacts(&circuit, &default_link_dir(), &zkey, &vk)?;

    // This node's share of each trader's input, distributed offline. Each
    // share already contains the shared public signals as Public entries.
    let read_share = |p: &PathBuf| -> Result<Rep3SharedInput<Fr>> {
        Ok(serde_json::from_str(
            &fs::read_to_string(p).context("reading share json")?,
        )?)
    };
    let input_shares = vec![
        read_share(&args.share_a_json)?,
        read_share(&args.share_b_json)?,
    ];

    println!("[{role:?}] connecting to peers...");
    let [net0, net1] = tcp_networks(role.id(), args.listen, &party_addrs)?;
    println!("[{role:?}] proving collaboratively...");
    let output = prove_party(&artifacts, input_shares, &net0, &net1)?;

    fs::create_dir_all(&args.out_dir)?;
    fs::write(
        args.out_dir.join("proof.json"),
        serde_json::to_string_pretty(&output.proof_json)?,
    )?;
    fs::write(
        args.out_dir.join("public.json"),
        serde_json::to_string_pretty(&output.public_json)?,
    )?;
    let stats = json!({
        "role": format!("{role:?}"),
        "witness_ms": output.stats.witness_ms,
        "prove_ms": output.stats.prove_ms,
        "verify_ms": output.stats.verify_ms,
        "witness_sent_bytes": output.stats.witness_sent_bytes,
        "witness_recv_bytes": output.stats.witness_recv_bytes,
        "prove_sent_bytes": output.stats.prove_sent_bytes,
        "prove_recv_bytes": output.stats.prove_recv_bytes,
        "peak_rss_bytes": peak_rss_bytes(),
        "proof_size_bytes": serde_json::to_string(&output.proof_json)?.len(),
    });
    fs::write(
        args.out_dir.join("stats.json"),
        serde_json::to_string_pretty(&stats)?,
    )?;
    println!(
        "[{role:?}] done: witness {:.1} ms, prove {:.1} ms, verified in {:.1} ms; outputs in {}",
        output.stats.witness_ms,
        output.stats.prove_ms,
        output.stats.verify_ms,
        args.out_dir.display()
    );
    Ok(())
}
