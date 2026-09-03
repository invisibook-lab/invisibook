//! One trader of the 2-party collaborative settlement prover, connected
//! over QUIC. Run exactly two instances: trader-a (PARTY0, dials) and
//! trader-b (PARTY1, listens). Each loads ONLY its own private side; the
//! counterparty's inputs arrive as SPDZ shares. Both end with the identical
//! standard PLONK proof, locally verified before writing.
//!
//! DEV CAVEAT: Beaver triples come from `PartyIDBeaverSource` (mock,
//! insecure); swap in a real offline phase (ark-mpc-offline LowGear) for
//! production.
//!
//! Example (two shells):
//!   settle2p_party --role trader-b --listen 127.0.0.1:23402 --peer 127.0.0.1:23401 \
//!       --side-json b_side.json --public-json public.json --out-dir out_b
//!   settle2p_party --role trader-a --listen 127.0.0.1:23401 --peer 127.0.0.1:23402 \
//!       --side-json a_side.json --public-json public.json --out-dir out_a

use std::{fs, net::SocketAddr, path::PathBuf, time::Instant};

use anyhow::{Context, Result};
use ark_mpc::{MpcFabric, PARTY0, PARTY1, offline_prep::PartyIDBeaverSource};
use ark_serialize::CanonicalSerialize;
use clap::{Parser, ValueEnum};
use cozk2p::{
    SettlePublic, SidePrivate, default_cache_dir, dev_keys, net::connect,
    prove::prove_collaborative_timed, stats::peak_rss_bytes, verify_settle,
};
use serde_json::json;

#[derive(Debug, Clone, Copy, ValueEnum)]
enum RoleArg {
    /// PARTY0 — dials the peer.
    TraderA,
    /// PARTY1 — listens for the peer.
    TraderB,
}

#[derive(Parser)]
#[command(about = "One trader of the 2-party collaborative settle prover")]
struct Args {
    #[arg(long, value_enum)]
    role: RoleArg,
    /// Local QUIC bind address.
    #[arg(long)]
    listen: SocketAddr,
    /// Counterparty QUIC address. Used by trader-a (the dialer); trader-b
    /// accepts whoever connects (ark-mpc's listener ignores it).
    #[arg(long)]
    peer: SocketAddr,
    /// This trader's private inputs (SidePrivate JSON).
    #[arg(long)]
    side_json: PathBuf,
    /// The agreed public statement (SettlePublic JSON).
    #[arg(long)]
    public_json: PathBuf,
    /// Proving/verifying key cache directory (dev keys generated on miss).
    #[arg(long)]
    keys_dir: Option<PathBuf>,
    /// Output directory for proof + stats.
    #[arg(long)]
    out_dir: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let party = match args.role {
        RoleArg::TraderA => PARTY0,
        RoleArg::TraderB => PARTY1,
    };
    let role_name = match args.role {
        RoleArg::TraderA => "TraderA",
        RoleArg::TraderB => "TraderB",
    };

    let side: SidePrivate =
        serde_json::from_str(&fs::read_to_string(&args.side_json).context("reading --side-json")?)?;
    let public: SettlePublic = serde_json::from_str(
        &fs::read_to_string(&args.public_json).context("reading --public-json")?,
    )?;
    let keys_dir = args.keys_dir.unwrap_or_else(default_cache_dir);
    let (pk, vk) = dev_keys(&keys_dir)?;

    println!("[{role_name}] connecting to peer...");
    let total_start = Instant::now();
    // Bounded connect: ark-mpc's listener side has no accept timeout, so a
    // dead counterparty would otherwise hang this process forever.
    let net = tokio::time::timeout(
        std::time::Duration::from_secs(60),
        connect(party, args.listen, args.peer),
    )
    .await
    .map_err(|_| anyhow::anyhow!("timed out waiting for the counterparty to connect"))??;
    // Mock Beaver source: dev only (see module docs). The masks are
    // predictable constants, so this leaks the counterparty's inputs and
    // strips the proof's zero-knowledge — functional demo, never production.
    eprintln!(
        "WARNING [cozk2p]: PartyIDBeaverSource is a MOCK offline phase — inputs \
         are recoverable and the proof carries no zero-knowledge. DEV ONLY."
    );
    let fabric = MpcFabric::new(net, PartyIDBeaverSource::new(party));

    println!("[{role_name}] proving collaboratively...");
    let (proof, timings) = prove_collaborative_timed(fabric, party, &side, &public, &pk).await?;

    let t = Instant::now();
    verify_settle(&vk, &public, &proof)?;
    let verify_ms = t.elapsed().as_secs_f64() * 1e3;
    let total_ms = total_start.elapsed().as_secs_f64() * 1e3;

    fs::create_dir_all(&args.out_dir)?;
    let mut proof_bytes = Vec::new();
    proof
        .serialize_compressed(&mut proof_bytes)
        .expect("proof serialization must not fail");
    fs::write(args.out_dir.join("proof.hex"), hex::encode(&proof_bytes))?;
    let stats = json!({
        "role": role_name,
        "build_ms": timings.build_ms,
        "prove_ms": timings.prove_ms,
        "open_ms": timings.open_ms,
        "verify_ms": verify_ms,
        "total_ms": total_ms,
        "peak_rss_bytes": peak_rss_bytes(),
        "proof_size_bytes_compressed": proof_bytes.len(),
    });
    fs::write(
        args.out_dir.join("stats.json"),
        serde_json::to_string_pretty(&stats)?,
    )?;
    println!(
        "[{role_name}] done: build {:.0} ms, prove {:.0} ms, open {:.0} ms, verified in {:.1} ms; proof {} B; outputs in {}",
        timings.build_ms,
        timings.prove_ms,
        timings.open_ms,
        verify_ms,
        proof_bytes.len(),
        args.out_dir.display()
    );
    Ok(())
}
