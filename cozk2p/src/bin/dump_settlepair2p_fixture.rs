//! Export the chain-side artifacts of the MERGED settlement path:
//!
//! - the ark-compressed PLONK verifying key (`--vk-out`, the
//!   `chain/vk/settle_pair_cozk2p_vk.bin` the chain loads at startup), and
//! - a fixture JSON (`--fixture-out`) for the chain's Go verifier tests,
//!   whose proof is generated COLLABORATIVELY by two in-process SPDZ
//!   parties over the merged relation.
//!
//! Run with:
//!   cargo run --release --bin dump_settlepair2p_fixture -- \
//!       --vk-out ../chain/vk/settle_pair_cozk2p_vk.bin \
//!       --fixture-out /tmp/settle_pair_cozk2p_fixture.json

use std::{fs, path::PathBuf};

use anyhow::{Context, Result, ensure};
use ark_mpc::{PARTY0, test_helpers::execute_mock_mpc};
use ark_serialize::CanonicalSerialize;
use clap::Parser;
use cozk2p::{
    PairSidePrivate, compute_pair_public,
    poseidon::fr_to_hex,
    prove_pair_collaborative,
    setup::{default_cache_dir, dev_keys_pair, sample_pair_trade},
    verify_settle_pair,
};
use serde_json::json;

#[derive(Parser)]
#[command(about = "Dump the merged settle-pair verifying key and/or a chain-test fixture")]
struct Args {
    /// Where to write the ark-compressed verifying key.
    #[arg(long)]
    vk_out: Option<PathBuf>,
    /// Where to write the fixture JSON (runs an in-process 2-party prove).
    #[arg(long)]
    fixture_out: Option<PathBuf>,
    /// Proving/verifying key cache directory (dev keys generated on miss).
    #[arg(long)]
    keys_dir: Option<PathBuf>,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let args = Args::parse();
    ensure!(
        args.vk_out.is_some() || args.fixture_out.is_some(),
        "nothing to do: pass --vk-out and/or --fixture-out"
    );
    let keys_dir = args.keys_dir.unwrap_or_else(default_cache_dir);
    let (pk, vk) = dev_keys_pair(&keys_dir)?;

    let vk_path = if let Some(path) = &args.vk_out {
        let mut buf = Vec::new();
        vk.serialize_compressed(&mut buf)
            .context("serializing verifying key")?;
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        fs::write(path, &buf).with_context(|| format!("writing {}", path.display()))?;
        println!(
            "wrote verifying key ({} B) to {}",
            buf.len(),
            path.display()
        );
        Some(fs::canonicalize(path)?)
    } else {
        None
    };

    let Some(fixture_out) = args.fixture_out else {
        return Ok(());
    };

    // Same sample trade as keygen: A sells 80 at price 3, B buys 60.
    let (a, b, inputs) = sample_pair_trade();
    let public = compute_pair_public(&a, &b, &inputs);

    // Two in-process SPDZ parties, each holding only its own side.
    let (r0, r1) = execute_mock_mpc(|fabric| {
        let (a, b, public, pk) = (a.clone(), b.clone(), public.clone(), pk.clone());
        async move {
            let party = fabric.party_id();
            let my: PairSidePrivate = if party == PARTY0 { a } else { b };
            prove_pair_collaborative(fabric.clone(), party, &my, &public, &pk)
                .await
                .expect("collaborative proving must succeed")
        }
    })
    .await;
    let mut p0 = Vec::new();
    r0.serialize_compressed(&mut p0)?;
    let mut p1 = Vec::new();
    r1.serialize_compressed(&mut p1)?;
    ensure!(p0 == p1, "the two parties revealed different proofs");
    verify_settle_pair(&vk, &public, &r0).context("locally verifying the collaborative proof")?;

    // Chain-rebuildable hexes so the Go test can reconstruct the statement
    // exactly as the writing does and compare against `public`.
    let fixture = json!({
        "cmp": public.cmp,
        "order_a_commitment_hex": fr_to_hex(&public.cm_q_a),
        "order_b_commitment_hex": fr_to_hex(&public.cm_q_b),
        "locked_a_hex": fr_to_hex(&public.locked_a),
        "locked_b_hex": fr_to_hex(&public.locked_b),
        "cm_note_out_a_hex": fr_to_hex(&public.cm_note_out_a),
        "cm_note_out_b_hex": fr_to_hex(&public.cm_note_out_b),
        "cm_q_res_a_hex": fr_to_hex(&public.cm_q_res_a),
        "cm_locked_res_a_hex": fr_to_hex(&public.cm_locked_res_a),
        "cm_q_res_b_hex": fr_to_hex(&public.cm_q_res_b),
        "cm_locked_res_b_hex": fr_to_hex(&public.cm_locked_res_b),
        "price": public.price,
        "a_is_seller": public.a_is_seller,
        "token_recv_a": "USDT",
        "token_recv_b": "ETH",
        "proof_hex": hex::encode(&p0),
        "public": serde_json::to_value(&public)?,
        "vk_path": vk_path.as_ref().map(|p| p.display().to_string()),
    });
    fs::write(&fixture_out, serde_json::to_string_pretty(&fixture)?)
        .with_context(|| format!("writing {}", fixture_out.display()))?;
    println!("wrote fixture to {}", fixture_out.display());
    Ok(())
}
