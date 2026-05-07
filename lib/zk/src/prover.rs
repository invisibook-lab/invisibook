//! Subprocess wrapper around the `rapidsnark` C++ prover binary.
//!
//! `rapidsnark <zkey> <wtns> <proof.json> <public.json>` consumes a snarkjs
//! zkey + circom witness and writes a snarkjs-format proof + public-input file.
//! This module shells out, parses both JSON files, and returns them as
//! `serde_json::Value` so wallet code can echo them straight to chain (where
//! go-rapidsnark verifies them natively).
//!
//! Requires `rapidsnark` available in `$PATH`.

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, bail};
use serde_json::Value;
use tempfile::tempdir;

/// Run rapidsnark and return `(proof_json, public_json)`. The temp dir holding
/// the JSON files is cleaned up when this function returns; both Values own
/// their data.
pub fn run_rapidsnark(zkey: &Path, witness: &Path) -> Result<(Value, Value)> {
    let workdir = tempdir().context("creating tempdir for rapidsnark output")?;
    let proof_path: PathBuf = workdir.path().join("proof.json");
    let public_path: PathBuf = workdir.path().join("public.json");

    let output = Command::new("rapidsnark")
        .arg(zkey)
        .arg(witness)
        .arg(&proof_path)
        .arg(&public_path)
        .output()
        .with_context(|| {
            format!(
                "spawning rapidsnark failed; ensure /usr/local/bin/rapidsnark or similar is in $PATH"
            )
        })?;

    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "rapidsnark prover failed (exit {}):\nstdout:\n{}\nstderr:\n{}",
            output.status,
            stdout,
            stderr
        );
    }

    // rapidsnark writes valid JSON followed by NUL padding (it pads its output
    // buffer to a fixed block size). Trim trailing NULs before parsing — also
    // strip stray whitespace just in case future versions change the padding.
    let proof_str = fs::read_to_string(&proof_path)
        .with_context(|| format!("reading rapidsnark proof.json at {proof_path:?}"))?;
    let public_str = fs::read_to_string(&public_path)
        .with_context(|| format!("reading rapidsnark public.json at {public_path:?}"))?;
    let proof_trimmed = proof_str.trim_end_matches(|c: char| c == '\0' || c.is_whitespace());
    let public_trimmed = public_str.trim_end_matches(|c: char| c == '\0' || c.is_whitespace());
    let proof_json: Value = serde_json::from_str(proof_trimmed)
        .with_context(|| format!("parsing proof.json (raw contents: {proof_str:?})"))?;
    let public_json: Value = serde_json::from_str(public_trimmed)
        .with_context(|| format!("parsing public.json (raw contents: {public_str:?})"))?;

    Ok((proof_json, public_json))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        setup::dev_setup_snarkjs,
        test_circuit::TestCircuitHandle,
        wallet::{
            DepositWitness, SettleLargerWitness, SettleSmallerWitness, SplitWitness,
            WithdrawWitness, fr_to_hex, poseidon_commit, prove_deposit, prove_settle_larger,
            prove_settle_smaller, prove_split, prove_withdraw,
        },
    };

    #[test]
    fn deposit_proof_round_trips_through_rapidsnark() {
        let setup = dev_setup_snarkjs("deposit").expect("snarkjs setup");
        let handle = TestCircuitHandle::from_compiled(&setup.circuit_dir).expect("circuit handle");
        let witness = DepositWitness {
            deposit_amount: 150,
            r_bridge: [0x11u8; 32],
            output_amount: 150,
            output_random: [0x22u8; 32],
        };
        let dp = prove_deposit(witness, &handle, &setup.zkey).expect("rapidsnark prove");

        // proof.json must carry the standard snarkjs envelope so go-rapidsnark accepts it.
        // (rapidsnark omits the `curve` field that snarkjs emits — go-rapidsnark only
        // needs `curve` on the VK, so this is fine as-is.)
        assert_eq!(dp.proof_json["protocol"], "groth16");
        assert!(dp.proof_json["pi_a"].is_array());
        assert!(dp.proof_json["pi_b"].is_array());
        assert!(dp.proof_json["pi_c"].is_array());

        // public.json is an ordered array of decimal strings — one per public signal.
        // deposit.circom declares `public [bridge_commitment, output_hashes]` so we
        // expect exactly 3 entries (1 + M=2 outputs).
        let public = dp.public_json.as_array().expect("public is array");
        assert_eq!(public.len(), 3);

        // Sanity: the off-circuit commitments echoed by prove_deposit must match
        // recomputing them — chain re-derives these to assemble the public-input vector.
        assert_eq!(
            dp.bridge_commitment_hex,
            fr_to_hex(&poseidon_commit(150, &[0x11u8; 32]))
        );
        assert_eq!(
            dp.output_commitment_hex,
            fr_to_hex(&poseidon_commit(150, &[0x22u8; 32]))
        );
    }

    #[test]
    fn withdraw_proof_round_trips_through_rapidsnark() {
        // Spend two cashes (70 + 40 = 110); withdraw 100 (hidden); mint 10 as change.
        let setup = dev_setup_snarkjs("withdraw").expect("snarkjs setup");
        let handle = TestCircuitHandle::from_compiled(&setup.circuit_dir).expect("circuit handle");
        let in_a_random = [0xA1u8; 32];
        let in_b_random = [0xB2u8; 32];
        let witness = WithdrawWitness {
            withdraw_amount: 100,
            r_bridge_out: [0x11u8; 32],
            inputs: vec![(70, in_a_random), (40, in_b_random)],
            change_amount: 10,
            change_random: [0xC3u8; 32],
        };
        let wp = prove_withdraw(witness, &handle, &setup.zkey).expect("rapidsnark prove");

        // proof.json envelope
        assert_eq!(wp.proof_json["protocol"], "groth16");

        // public.json layout: [bridge_out_commitment, input_hashes[0..N], output_hashes[0..M]]
        let public = wp.public_json.as_array().expect("public is array");
        assert_eq!(public.len(), 1 + 2 + 2);

        // Real input commitments echoed in unpadded order
        assert_eq!(wp.input_commitments_hex.len(), 2);
        assert_eq!(
            wp.input_commitments_hex[0],
            fr_to_hex(&poseidon_commit(70, &in_a_random))
        );
        assert_eq!(
            wp.input_commitments_hex[1],
            fr_to_hex(&poseidon_commit(40, &in_b_random))
        );

        // Bridge + change commitments match an off-circuit recomputation
        assert_eq!(
            wp.bridge_out_commitment_hex,
            fr_to_hex(&poseidon_commit(100, &[0x11u8; 32]))
        );
        assert_eq!(
            wp.change_commitment_hex,
            fr_to_hex(&poseidon_commit(10, &[0xC3u8; 32]))
        );
    }

    #[test]
    fn split_proof_round_trips_through_rapidsnark() {
        // Spend one 100-cash, lock 60 + return 40 change — the most common SendOrder
        // split. Mirrors how the wallet uses it when collateralizing a partial trade.
        let setup = dev_setup_snarkjs("split").expect("snarkjs setup");
        let handle = TestCircuitHandle::from_compiled(&setup.circuit_dir).expect("circuit handle");
        let in_random = [0xE5u8; 32];
        let locked_random = [0xF6u8; 32];
        let change_random = [0xC7u8; 32];
        let witness = SplitWitness {
            inputs: vec![(100, in_random)],
            locked_amount: 60,
            locked_random,
            change_amount: 40,
            change_random,
        };
        let sp = prove_split(witness, &handle, &setup.zkey).expect("rapidsnark prove");

        assert_eq!(sp.proof_json["protocol"], "groth16");
        // public.json layout: [input_hashes[0..N], output_hashes[0..M]] = 2 + 2 = 4
        let public = sp.public_json.as_array().expect("public is array");
        assert_eq!(public.len(), 4);

        assert_eq!(sp.input_commitments_hex.len(), 1);
        assert_eq!(
            sp.input_commitments_hex[0],
            fr_to_hex(&poseidon_commit(100, &in_random))
        );
        assert_eq!(
            sp.locked_commitment_hex,
            fr_to_hex(&poseidon_commit(60, &locked_random))
        );
        assert_eq!(
            sp.change_commitment_hex,
            fr_to_hex(&poseidon_commit(40, &change_random))
        );
    }

    #[test]
    fn split_proof_supports_exact_lock_no_change() {
        // Lock the entire 100-cash, no change — change_amount=0 + change_random=0
        // makes output[1] collapse to the constant zero-pad commitment chain
        // detects via PoseidonZeroCommitmentHex.
        let setup = dev_setup_snarkjs("split").expect("snarkjs setup");
        let handle = TestCircuitHandle::from_compiled(&setup.circuit_dir).expect("circuit handle");
        let witness = SplitWitness {
            inputs: vec![(100, [0xA1u8; 32])],
            locked_amount: 100,
            locked_random: [0xB2u8; 32],
            change_amount: 0,
            change_random: [0u8; 32],
        };
        let sp = prove_split(witness, &handle, &setup.zkey).expect("exact-lock split");
        // Without explicit change, the change commitment should equal Poseidon(0,0).
        assert_eq!(
            sp.change_commitment_hex,
            fr_to_hex(&poseidon_commit(0, &[0u8; 32]))
        );
    }

    #[test]
    fn settle_larger_proof_round_trips_through_rapidsnark() {
        // Alice locked 80 ETH (Token1 sender), trade fills 60, change=20.
        // Counterparty (bob) sends 60 USDT back (other_fill, price=1).
        let setup = dev_setup_snarkjs("settle_larger").expect("snarkjs setup");
        let handle = TestCircuitHandle::from_compiled(&setup.circuit_dir).expect("circuit handle");
        let in_random = [0xA1u8; 32];
        let r_my = [0x01u8; 32];
        let r_other = [0x02u8; 32];
        let change_random = [0xC3u8; 32];
        // Counterparty's recv commitment hex — bob computes Poseidon(60_USDT, his_random)
        // and gives it to alice. We just synthesize one for the round-trip.
        let bob_recv_random = [0xB0u8; 32];
        let bob_recv_commit_hex = fr_to_hex(&poseidon_commit(60, &bob_recv_random));
        let witness = SettleLargerWitness {
            r_my,
            other_fill: 60,
            r_other,
            price: 1,
            is_token2_sender: false,
            inputs: vec![(80, in_random)],
            change_amount: 20,
            change_random,
            counterparty_recv_commitment_hex: bob_recv_commit_hex.clone(),
        };
        let sp = prove_settle_larger(witness, &handle, &setup.zkey)
            .expect("rapidsnark prove settle_larger");

        assert_eq!(sp.proof_json["protocol"], "groth16");
        // public.json layout: [my_match, other_match, price, is_token2_sender,
        //                      input_hashes[0], input_hashes[1], change, recv]
        let public = sp.public_json.as_array().expect("public is array");
        assert_eq!(public.len(), 8);

        // commitments echoed match recomputing them off-circuit
        assert_eq!(
            sp.my_match_commitment_hex,
            fr_to_hex(&poseidon_commit(60, &r_my))
        );
        assert_eq!(
            sp.other_match_commitment_hex,
            fr_to_hex(&poseidon_commit(60, &r_other))
        );
        assert_eq!(
            sp.change_commitment_hex,
            fr_to_hex(&poseidon_commit(20, &change_random))
        );
    }

    #[test]
    fn settle_smaller_proof_round_trips_through_rapidsnark() {
        // Bob locked exactly 60 USDT (Token2 sender), no change. fill = inputs.sum.
        let setup = dev_setup_snarkjs("settle_smaller").expect("snarkjs setup");
        let handle = TestCircuitHandle::from_compiled(&setup.circuit_dir).expect("circuit handle");
        let in_random = [0xB2u8; 32];
        let r_match = [0x02u8; 32];
        // alice's recv commitment hex — she computes Poseidon(60_ETH, her_random) and gives it.
        let alice_recv_random = [0xA0u8; 32];
        let alice_recv_commit_hex = fr_to_hex(&poseidon_commit(60, &alice_recv_random));
        let witness = SettleSmallerWitness {
            r_match,
            inputs: vec![(60, in_random)],
            counterparty_recv_commitment_hex: alice_recv_commit_hex.clone(),
        };
        let sp = prove_settle_smaller(witness, &handle, &setup.zkey)
            .expect("rapidsnark prove settle_smaller");

        // public.json: [match_commitment, input_hashes[0], input_hashes[1], recv]
        let public = sp.public_json.as_array().expect("public is array");
        assert_eq!(public.len(), 4);
        assert_eq!(
            sp.match_commitment_hex,
            fr_to_hex(&poseidon_commit(60, &r_match))
        );
    }

    #[test]
    fn withdraw_proof_supports_single_input() {
        // One 100-cash spent, no change — exercises the N-padding path.
        let setup = dev_setup_snarkjs("withdraw").expect("snarkjs setup");
        let handle = TestCircuitHandle::from_compiled(&setup.circuit_dir).expect("circuit handle");
        let only_input = [0xD4u8; 32];
        let witness = WithdrawWitness {
            withdraw_amount: 100,
            r_bridge_out: [0x33u8; 32],
            inputs: vec![(100, only_input)],
            change_amount: 0,
            change_random: [0u8; 32],
        };
        let wp = prove_withdraw(witness, &handle, &setup.zkey).expect("single-input withdraw");
        assert_eq!(wp.input_commitments_hex.len(), 1);
    }
}
