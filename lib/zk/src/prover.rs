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
    use crate::{
        setup::dev_setup_snarkjs,
        test_circuit::TestCircuitHandle,
        wallet::{SettleCmpWitness, fr_to_hex, poseidon_commit, prove_settle_cmp},
    };

    #[test]
    fn settle_cmp_proof_round_trips_through_rapidsnark() {
        // A sells 80, B buys 60 → cmp = 1. Publics: [cmp, order_a, order_b].
        let setup = dev_setup_snarkjs("settle_cozk").expect("snarkjs setup");
        let handle = TestCircuitHandle::from_compiled(&setup.circuit_dir).expect("circuit handle");
        let witness = SettleCmpWitness {
            a: 80,
            r_a: [0xA1u8; 32],
            b: 60,
            r_b: [0xB1u8; 32],
        };
        let sp =
            prove_settle_cmp(&witness, &handle, &setup.zkey).expect("rapidsnark prove settle_cmp");

        assert_eq!(sp.proof_json["protocol"], "groth16");
        let public = sp.public_json.as_array().expect("public is array");
        assert_eq!(public.len(), 3);
        assert_eq!(sp.cmp, 1);
        assert_eq!(
            sp.order_a_commitment_hex,
            fr_to_hex(&poseidon_commit(80, &[0xA1u8; 32]))
        );
    }
}
