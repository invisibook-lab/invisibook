pub mod circom_bridge;
pub mod test_circuit;

use std::{env, fs, path::PathBuf, process::Command};

use anyhow::ensure;
use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::snark::SNARK;
use ark_groth16::{Groth16, Proof, VerifyingKey, prepare_verifying_key};
use rand::thread_rng;
use serde_json::Value;

use crate::{circom_bridge::CircomCircuit, test_circuit::TestCircuitHandle};

/// The result of a Groth16 proof generation for any circuit in `templates/`.
pub struct CircuitProof {
    pub proof: Proof<Bn254>,
    pub public_inputs: Vec<Fr>,
    pub vk: VerifyingKey<Bn254>,
}

/// Generate a Groth16 proof for the named circuit (`templates/<name>.circom`).
///
/// This function:
/// 1. Compiles the circuit if needed (cached under `target/circuit-build/<name>/`)
/// 2. Generates the witness via node.js (circom WASM witness generator)
/// 3. Runs a random trusted setup (dev/test only)
/// 4. Generates and returns the Groth16 proof
pub fn generate_proof(name: &str, input: &Value) -> anyhow::Result<CircuitProof> {
    let out_dir = compile_circuit(name)?;
    let r1cs_path = out_dir.join(format!("{name}.r1cs"));

    // Generate witness via node.js
    let handle = TestCircuitHandle::from_compiled(&out_dir)?;
    let witness_path = handle.gen_witness(input)?;

    // Load R1CS as empty circuit for trusted setup
    let circuit_empty = CircomCircuit::from_r1cs(&r1cs_path, None)?;

    // Random trusted setup (dev/test only)
    let mut rng = thread_rng();
    let params =
        Groth16::<Bn254>::generate_random_parameters_with_reduction(circuit_empty, &mut rng)?;

    // Load circuit with witness for proving
    let circuit_with_witness = CircomCircuit::from_r1cs_and_wtns(&r1cs_path, &witness_path)?;
    let public_inputs = circuit_with_witness.public_inputs();

    // Generate the proof
    let proof = Groth16::<Bn254>::prove(&params, circuit_with_witness, &mut rng)?;

    // Verify locally
    let pvk = prepare_verifying_key(&params.vk);
    let verified = Groth16::<Bn254>::verify_proof(&pvk, &proof, &public_inputs)?;
    ensure!(verified, "Proof verification failed");

    Ok(CircuitProof {
        proof,
        public_inputs,
        vk: params.vk,
    })
}

/// Compile `templates/<name>.circom` if its artifacts are missing.
/// Output is cached under `lib/target/circuit-build/<name>/` so each circuit has
/// an isolated build directory and they do not clobber each other.
fn compile_circuit(name: &str) -> anyhow::Result<PathBuf> {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = manifest_dir.join(format!("../target/circuit-build/{name}"));
    let circuit_path = manifest_dir.join(format!("templates/{name}.circom"));
    let include_dir = manifest_dir.join("templates");

    let wasm = out_dir.join(format!("{name}_js/{name}.wasm"));
    let r1cs = out_dir.join(format!("{name}.r1cs"));
    // Skip compilation if artifacts already exist
    if wasm.exists() && r1cs.exists() {
        return Ok(out_dir);
    }

    fs::create_dir_all(&out_dir)?;

    let output = Command::new("circom")
        .args([
            "--O0",
            "-l",
            include_dir.to_str().unwrap(),
            circuit_path.to_str().unwrap(),
            "--wasm",
            "--r1cs",
            "-o",
            out_dir.to_str().unwrap(),
        ])
        .output()?;

    if !output.status.success() {
        // circom may panic after writing files (e.g. wasm-opt not found).
        // Check whether the essential outputs were still written.
        if wasm.exists() && r1cs.exists() {
            return Ok(out_dir);
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        anyhow::bail!("circom compilation failed:\n{}\n{}", stdout, stderr);
    }

    Ok(out_dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    use circom_bridge::fr_to_decimal_string;

    /// Compute circomlib-compatible Poseidon hash of a single u64 value.
    fn poseidon_hash(val: u64) -> Fr {
        use light_poseidon::{Poseidon, PoseidonHasher};
        let mut hasher = Poseidon::<Fr>::new_circom(1).unwrap();
        hasher.hash(&[Fr::from(val)]).unwrap()
    }

    /// Convert a u64 amount into its decimal-string Poseidon hash representation.
    fn hash_str(val: u64) -> String {
        fr_to_decimal_string(&poseidon_hash(val))
    }

    /// Convert a slice of u64 amounts into their decimal-string Poseidon hashes.
    fn hash_strs(vals: &[u64]) -> Vec<String> {
        vals.iter().copied().map(hash_str).collect()
    }

    /// Convert a slice of u64 amounts into their decimal-string representations.
    fn amount_strs(vals: &[u64]) -> Vec<String> {
        vals.iter().map(|v| v.to_string()).collect()
    }

    #[test]
    fn main_template_should_compile() {
        TestCircuitHandle::new("templates/main.circom").unwrap();
    }

    #[test]
    fn main_template_witness_gen_valid() {
        let handle = TestCircuitHandle::new("templates/main.circom").unwrap();

        let input = serde_json::json!({
            "larger_amount": "100",
            "smaller_amount": "50",
            "larger_amount_hash": hash_str(100),
            "smaller_amount_hash": hash_str(50),
        });

        let witness_path = handle.gen_witness(&input).unwrap();
        assert!(witness_path.exists(), "Witness file should exist");
    }

    #[test]
    fn generate_proof_and_verify() {
        let input = serde_json::json!({
            "larger_amount": "100",
            "smaller_amount": "50",
            "larger_amount_hash": hash_str(100),
            "smaller_amount_hash": hash_str(50),
        });

        let result = generate_proof("main", &input);
        assert!(
            result.is_ok(),
            "Proof generation failed: {:?}",
            result.err()
        );

        let proof = result.unwrap();
        let pvk = prepare_verifying_key(&proof.vk);
        let verified =
            Groth16::<Bn254>::verify_proof(&pvk, &proof.proof, &proof.public_inputs).unwrap();
        assert!(verified, "Proof should verify");
    }

    #[test]
    fn generate_proof_fails_when_smaller_gt_larger() {
        // larger_amount=50, smaller_amount=100 with correct hashes
        // Should fail: 100 > 50, violating LessEqThan constraint
        let input = serde_json::json!({
            "larger_amount": "50",
            "smaller_amount": "100",
            "larger_amount_hash": hash_str(50),
            "smaller_amount_hash": hash_str(100),
        });

        let result = generate_proof("main", &input);
        assert!(
            result.is_err(),
            "Should fail when smaller_amount > larger_amount"
        );
    }

    // ────────────────────── DepositVerify ──────────────────────

    #[test]
    fn deposit_proof_verifies_when_outputs_sum_to_deposit() {
        // Bridged 150; mint as two output cashes 100 + 50
        let input = serde_json::json!({
            "deposit_amount": "150",
            "output_amounts": amount_strs(&[100, 50]),
            "output_hashes": hash_strs(&[100, 50]),
        });
        let proof = generate_proof("deposit", &input).expect("deposit proof should succeed");
        let pvk = prepare_verifying_key(&proof.vk);
        assert!(Groth16::<Bn254>::verify_proof(&pvk, &proof.proof, &proof.public_inputs).unwrap());
    }

    #[test]
    fn deposit_proof_supports_single_output_with_zero_padding() {
        // Bridged 100; only one real output, second slot padded with amount=0
        let input = serde_json::json!({
            "deposit_amount": "100",
            "output_amounts": amount_strs(&[100, 0]),
            "output_hashes": hash_strs(&[100, 0]),
        });
        generate_proof("deposit", &input).expect("padded deposit proof should succeed");
    }

    #[test]
    fn deposit_proof_fails_when_outputs_overshoot_deposit() {
        // Bridged 100 but outputs claim 100 + 1 — would mint value out of nothing
        let input = serde_json::json!({
            "deposit_amount": "100",
            "output_amounts": amount_strs(&[100, 1]),
            "output_hashes": hash_strs(&[100, 1]),
        });
        assert!(generate_proof("deposit", &input).is_err());
    }

    // ────────────────────── WithdrawVerify ──────────────────────

    #[test]
    fn withdraw_proof_verifies_with_change() {
        // Spend 70 + 40 = 110; withdraw 100; mint 10 as change
        let input = serde_json::json!({
            "withdraw_amount": "100",
            "input_amounts": amount_strs(&[70, 40]),
            "input_hashes": hash_strs(&[70, 40]),
            "output_amounts": amount_strs(&[10, 0]),
            "output_hashes": hash_strs(&[10, 0]),
        });
        generate_proof("withdraw", &input).expect("withdraw with change should prove");
    }

    #[test]
    fn withdraw_proof_verifies_without_change() {
        // Spend 60 + 40 = 100; withdraw 100; no change
        let input = serde_json::json!({
            "withdraw_amount": "100",
            "input_amounts": amount_strs(&[60, 40]),
            "input_hashes": hash_strs(&[60, 40]),
            "output_amounts": amount_strs(&[0, 0]),
            "output_hashes": hash_strs(&[0, 0]),
        });
        generate_proof("withdraw", &input).expect("exact withdraw should prove");
    }

    #[test]
    fn withdraw_proof_fails_when_inputs_insufficient() {
        // Spend 30 + 20 = 50; try to withdraw 100 — would create value
        let input = serde_json::json!({
            "withdraw_amount": "100",
            "input_amounts": amount_strs(&[30, 20]),
            "input_hashes": hash_strs(&[30, 20]),
            "output_amounts": amount_strs(&[0, 0]),
            "output_hashes": hash_strs(&[0, 0]),
        });
        assert!(generate_proof("withdraw", &input).is_err());
    }

    // ────────────────────── SplitVerify ──────────────────────

    #[test]
    fn split_proof_verifies_when_inputs_equal_outputs() {
        // One 100-cash split into a 60 locked cash + a 40 change cash
        let input = serde_json::json!({
            "input_amounts": amount_strs(&[100, 0]),
            "input_hashes": hash_strs(&[100, 0]),
            "output_amounts": amount_strs(&[60, 40]),
            "output_hashes": hash_strs(&[60, 40]),
        });
        generate_proof("split", &input).expect("split conservation should prove");
    }

    #[test]
    fn split_proof_fails_when_outputs_exceed_inputs() {
        let input = serde_json::json!({
            "input_amounts": amount_strs(&[100, 0]),
            "input_hashes": hash_strs(&[100, 0]),
            "output_amounts": amount_strs(&[60, 50]),
            "output_hashes": hash_strs(&[60, 50]),
        });
        assert!(generate_proof("split", &input).is_err());
    }

    // ────────────────────── SettleVerify ──────────────────────

    #[test]
    fn settle_proof_verifies_when_inputs_equal_outputs() {
        // Token-group example: two locked inputs (80 + 20) flow to two recipients (50 + 50)
        let input = serde_json::json!({
            "input_amounts": amount_strs(&[80, 20]),
            "input_hashes": hash_strs(&[80, 20]),
            "output_amounts": amount_strs(&[50, 50]),
            "output_hashes": hash_strs(&[50, 50]),
        });
        generate_proof("settle", &input).expect("settle conservation should prove");
    }

    #[test]
    fn settle_proof_fails_when_inputs_exceed_outputs() {
        // Inputs 100 but only 90 minted — burning value should also be rejected
        let input = serde_json::json!({
            "input_amounts": amount_strs(&[80, 20]),
            "input_hashes": hash_strs(&[80, 20]),
            "output_amounts": amount_strs(&[50, 40]),
            "output_hashes": hash_strs(&[50, 40]),
        });
        assert!(generate_proof("settle", &input).is_err());
    }

    #[test]
    fn settle_proof_fails_when_commitment_does_not_open() {
        // Output amount 60 but its hash is for 50 — commitment opening must fail
        let input = serde_json::json!({
            "input_amounts": amount_strs(&[100, 0]),
            "input_hashes": hash_strs(&[100, 0]),
            "output_amounts": amount_strs(&[60, 40]),
            "output_hashes": [hash_str(50), hash_str(40)],
        });
        assert!(generate_proof("settle", &input).is_err());
    }
}
