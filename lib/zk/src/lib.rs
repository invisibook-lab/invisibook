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

/// The result of a Groth16 proof generation for the OrderVerify circuit.
pub struct OrderProof {
    pub proof: Proof<Bn254>,
    pub public_inputs: Vec<Fr>,
    pub vk: VerifyingKey<Bn254>,
}

/// Given circuit input signals as JSON, generate a Groth16 proof for the OrderVerify circuit.
///
/// This function:
/// 1. Compiles the OrderVerify circuit (templates/main.circom) if needed
/// 2. Generates the witness via node.js (circom WASM witness generator)
/// 3. Runs a random trusted setup (dev/test only)
/// 4. Generates and returns the Groth16 proof
pub fn generate_proof(input: &Value) -> anyhow::Result<OrderProof> {
    let out_dir = compile_circuit()?;
    let r1cs_path = out_dir.join("main.r1cs");

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

    Ok(OrderProof {
        proof,
        public_inputs,
        vk: params.vk,
    })
}

/// Compile the main circom circuit if not already compiled.
/// Build output is stored under lib/target/circuit-build/.
fn compile_circuit() -> anyhow::Result<PathBuf> {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = manifest_dir.join("../target/circuit-build");
    let circuit_path = manifest_dir.join("templates/main.circom");
    let include_dir = manifest_dir.join("templates");

    let wasm = out_dir.join("main_js/main.wasm");
    let r1cs = out_dir.join("main.r1cs");
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
        // circom may panic after writing files (e.g. wasm-opt not found)
        // Check if the essential outputs were still written
        let wasm = out_dir.join("main_js/main.wasm");
        let r1cs = out_dir.join("main.r1cs");
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

    /// Compute circomlib-compatible Poseidon hash of a single u64 value.
    fn poseidon_hash(val: u64) -> Fr {
        use light_poseidon::{Poseidon, PoseidonHasher};
        let mut hasher = Poseidon::<Fr>::new_circom(1).unwrap();
        hasher.hash(&[Fr::from(val)]).unwrap()
    }

    #[test]
    fn main_template_should_compile() {
        TestCircuitHandle::new("templates/main.circom").unwrap();
    }

    #[test]
    fn main_template_witness_gen_valid() {
        let handle = TestCircuitHandle::new("templates/main.circom").unwrap();

        let larger_hash = poseidon_hash(100);
        let smaller_hash = poseidon_hash(50);

        let input = serde_json::json!({
            "larger_amount": "100",
            "smaller_amount": "50",
            "larger_amount_hash": circom_bridge::fr_to_decimal_string(&larger_hash),
            "smaller_amount_hash": circom_bridge::fr_to_decimal_string(&smaller_hash),
        });

        let witness_path = handle.gen_witness(&input).unwrap();
        assert!(witness_path.exists(), "Witness file should exist");
    }

    #[test]
    fn generate_proof_and_verify() {
        let larger_hash = poseidon_hash(100);
        let smaller_hash = poseidon_hash(50);

        let input = serde_json::json!({
            "larger_amount": "100",
            "smaller_amount": "50",
            "larger_amount_hash": circom_bridge::fr_to_decimal_string(&larger_hash),
            "smaller_amount_hash": circom_bridge::fr_to_decimal_string(&smaller_hash),
        });

        let result = generate_proof(&input);
        assert!(
            result.is_ok(),
            "Proof generation failed: {:?}",
            result.err()
        );

        let order_proof = result.unwrap();
        let pvk = prepare_verifying_key(&order_proof.vk);
        let verified =
            Groth16::<Bn254>::verify_proof(&pvk, &order_proof.proof, &order_proof.public_inputs)
                .unwrap();
        assert!(verified, "Proof should verify");
    }

    #[test]
    fn generate_proof_fails_when_smaller_gt_larger() {
        let hash_50 = poseidon_hash(50);
        let hash_100 = poseidon_hash(100);

        // larger_amount=50, smaller_amount=100 with correct hashes
        // Should fail: 100 > 50, violating LessEqThan constraint
        let input = serde_json::json!({
            "larger_amount": "50",
            "smaller_amount": "100",
            "larger_amount_hash": circom_bridge::fr_to_decimal_string(&hash_50),
            "smaller_amount_hash": circom_bridge::fr_to_decimal_string(&hash_100),
        });

        let result = generate_proof(&input);
        assert!(
            result.is_err(),
            "Should fail when smaller_amount > larger_amount"
        );
    }
}
