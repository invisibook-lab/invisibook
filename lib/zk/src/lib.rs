pub mod circom_bridge;
pub mod prover;
pub mod setup;
pub mod test_circuit;
pub mod wallet;

use std::{
    any::TypeId,
    env,
    fs::{File, create_dir_all},
    io::{BufReader, BufWriter},
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, ensure};
use ark_bn254::Bn254;
use ark_crypto_primitives::snark::SNARK;
use ark_ec::pairing::Pairing;
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey, prepare_verifying_key};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::thread_rng;
use serde_json::Value;

use crate::{circom_bridge::CircomCircuit, test_circuit::TestCircuitHandle};

/// A Groth16 proof together with its public inputs.
///
/// The verifying key is intentionally not bundled here — under the trusted-setup
/// model the verifier holds its own canonical VK (e.g. hardcoded into the
/// settlement contract). Anything the prover ships could otherwise be replaced
/// with an attacker-controlled VK paired with a forged proof.
pub struct CircuitProof<E: Pairing> {
    pub proof: Proof<E>,
    pub public_inputs: Vec<E::ScalarField>,
}

/// Output of a Groth16 trusted setup ceremony for one specific circuit.
///
/// `pk` lives on the prover; `vk` lives on the verifier. They must originate
/// from the same multi-party ceremony — Groth16's verification equation only
/// holds when both keys encode the same `(τ, α, β, γ, δ)` trapdoor.
pub struct CircuitParams<E: Pairing> {
    pub pk: ProvingKey<E>,
    pub vk: VerifyingKey<E>,
}

/// Asserts at runtime that `E` is BN254. circom only emits BN254 R1CS, so
/// any code path that proves a circom-compiled circuit is BN254-only.
fn assert_bn254<E: 'static>() {
    assert_eq!(
        TypeId::of::<E>(),
        TypeId::of::<Bn254>(),
        "zk currently supports only BN254"
    );
}

/// Production trusted-setup loader: reads circuit parameters from a file
/// produced by `save_params`, which in turn should be written from a
/// multi-party ceremony output (Powers of Tau phase 1 + circuit-specific
/// phase 2).
///
/// File format is arkworks's canonical-serialize, compressed encoding. The
/// expected pipeline is: run the ceremony with snarkjs (`.zkey`), convert
/// once offline into this format, then ship the result to the prover.
///
/// The resulting params are only safe to use if at least one ceremony
/// participant honestly destroyed their share of the toxic waste — see
/// `dev_setup` for the security difference.
///
/// Loading is intended to happen once at process startup; a `ProvingKey` is
/// large (tens of MB to GB depending on the circuit), so the caller should
/// keep the result in memory and reuse it across every proof for that circuit.
pub fn load_params<E: Pairing + 'static>(path: &Path) -> anyhow::Result<CircuitParams<E>> {
    assert_bn254::<E>();
    let file = File::open(path)
        .with_context(|| format!("opening trusted-setup file {}", path.display()))?;
    let mut reader = BufReader::new(file);
    let pk = ProvingKey::<E>::deserialize_compressed(&mut reader)
        .with_context(|| format!("deserializing ProvingKey from {}", path.display()))?;
    let vk = pk.vk.clone();
    Ok(CircuitParams { pk, vk })
}

/// Persist circuit parameters in arkworks's canonical-serialize, compressed
/// encoding. Companion to `load_params`. Typically used by the offline tool
/// that converts a ceremony output (e.g. snarkjs `.zkey`) into the on-disk
/// format the prover service consumes.
pub fn save_params<E: Pairing>(params: &CircuitParams<E>, path: &Path) -> anyhow::Result<()> {
    let file = File::create(path)
        .with_context(|| format!("creating trusted-setup file {}", path.display()))?;
    let mut writer = BufWriter::new(file);
    params
        .pk
        .serialize_compressed(&mut writer)
        .with_context(|| format!("serializing ProvingKey to {}", path.display()))?;
    Ok(())
}

/// **DEV/TEST ONLY.** Generates Groth16 parameters via a single-party local
/// random setup, with the toxic waste held in this process's memory.
///
/// In a real deployment this is fatally insecure: anyone with access to the
/// generating process can recover `(τ, α, β, γ, δ)` and forge proofs against
/// the resulting VK without satisfying the circuit. Production must call
/// `load_params` against a multi-party ceremony output instead.
pub fn dev_setup<E: Pairing + 'static>(name: &str) -> anyhow::Result<CircuitParams<E>> {
    assert_bn254::<E>();
    let out_dir = compile_circuit(name)?;
    let r1cs_path = out_dir.join(format!("{name}.r1cs"));

    // Setup only consumes the R1CS shape; no witness is needed.
    let circuit_empty = CircomCircuit::<E>::from_r1cs(&r1cs_path, None)?;
    let mut rng = thread_rng();
    let pk = Groth16::<E>::generate_random_parameters_with_reduction(circuit_empty, &mut rng)?;
    let vk = pk.vk.clone();

    Ok(CircuitParams { pk, vk })
}

/// Generate a Groth16 proof for the named circuit using a pre-computed
/// proving key. `params` must come from `load_params` in production
/// (or `dev_setup` in tests) — never from a setup the prover ran herself
/// without trusted-ceremony provenance.
pub fn generate_proof<E: Pairing + 'static>(
    name: &str,
    input: &Value,
    params: &CircuitParams<E>,
) -> anyhow::Result<CircuitProof<E>> {
    assert_bn254::<E>();
    let out_dir = compile_circuit(name)?;
    let r1cs_path = out_dir.join(format!("{name}.r1cs"));

    // Generate witness via node.js
    let handle = TestCircuitHandle::from_compiled(&out_dir)?;
    let witness_path = handle.gen_witness(input)?;

    // Load circuit with witness for proving
    let circuit = CircomCircuit::<E>::from_r1cs_and_wtns(&r1cs_path, &witness_path)?;
    let public_inputs = circuit.public_inputs();

    let mut rng = thread_rng();
    let proof = Groth16::<E>::prove(&params.pk, circuit, &mut rng)?;

    // Local sanity check — fails early if the prover's params have drifted
    // from the verifier's. Production verifiers run their own check anyway
    // against their canonical VK.
    let pvk = prepare_verifying_key(&params.vk);
    let verified = Groth16::<E>::verify_proof(&pvk, &proof, &public_inputs)?;
    ensure!(verified, "Proof verification failed");

    Ok(CircuitProof {
        proof,
        public_inputs,
    })
}

/// Verify a Groth16 proof against a verifying key the verifier holds
/// canonically (from its own copy of the trusted-setup ceremony output).
pub fn verify_proof<E: Pairing>(
    proof: &CircuitProof<E>,
    vk: &VerifyingKey<E>,
) -> anyhow::Result<bool> {
    let pvk = prepare_verifying_key(vk);
    Ok(Groth16::<E>::verify_proof(
        &pvk,
        &proof.proof,
        &proof.public_inputs,
    )?)
}

/// Return the circom optimization flag for the named circuit.
///
/// Wallet circuits keep `--O0` (no constraint simplification — every wire
/// survives, which is what the existing zkeys and fixtures were built from).
/// `settle_cozk` must use `--O2`: with `--O0` its ~6k linear constraints
/// overflow the pot13 dev ptau, and the co-snarks MPC witness extension
/// (`lib/cozk`) compiles the same source at simplification level O2, so the
/// snarkjs zkey has to be generated from the O2 R1CS for the witness layout
/// to match.
fn circuit_opt_flag(name: &str) -> &'static str {
    if name == "settle_cozk" {
        "--O2"
    } else {
        "--O0"
    }
}

/// Compile `templates/<name>.circom` if its artifacts are missing.
/// Output is cached under `lib/target/circuit-build/<name>/` so each circuit has
/// an isolated build directory and they do not clobber each other.
///
/// `CARGO_MANIFEST_DIR` is baked in at compile time via `env!()` so this works
/// from any process (test, example, or shipped binary) — not just under
/// `cargo test`, where the env var is set live.
fn compile_circuit(name: &str) -> anyhow::Result<PathBuf> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let out_dir = manifest_dir.join(format!("../target/circuit-build/{name}"));
    let circuit_path = manifest_dir.join(format!("templates/{name}.circom"));
    let include_dir = manifest_dir.join("templates");

    let wasm = out_dir.join(format!("{name}_js/{name}.wasm"));
    let r1cs = out_dir.join(format!("{name}.r1cs"));
    // Skip compilation if artifacts already exist
    if wasm.exists() && r1cs.exists() {
        return Ok(out_dir);
    }

    create_dir_all(&out_dir)?;

    let output = Command::new("circom")
        .args([
            circuit_opt_flag(name),
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

    use std::{
        collections::HashMap,
        sync::{Mutex, OnceLock},
    };

    use ark_bn254::Fr;
    use ark_ff::{BigInteger, PrimeField};
    use circom_bridge::fr_to_decimal_string;

    use crate::wallet::{SettleCoZkSide, SettleCoZkWitness};

    /// Cached `dev_setup` result per circuit name. A real ceremony's PK is
    /// loaded once at startup; mirroring that here also avoids paying ~200 ms
    /// of random-setup cost on every test.
    fn cached_params(name: &str) -> &'static CircuitParams<Bn254> {
        static CACHE: OnceLock<Mutex<HashMap<String, &'static CircuitParams<Bn254>>>> =
            OnceLock::new();
        let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
        let mut guard = cache.lock().unwrap();
        if let Some(p) = guard.get(name) {
            return p;
        }
        let params = dev_setup::<Bn254>(name).expect("dev_setup failed");
        let leaked: &'static CircuitParams<Bn254> = Box::leak(Box::new(params));
        guard.insert(name.to_string(), leaked);
        leaked
    }

    /// Deterministic per-amount blinding factor for tests. Using a fixed-but-
    /// distinct r per amount keeps tests reproducible while still exercising
    /// the two-input Poseidon commitment path. Production code must draw r
    /// from a CSPRNG (256-bit) per the protocol spec.
    fn test_r(amount: u64) -> Fr {
        // Hash the amount with a constant tag to derive an r that varies per
        // amount but is deterministic across runs. The Poseidon parity tests
        // already cover the hash itself; here we just want a reproducible r.
        use light_poseidon::{Poseidon, PoseidonHasher};
        let mut hasher = Poseidon::<Fr>::new_circom(2).unwrap();
        hasher
            .hash(&[Fr::from(amount), Fr::from(0xA11CE_u64)])
            .unwrap()
    }

    /// Compute the commitment `Poseidon(2)([amount, r])` matching the circom
    /// circuit's `Poseidon(2)([amount, r])` evaluation.
    fn poseidon_hash(amount: u64, r: Fr) -> Fr {
        use light_poseidon::{Poseidon, PoseidonHasher};
        let mut hasher = Poseidon::<Fr>::new_circom(2).unwrap();
        hasher.hash(&[Fr::from(amount), r]).unwrap()
    }

    /// Decimal-string commitment for amount `val` under the test blinding factor.
    fn hash_str(val: u64) -> String {
        fr_to_decimal_string(&poseidon_hash(val, test_r(val)))
    }

    /// Decimal-string commitments for a slice of amounts, each with its test r.
    fn hash_strs(vals: &[u64]) -> Vec<String> {
        vals.iter().copied().map(hash_str).collect()
    }

    /// Decimal-string blinding factors corresponding to `vals` (same indexing).
    fn r_strs(vals: &[u64]) -> Vec<String> {
        vals.iter()
            .map(|v| fr_to_decimal_string(&test_r(*v)))
            .collect()
    }

    /// Convert a slice of u64 amounts into their decimal-string representations.
    fn amount_strs(vals: &[u64]) -> Vec<String> {
        vals.iter().map(|v| v.to_string()).collect()
    }

    /// Bridge-side blinding factor for tests, distinct from the per-output `test_r`
    /// so that bridge_commitment binds (deposit_amount, r_bridge) independently of
    /// any output's blinding factor.
    fn bridge_r(deposit_amount: u64) -> Fr {
        test_r(deposit_amount.wrapping_add(0xB81D6E))
    }

    /// Decimal-string Poseidon commitment of (deposit_amount, bridge_r(deposit_amount)).
    fn bridge_commit_str(deposit_amount: u64) -> String {
        fr_to_decimal_string(&poseidon_hash(deposit_amount, bridge_r(deposit_amount)))
    }

    /// Withdraw-side bridge_out blinding factor for tests, distinct from both
    /// per-cash `test_r` and the deposit-side `bridge_r` so the three never
    /// alias.
    fn bridge_out_r(withdraw_amount: u64) -> Fr {
        test_r(withdraw_amount.wrapping_add(0xB7DDA7))
    }

    /// Decimal-string `Poseidon(withdraw_amount, bridge_out_r(withdraw_amount))`.
    fn bridge_out_commit_str(withdraw_amount: u64) -> String {
        fr_to_decimal_string(&poseidon_hash(
            withdraw_amount,
            bridge_out_r(withdraw_amount),
        ))
    }

    // ────────────────────── DepositVerify ──────────────────────

    #[test]
    fn deposit_proof_verifies_when_outputs_sum_to_deposit() {
        // Bridged 150 (hidden); mint as two output cashes 100 + 50.
        // Public inputs the verifier sees: bridge_commitment + output_hashes.
        let input = serde_json::json!({
            "bridge_commitment": bridge_commit_str(150),
            "output_hashes": hash_strs(&[100, 50]),
            "deposit_amount": "150",
            "r_bridge": fr_to_decimal_string(&bridge_r(150)),
            "output_amounts": amount_strs(&[100, 50]),
            "output_randomness": r_strs(&[100, 50]),
        });
        let params = cached_params("deposit");
        let proof = generate_proof::<Bn254>("deposit", &input, params)
            .expect("deposit proof should succeed");
        assert!(verify_proof(&proof, &params.vk).unwrap());
    }

    #[test]
    fn deposit_proof_supports_single_output_with_zero_padding() {
        // Bridged 100 (hidden); only one real output, second slot padded with amount=0
        let input = serde_json::json!({
            "bridge_commitment": bridge_commit_str(100),
            "output_hashes": hash_strs(&[100, 0]),
            "deposit_amount": "100",
            "r_bridge": fr_to_decimal_string(&bridge_r(100)),
            "output_amounts": amount_strs(&[100, 0]),
            "output_randomness": r_strs(&[100, 0]),
        });
        let params = cached_params("deposit");
        generate_proof::<Bn254>("deposit", &input, params)
            .expect("padded deposit proof should succeed");
    }

    #[test]
    fn deposit_proof_fails_when_outputs_overshoot_deposit() {
        // bridge_commitment binds deposit_amount=100, but outputs claim 100 + 1 —
        // would mint value out of nothing. Conservation constraint must reject.
        let input = serde_json::json!({
            "bridge_commitment": bridge_commit_str(100),
            "output_hashes": hash_strs(&[100, 1]),
            "deposit_amount": "100",
            "r_bridge": fr_to_decimal_string(&bridge_r(100)),
            "output_amounts": amount_strs(&[100, 1]),
            "output_randomness": r_strs(&[100, 1]),
        });
        let params = cached_params("deposit");
        assert!(generate_proof::<Bn254>("deposit", &input, params).is_err());
    }

    #[test]
    fn deposit_proof_fails_when_amount_does_not_match_bridge() {
        // Malicious prover: bridge_commitment is for amount=100, but the prover
        // privately claims deposit_amount=200 and outputs 200. The Poseidon
        // bridge-binding constraint must reject because Poseidon(200, r_for_100)
        // ≠ bridge_commitment(100, r_for_100).
        let input = serde_json::json!({
            "bridge_commitment": bridge_commit_str(100),
            "output_hashes": hash_strs(&[200, 0]),
            "deposit_amount": "200",
            "r_bridge": fr_to_decimal_string(&bridge_r(100)),
            "output_amounts": amount_strs(&[200, 0]),
            "output_randomness": r_strs(&[200, 0]),
        });
        let params = cached_params("deposit");
        assert!(generate_proof::<Bn254>("deposit", &input, params).is_err());
    }

    // ────────────────────── WithdrawVerify ──────────────────────

    #[test]
    fn withdraw_proof_verifies_with_change() {
        // Spend 70 + 40 = 110; withdraw 100 (hidden); mint 10 as change.
        // Public inputs the verifier sees: bridge_out_commitment + input/output hashes.
        let input = serde_json::json!({
            "bridge_out_commitment": bridge_out_commit_str(100),
            "input_hashes": hash_strs(&[70, 40]),
            "output_hashes": hash_strs(&[10, 0]),
            "withdraw_amount": "100",
            "r_bridge_out": fr_to_decimal_string(&bridge_out_r(100)),
            "input_amounts": amount_strs(&[70, 40]),
            "input_randomness": r_strs(&[70, 40]),
            "output_amounts": amount_strs(&[10, 0]),
            "output_randomness": r_strs(&[10, 0]),
        });
        let params = cached_params("withdraw");
        generate_proof::<Bn254>("withdraw", &input, params)
            .expect("withdraw with change should prove");
    }

    #[test]
    fn withdraw_proof_verifies_without_change() {
        // Spend 60 + 40 = 100; withdraw 100; no change (both output slots zero-padded).
        let input = serde_json::json!({
            "bridge_out_commitment": bridge_out_commit_str(100),
            "input_hashes": hash_strs(&[60, 40]),
            "output_hashes": hash_strs(&[0, 0]),
            "withdraw_amount": "100",
            "r_bridge_out": fr_to_decimal_string(&bridge_out_r(100)),
            "input_amounts": amount_strs(&[60, 40]),
            "input_randomness": r_strs(&[60, 40]),
            "output_amounts": amount_strs(&[0, 0]),
            "output_randomness": r_strs(&[0, 0]),
        });
        let params = cached_params("withdraw");
        generate_proof::<Bn254>("withdraw", &input, params).expect("exact withdraw should prove");
    }

    #[test]
    fn withdraw_proof_fails_when_inputs_insufficient() {
        // Spend 30 + 20 = 50; try to withdraw 100 — would create value
        let input = serde_json::json!({
            "bridge_out_commitment": bridge_out_commit_str(100),
            "input_hashes": hash_strs(&[30, 20]),
            "output_hashes": hash_strs(&[0, 0]),
            "withdraw_amount": "100",
            "r_bridge_out": fr_to_decimal_string(&bridge_out_r(100)),
            "input_amounts": amount_strs(&[30, 20]),
            "input_randomness": r_strs(&[30, 20]),
            "output_amounts": amount_strs(&[0, 0]),
            "output_randomness": r_strs(&[0, 0]),
        });
        let params = cached_params("withdraw");
        assert!(generate_proof::<Bn254>("withdraw", &input, params).is_err());
    }

    #[test]
    fn withdraw_proof_fails_when_amount_does_not_match_bridge() {
        // Malicious prover: bridge_out_commitment is for amount=100, but the
        // prover privately claims withdraw_amount=200 and the inputs sum to 200.
        // The Poseidon bridge-binding constraint must reject because
        // Poseidon(200, r_for_100) ≠ bridge_out_commitment(100, r_for_100).
        let input = serde_json::json!({
            "bridge_out_commitment": bridge_out_commit_str(100),
            "input_hashes": hash_strs(&[200, 0]),
            "output_hashes": hash_strs(&[0, 0]),
            "withdraw_amount": "200",
            "r_bridge_out": fr_to_decimal_string(&bridge_out_r(100)),
            "input_amounts": amount_strs(&[200, 0]),
            "input_randomness": r_strs(&[200, 0]),
            "output_amounts": amount_strs(&[0, 0]),
            "output_randomness": r_strs(&[0, 0]),
        });
        let params = cached_params("withdraw");
        assert!(generate_proof::<Bn254>("withdraw", &input, params).is_err());
    }

    // ────────────────────── SplitVerify ──────────────────────

    #[test]
    fn split_proof_verifies_when_inputs_equal_outputs() {
        // One 100-cash split into a 60 locked cash + a 40 change cash
        let input = serde_json::json!({
            "input_amounts": amount_strs(&[100, 0]),
            "input_randomness": r_strs(&[100, 0]),
            "input_hashes": hash_strs(&[100, 0]),
            "output_amounts": amount_strs(&[60, 40]),
            "output_randomness": r_strs(&[60, 40]),
            "output_hashes": hash_strs(&[60, 40]),
        });
        let params = cached_params("split");
        generate_proof::<Bn254>("split", &input, params).expect("split conservation should prove");
    }

    #[test]
    fn split_proof_fails_when_outputs_exceed_inputs() {
        let input = serde_json::json!({
            "input_amounts": amount_strs(&[100, 0]),
            "input_randomness": r_strs(&[100, 0]),
            "input_hashes": hash_strs(&[100, 0]),
            "output_amounts": amount_strs(&[60, 50]),
            "output_randomness": r_strs(&[60, 50]),
            "output_hashes": hash_strs(&[60, 50]),
        });
        let params = cached_params("split");
        assert!(generate_proof::<Bn254>("split", &input, params).is_err());
    }

    // ────────────────────── SettleCoZk ──────────────────────

    /// Fr blinding rendered as the 32-byte big-endian array the wallet API takes.
    fn r_bytes(seed: u64) -> [u8; 32] {
        let bytes = test_r(seed).into_bigint().to_bytes_be();
        let mut out = [0u8; 32];
        out[32 - bytes.len()..].copy_from_slice(&bytes);
        out
    }

    /// Build a settle_cozk witness: A's order is `a_amt` token1, B's `b_amt`,
    /// each backed by a single locked cash of exactly the required collateral.
    fn cozk_witness(a_amt: u64, b_amt: u64, price: u64, a_is_seller: bool) -> SettleCoZkWitness {
        let side = |amt: u64, is_seller: bool, salt: u64| SettleCoZkSide {
            order_amount: amt,
            r_order: r_bytes(salt),
            r_order_new: r_bytes(salt + 1),
            locked: vec![(if is_seller { amt } else { amt * price }, r_bytes(salt + 2))],
            r_locked_new: r_bytes(salt + 3),
            r_recv: r_bytes(salt + 4),
        };
        SettleCoZkWitness {
            a: side(a_amt, a_is_seller, 0x0A00),
            b: side(b_amt, !a_is_seller, 0x0B00),
            price,
            a_is_seller,
        }
    }

    /// Prove and verify, then assert the 15-signal public vector layout
    /// (outputs first, then public inputs) matches the documented order the
    /// chain rebuilds. Returns the proof for further inspection.
    fn cozk_prove_and_check(w: &SettleCoZkWitness) -> CircuitProof<Bn254> {
        use crate::wallet::{
            poseidon_commit, settle_cozk_cmp_fr, settle_cozk_input_json, settle_cozk_outcome,
        };
        let input = settle_cozk_input_json(w).expect("witness builds");
        let params = cached_params("settle_cozk");
        let proof = generate_proof::<Bn254>("settle_cozk", &input, params)
            .expect("settle_cozk should prove");
        assert!(verify_proof(&proof, &params.vk).unwrap());

        let out = settle_cozk_outcome(w).expect("outcome computes");
        let expected: Vec<Fr> = vec![
            settle_cozk_cmp_fr(out.cmp),
            poseidon_commit(out.a_prime, &w.a.r_order_new),
            poseidon_commit(out.b_prime, &w.b.r_order_new),
            poseidon_commit(out.a_new_locked, &w.a.r_locked_new),
            poseidon_commit(out.b_new_locked, &w.b.r_locked_new),
            poseidon_commit(out.a_recv, &w.a.r_recv),
            poseidon_commit(out.b_recv, &w.b.r_recv),
            poseidon_commit(w.a.order_amount, &w.a.r_order),
            poseidon_commit(w.b.order_amount, &w.b.r_order),
            Fr::from(w.price),
            Fr::from(w.a_is_seller as u64),
            poseidon_commit(w.a.locked[0].0, &w.a.locked[0].1),
            poseidon_commit(0, &[0u8; 32]),
            poseidon_commit(w.b.locked[0].0, &w.b.locked[0].1),
            poseidon_commit(0, &[0u8; 32]),
        ];
        assert_eq!(
            proof.public_inputs, expected,
            "public vector must be [outputs..., public inputs...] in declaration order"
        );
        proof
    }

    /// A (maker) sells 80 token1 at price 3; B buys 60 → B fully fills,
    /// cmp = 1, A keeps 20 on the book. Covers the seller-is-larger mux path.
    #[test]
    fn settle_cozk_proof_verifies_partial_fill() {
        let w = cozk_witness(80, 60, 3, true);
        cozk_prove_and_check(&w);
    }

    /// A (maker) buys 50 token1 at price 2; B sells 90 → A fully fills,
    /// cmp = -1, B keeps 40. Covers the buyer-side-A mux path.
    #[test]
    fn settle_cozk_proof_verifies_buyer_maker_smaller() {
        let w = cozk_witness(50, 90, 2, false);
        cozk_prove_and_check(&w);
    }

    /// Equal amounts: cmp = 0, both remainders are commitments to zero.
    #[test]
    fn settle_cozk_proof_verifies_equal_amounts() {
        let w = cozk_witness(60, 60, 5, true);
        cozk_prove_and_check(&w);
    }

    /// Buyer collateral must be exactly order_amount * price — a buyer locking
    /// the wrong total fails witness generation on the conservation constraint.
    #[test]
    fn settle_cozk_proof_fails_when_buyer_collateral_mismatched() {
        use crate::wallet::settle_cozk_input_json;
        let mut w = cozk_witness(80, 60, 3, true);
        // B is the buyer and should lock 180; lock 179 instead.
        w.b.locked = vec![(179, r_bytes(0x0B02))];
        let input = settle_cozk_input_json(&w).expect("builder does not enforce conservation");
        let params = cached_params("settle_cozk");
        assert!(generate_proof::<Bn254>("settle_cozk", &input, params).is_err());
    }

    /// An order commitment that does not open to (amount, r) is rejected.
    #[test]
    fn settle_cozk_proof_fails_when_order_commitment_tampered() {
        use crate::wallet::settle_cozk_input_json;
        let w = cozk_witness(80, 60, 3, true);
        let mut input = settle_cozk_input_json(&w).expect("witness builds");
        input["order_a_commitment"] = serde_json::json!(hash_str(81));
        let params = cached_params("settle_cozk");
        assert!(generate_proof::<Bn254>("settle_cozk", &input, params).is_err());
    }

    // ────────────────────── Note golden vectors ──────────────────────

    /// The circom leg of the three-language golden-vector gate
    /// (`spec/golden.json`): witness generation for `note_golden.circom`
    /// succeeds iff every note derivation — keys, commitment chain, Merkle
    /// root/index, position-bound nullifier, dummy nullifier — matches the
    /// values Go and Rust pin.
    #[test]
    fn note_golden_vectors_hold_in_circom() {
        use crate::{test_circuit::TestCircuitHandle, wallet::hex_to_fr};

        let raw = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../spec/golden.json"
        ))
        .expect("spec/golden.json must exist");
        let g: serde_json::Value = serde_json::from_str(&raw).expect("golden.json must parse");

        let dec_of_hex =
            |hex: &str| fr_to_decimal_string(&hex_to_fr(hex).expect("golden hex must parse"));
        let dec_of_key = |key: &str| dec_of_hex(g[key].as_str().expect(key));
        let dec_of_rep = |b: u8| fr_to_decimal_string(&Fr::from_be_bytes_mod_order(&[b; 32]));

        let path: Vec<String> = g["path_leaf1"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| dec_of_hex(v.as_str().unwrap()))
            .collect();
        let bits: Vec<String> = g["bits_leaf1"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_i64().unwrap().to_string())
            .collect();

        let input = serde_json::json!({
            "sk1": dec_of_rep(0x42),
            "sk2": dec_of_rep(0x43),
            "asset_usdt": dec_of_key("asset_usdt"),
            "r1": dec_of_rep(0x34),
            "path": path,
            "path_bits": bits,
            "sk_dummy": dec_of_rep(0x66),
            "rho_dummy": dec_of_rep(0x77),
            "want_nk1": dec_of_key("nk1"),
            "want_npk1": dec_of_key("npk1"),
            "want_leaf1": dec_of_key("leaf1"),
            "want_root": dec_of_key("root_after_3"),
            "want_nf1": dec_of_key("nf_leaf1"),
            "want_nf_dummy": dec_of_key("nf_dummy"),
        });

        let dir = compile_circuit("note_golden").expect("note_golden must compile");
        let handle = TestCircuitHandle::from_compiled(&dir).expect("circuit handle");
        handle
            .gen_witness(&input)
            .expect("golden values must satisfy every note constraint");

        // A tampered expectation must be rejected by the constraints.
        let mut bad = input.clone();
        bad["want_nf1"] = serde_json::json!("1");
        assert!(
            handle.gen_witness(&bad).is_err(),
            "a wrong nullifier expectation must fail witness generation"
        );
    }
}
