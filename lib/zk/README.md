# ZK — Zero-Knowledge Proof Library

Groth16 proof generation and verification for Invisibook wallet circuits, using circom-compiled R1CS + [rapidsnark](https://github.com/iden3/rapidsnark) as the native prover.

## Architecture

```
circom templates  →  compile (circom CLI)  →  R1CS + WASM witness generator
                                                      ↓
wallet witness  →  gen_witness (node.js)  →  .wtns file
                                                      ↓
                  rapidsnark (zkey + wtns)  →  proof.json + public.json
                                                      ↓
              arkworks verify (VerifyingKey + proof)  →  bool
```

## Circuits

| Circuit | Purpose | Public Inputs |
|---------|---------|---------------|
| `deposit` | Prove bridged amount splits correctly into output cashes | `bridge_commitment`, `output_hashes[M]` |
| `withdraw` | Prove input cashes cover the withdrawal + change | `bridge_out_commitment`, `input_hashes[N]`, `output_hashes[M]` |
| `split` | Prove input cashes split into locked + change (SendOrder) | `input_hashes[N]`, `output_hashes[M]` |
| `settle_larger` | Larger side of settlement (has change) | `my_match`, `other_match`, `price`, `is_token2_sender`, `input_hashes[N]`, `change`, `recv` |
| `settle_smaller` | Smaller side of settlement (no change, fill == inputs) | `match_commitment`, `input_hashes[N]`, `recv` |

All circuits use N=2 inputs and M=2 outputs (unused slots zero-padded with `Poseidon(0, 0)`).

## Usage

### Wallet-facing API (rapidsnark prover)

```rust
use zk::wallet::{
    DepositWitness, prove_deposit,
    WithdrawWitness, prove_withdraw,
    SplitWitness, prove_split,
    SettleLargerWitness, prove_settle_larger,
    SettleSmallerWitness, prove_settle_smaller,
    poseidon_commit, fr_to_hex,
};
use zk::setup::dev_setup_snarkjs;
use zk::test_circuit::TestCircuitHandle;

// One-time setup (production: load from ceremony output)
let setup = dev_setup_snarkjs("deposit").unwrap();
let handle = TestCircuitHandle::from_compiled(&setup.circuit_dir).unwrap();

// Build witness and prove
let witness = DepositWitness {
    deposit_amount: 150,
    r_bridge: [0x11u8; 32],       // 32-byte blinding factor
    output_amount: 150,
    output_random: [0x22u8; 32],
};
let proof = prove_deposit(witness, &handle, &setup.zkey).unwrap();

// Results to send to chain
println!("bridge_commitment: {}", proof.bridge_commitment_hex);
println!("output_commitment: {}", proof.output_commitment_hex);
println!("proof: {}", proof.proof_json);
println!("public: {}", proof.public_json);
```

### Poseidon commitment (shared with chain)

```rust
use zk::wallet::{poseidon_commit, fr_to_hex};

// Poseidon(2)([amount, random]) — canonical commitment shape
let commitment = poseidon_commit(100, &[0x42u8; 32]);
let hex = fr_to_hex(&commitment);  // 64-char lowercase BE hex
```

### Arkworks-level API (dev/test setup + prove + verify)

```rust
use ark_bn254::Bn254;
use zk::{dev_setup, generate_proof, verify_proof, CircuitParams};

// Dev setup (insecure — single-party toxic waste)
let params: CircuitParams<Bn254> = dev_setup("deposit").unwrap();

// Generate proof with JSON circuit inputs
let input = serde_json::json!({ /* circuit signals */ });
let proof = generate_proof::<Bn254>("deposit", &input, &params).unwrap();

// Verify
assert!(verify_proof(&proof, &params.vk).unwrap());
```

### Production setup (load from ceremony)

```rust
use zk::{load_params, CircuitParams};
use ark_bn254::Bn254;

let params: CircuitParams<Bn254> = load_params(Path::new("deposit.params")).unwrap();
```

## Modules

| Module | Description |
|--------|-------------|
| `wallet` | Type-safe prove wrappers per circuit (`prove_deposit`, `prove_withdraw`, etc.) + `poseidon_commit` |
| `prover` | Subprocess wrapper around rapidsnark binary |
| `setup` | snarkjs trusted-setup orchestration (`dev_setup_snarkjs`) |
| `circom_bridge` | R1CS + witness file parsing into arkworks types |
| `test_circuit` | Compiled circuit handle (witness generation via node.js) |
| `lib.rs` | Arkworks-level `dev_setup`, `generate_proof`, `verify_proof`, `load_params`, `save_params` |

## Dependencies

- **circom** — circuit compiler (must be in `$PATH`)
- **snarkjs** — trusted setup ceremony tool (`npm install -g snarkjs`)
- **rapidsnark** — native Groth16 prover binary (must be in `$PATH`)
- **Node.js** — witness generation (circom compiles to WASM, executed via node)

## Circom Templates

Located in `templates/`:
- `deposit.circom` — deposit conservation + Poseidon binding
- `withdraw.circom` — withdrawal conservation + bridge-out binding
- `split.circom` — input/output conservation (SendOrder)
- `settle_larger.circom` — larger-side settlement with change + cross-leg ratio check
- `settle_smaller.circom` — smaller-side settlement (fill == inputs.sum)
- `utils/` — shared components (poseidon, bitify, comparators)
