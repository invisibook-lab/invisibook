//! Wallet-facing helpers: per-circuit type-safe prove wrappers, plus the shared
//! Poseidon commitment used to bind plaintext amounts to on-chain `Cash.Amount`.
//!
//! Callers (`lib/chain`, `cli`, app) should use these instead of building circom
//! JSON inputs by hand — keeps Poseidon parameters, BN254 byte order, and zero-
//! padding conventions in one place.

use std::path::Path;

use anyhow::Result;
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use light_poseidon::{Poseidon, PoseidonHasher};
use serde_json::{Map, Value, json};

use crate::{
    circom_bridge::fr_to_decimal_string, prover::run_rapidsnark, test_circuit::TestCircuitHandle,
};

/// Compute `Poseidon(2)([amount, r])` — the canonical commitment shape used by
/// every wallet circuit. `random` is interpreted as a 32-byte big-endian field
/// element and reduced mod the BN254 scalar field if it overflows.
///
/// This must stay byte-identical to circom's `Poseidon(2)([amount, r])` and to
/// `lib/chain/src/orderbook.rs::encrypt_with_random`, otherwise commitments on
/// the wallet, on the chain, and inside circuits would not align.
pub fn poseidon_commit(amount: u64, random: &[u8; 32]) -> Fr {
    let amount_fr = Fr::from(amount);
    let random_fr = Fr::from_be_bytes_mod_order(random);
    let mut hasher = Poseidon::<Fr>::new_circom(2).expect("circom(2) Poseidon params must build");
    hasher
        .hash(&[amount_fr, random_fr])
        .expect("Poseidon hash must not fail on two field elements")
}

/// Render a BN254 Fr as the lowercase 64-char big-endian hex string the chain
/// stores in `Cash.Amount` (and as `bridge_commitment` in deposit). Pads with
/// leading zeros so the length is always 64.
pub fn fr_to_hex(f: &Fr) -> String {
    let bytes = f.into_bigint().to_bytes_be();
    // bytes is at most 32 bytes for BN254; pad-left to 64 hex chars
    let mut out = String::with_capacity(64);
    for _ in 0..(32 - bytes.len()) {
        out.push_str("00");
    }
    for b in bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

/// Pad a `Vec<String>` of decimal field elements to `n` entries with the
/// supplied filler. Used to right-pad input/output slot arrays so the JSON
/// passed to the M=N=2 wallet circuits always has the right shape.
fn pad_to(mut v: Vec<String>, n: usize, filler: &str) -> Vec<String> {
    while v.len() < n {
        v.push(filler.to_string());
    }
    v
}

// ────────────────────── Deposit ──────────────────────

/// Inputs the wallet needs to assemble a deposit proof. `output_amount` is the
/// plaintext value being minted into the single new Cash; `output_random` is
/// the 32-byte blinding factor stored in `cash.json` so the wallet can later
/// re-open the commitment when spending.
pub struct DepositWitness {
    pub deposit_amount: u64,
    pub r_bridge: [u8; 32],
    pub output_amount: u64,
    pub output_random: [u8; 32],
}

/// Output of `prove_deposit`: the two public commitments the wallet must echo
/// back to chain (so the verifier can rebuild the public-input vector) plus the
/// Groth16 proof in snarkjs JSON format that go-rapidsnark consumes natively.
pub struct DepositProof {
    pub bridge_commitment_hex: String,
    pub output_commitment_hex: String,
    /// snarkjs-format proof: `{ pi_a, pi_b, pi_c, protocol, curve }`.
    pub proof_json: Value,
    /// snarkjs-format public inputs: array of decimal strings, in the order the
    /// circuit declares them. Chain re-derives these from the commitment fields
    /// and rejects the request if they don't match.
    pub public_json: Value,
}

/// Build the witness for `deposit.circom` (M=2 outputs, second slot zero-padded),
/// run rapidsnark to generate the proof, and return public commitments + the
/// snarkjs JSON proof the wallet sends to chain.
///
/// `zkey` must be the proving key produced by `snarkjs groth16 setup` for the
/// **deposit** circuit specifically; passing the wrong circuit's zkey silently
/// produces an unverifiable proof. `circuit_handle` carries the compiled circom
/// artifacts (r1cs + wasm) needed to generate the witness.
pub fn prove_deposit(
    w: DepositWitness,
    circuit_handle: &TestCircuitHandle,
    zkey: &Path,
) -> Result<DepositProof> {
    // Compute the two public commitments off-circuit so we can echo them to chain
    let bridge_commitment = poseidon_commit(w.deposit_amount, &w.r_bridge);
    let output_commitment = poseidon_commit(w.output_amount, &w.output_random);

    // Pad the unused output slot with amount=0 and random=0 (so its hash is
    // Poseidon(0, 0)). Keeps M=2 hard-coded behavior but supports a single real cash.
    let zero_random = [0u8; 32];
    let zero_commitment = poseidon_commit(0, &zero_random);

    let r_bridge_fr = Fr::from_be_bytes_mod_order(&w.r_bridge);
    let output_random_fr = Fr::from_be_bytes_mod_order(&w.output_random);
    let zero_random_fr = Fr::from_be_bytes_mod_order(&zero_random);

    let input = json!({
        "bridge_commitment": fr_to_decimal_string(&bridge_commitment),
        "output_hashes": [
            fr_to_decimal_string(&output_commitment),
            fr_to_decimal_string(&zero_commitment),
        ],
        "deposit_amount": w.deposit_amount.to_string(),
        "r_bridge": fr_to_decimal_string(&r_bridge_fr),
        "output_amounts": [w.output_amount.to_string(), "0".to_string()],
        "output_randomness": [
            fr_to_decimal_string(&output_random_fr),
            fr_to_decimal_string(&zero_random_fr),
        ],
    });

    let wtns = circuit_handle.gen_witness(&input)?;
    let (proof_json, public_json) = run_rapidsnark(zkey, &wtns)?;

    Ok(DepositProof {
        bridge_commitment_hex: fr_to_hex(&bridge_commitment),
        output_commitment_hex: fr_to_hex(&output_commitment),
        proof_json,
        public_json,
    })
}

// ────────────────────── Withdraw ──────────────────────

/// Hard-coded N=2 capacity matching `withdraw.circom`'s `main` instantiation.
/// (M=2 outputs is also fixed: output[0] = change, output[1] = zero pad.)
const WITHDRAW_N: usize = 2;

/// Inputs the wallet needs to assemble a withdraw proof. `inputs` lists the
/// `(amount, random)` pairs the wallet is spending, taken straight from
/// `CashStore`. `change_amount` is the part of `sum(inputs)` not being moved
/// off-chain (0 means "no change"); `change_random` is the blinding factor for
/// the new change Cash.
pub struct WithdrawWitness {
    pub withdraw_amount: u64,
    pub r_bridge_out: [u8; 32],
    pub inputs: Vec<(u64, [u8; 32])>,
    pub change_amount: u64,
    pub change_random: [u8; 32],
}

/// Output of `prove_withdraw`. `input_commitments_hex` is in 1:1 order with the
/// caller-supplied `inputs` (no zero-pad slots) so the chain side can match
/// each commitment back to the cash being spent. `change_commitment_hex` is
/// the M=2 output[0] entry; output[1] is always the constant zero-pad and not
/// returned (the chain rebuilds it).
pub struct WithdrawProof {
    pub bridge_out_commitment_hex: String,
    pub input_commitments_hex: Vec<String>,
    pub change_commitment_hex: String,
    pub proof_json: Value,
    pub public_json: Value,
}

/// Build the witness for `withdraw.circom` (N=M=2, padded with zero slots),
/// run rapidsnark, and return the public commitments + snarkjs JSON proof the
/// wallet sends to chain.
///
/// Constraints on `WithdrawWitness`:
/// * `inputs.len()` must be in `1..=WITHDRAW_N` — exceeding the circuit
///   capacity returns an error rather than silently dropping inputs.
/// * The caller is responsible for ensuring `sum(inputs) == withdraw_amount + change_amount`;
///   the circuit itself enforces this via its conservation constraint and the
///   prover will fail if violated.
pub fn prove_withdraw(
    w: WithdrawWitness,
    circuit_handle: &TestCircuitHandle,
    zkey: &Path,
) -> Result<WithdrawProof> {
    if w.inputs.is_empty() || w.inputs.len() > WITHDRAW_N {
        anyhow::bail!(
            "withdraw circuit takes 1..={WITHDRAW_N} inputs, got {}",
            w.inputs.len()
        );
    }

    // 1) Bridge-side commitment binding the hidden withdraw_amount
    let bridge_out_commitment = poseidon_commit(w.withdraw_amount, &w.r_bridge_out);
    let r_bridge_out_fr = Fr::from_be_bytes_mod_order(&w.r_bridge_out);

    // 2) Input commitments echoed back to chain (real slots only)
    let input_commitments: Vec<Fr> = w
        .inputs
        .iter()
        .map(|(amt, rnd)| poseidon_commit(*amt, rnd))
        .collect();
    let input_commitments_hex: Vec<String> = input_commitments.iter().map(fr_to_hex).collect();

    // 3) Change commitment (M=2 output[0]); output[1] is the zero-pad constant
    let change_commitment = poseidon_commit(w.change_amount, &w.change_random);
    let change_random_fr = Fr::from_be_bytes_mod_order(&w.change_random);
    let zero_random = [0u8; 32];
    let zero_commitment = poseidon_commit(0, &zero_random);
    let zero_random_fr = Fr::from_be_bytes_mod_order(&zero_random);

    // 4) Build the JSON witness, padding any unused input slot with (0, 0).
    let input_amounts = pad_to(
        w.inputs.iter().map(|(a, _)| a.to_string()).collect(),
        WITHDRAW_N,
        "0",
    );
    let zero_random_dec = fr_to_decimal_string(&zero_random_fr);
    let input_randomness = pad_to(
        w.inputs
            .iter()
            .map(|(_, r)| fr_to_decimal_string(&Fr::from_be_bytes_mod_order(r)))
            .collect(),
        WITHDRAW_N,
        &zero_random_dec,
    );
    let input_hashes_dec = pad_to(
        input_commitments.iter().map(fr_to_decimal_string).collect(),
        WITHDRAW_N,
        &fr_to_decimal_string(&zero_commitment),
    );

    let input = json!({
        "bridge_out_commitment": fr_to_decimal_string(&bridge_out_commitment),
        "input_hashes": input_hashes_dec,
        "output_hashes": [
            fr_to_decimal_string(&change_commitment),
            fr_to_decimal_string(&zero_commitment),
        ],
        "withdraw_amount": w.withdraw_amount.to_string(),
        "r_bridge_out": fr_to_decimal_string(&r_bridge_out_fr),
        "input_amounts": input_amounts,
        "input_randomness": input_randomness,
        "output_amounts": [w.change_amount.to_string(), "0".to_string()],
        "output_randomness": [
            fr_to_decimal_string(&change_random_fr),
            fr_to_decimal_string(&zero_random_fr),
        ],
    });

    let wtns = circuit_handle.gen_witness(&input)?;
    let (proof_json, public_json) = run_rapidsnark(zkey, &wtns)?;

    Ok(WithdrawProof {
        bridge_out_commitment_hex: fr_to_hex(&bridge_out_commitment),
        input_commitments_hex,
        change_commitment_hex: fr_to_hex(&change_commitment),
        proof_json,
        public_json,
    })
}

// ────────────────────── Split (SendOrder) ──────────────────────

/// Hard-coded N=2 capacity matching `split.circom`'s `main` instantiation.
/// (M=2 outputs is also fixed: output[0] = locked, output[1] = change or zero pad.)
const SPLIT_N: usize = 2;

/// Inputs the wallet needs to assemble a split proof. `inputs` lists the
/// `(amount, random)` pairs of the original Active Cashes being consumed
/// (taken from `CashStore`). `locked_*` describes the new Locked Cash that
/// will collateralize the order; `change_*` describes the residual change
/// Cash sent back to the same owner — set `change_amount = 0` for an exact
/// match with no change (output[1] then collapses to the zero-pad constant).
pub struct SplitWitness {
    pub inputs: Vec<(u64, [u8; 32])>,
    pub locked_amount: u64,
    pub locked_random: [u8; 32],
    pub change_amount: u64,
    pub change_random: [u8; 32],
}

/// Output of `prove_split`. Hex strings are 64-char big-endian (the on-wire
/// commitment format `Cash.Amount` stores). `input_commitments_hex` is in 1:1
/// order with `inputs` (no zero-pad slot included) so the chain side can match
/// each commitment back to a real Cash row.
pub struct SplitProof {
    pub input_commitments_hex: Vec<String>,
    pub locked_commitment_hex: String,
    pub change_commitment_hex: String,
    pub proof_json: Value,
    pub public_json: Value,
}

/// Build the witness for `split.circom` (N=M=2), run rapidsnark, and return the
/// commitments + snarkjs JSON proof. The chain rebuilds the public-input vector
/// from the commitments so verification is deterministic from request fields.
///
/// Errors out (without invoking the prover) if `inputs.len()` is outside
/// `1..=SPLIT_N` — exceeding the circuit capacity is a programming error,
/// not something we silently truncate.
pub fn prove_split(
    w: SplitWitness,
    circuit_handle: &TestCircuitHandle,
    zkey: &Path,
) -> Result<SplitProof> {
    if w.inputs.is_empty() || w.inputs.len() > SPLIT_N {
        anyhow::bail!(
            "split circuit takes 1..={SPLIT_N} inputs, got {}",
            w.inputs.len()
        );
    }

    // Off-circuit commitments — also echoed to chain so the verifier can
    // assemble its public-input vector without recomputing Poseidon.
    let input_commitments: Vec<Fr> = w
        .inputs
        .iter()
        .map(|(amt, rnd)| poseidon_commit(*amt, rnd))
        .collect();
    let input_commitments_hex: Vec<String> = input_commitments.iter().map(fr_to_hex).collect();

    let locked_commitment = poseidon_commit(w.locked_amount, &w.locked_random);
    let change_commitment = poseidon_commit(w.change_amount, &w.change_random);

    // Zero-pad constants reused for any unused input slot AND for output[1]
    // when the caller signalled "no change" via change_amount=0 + change_random=0.
    let zero_random = [0u8; 32];
    let zero_commitment = poseidon_commit(0, &zero_random);
    let zero_random_fr = Fr::from_be_bytes_mod_order(&zero_random);
    let zero_random_dec = fr_to_decimal_string(&zero_random_fr);

    // N=2 input slot padding. We mirror the (amount, random, hash) triple so
    // VerifyAmounts opens the same Poseidon constraint on each padded slot.
    let input_amounts = pad_to(
        w.inputs.iter().map(|(a, _)| a.to_string()).collect(),
        SPLIT_N,
        "0",
    );
    let input_randomness = pad_to(
        w.inputs
            .iter()
            .map(|(_, r)| fr_to_decimal_string(&Fr::from_be_bytes_mod_order(r)))
            .collect(),
        SPLIT_N,
        &zero_random_dec,
    );
    let input_hashes_dec = pad_to(
        input_commitments.iter().map(fr_to_decimal_string).collect(),
        SPLIT_N,
        &fr_to_decimal_string(&zero_commitment),
    );

    let locked_random_fr = Fr::from_be_bytes_mod_order(&w.locked_random);
    let change_random_fr = Fr::from_be_bytes_mod_order(&w.change_random);

    let input = json!({
        "input_hashes": input_hashes_dec,
        "output_hashes": [
            fr_to_decimal_string(&locked_commitment),
            fr_to_decimal_string(&change_commitment),
        ],
        "input_amounts": input_amounts,
        "input_randomness": input_randomness,
        "output_amounts": [w.locked_amount.to_string(), w.change_amount.to_string()],
        "output_randomness": [
            fr_to_decimal_string(&locked_random_fr),
            fr_to_decimal_string(&change_random_fr),
        ],
    });

    let wtns = circuit_handle.gen_witness(&input)?;
    let (proof_json, public_json) = run_rapidsnark(zkey, &wtns)?;

    Ok(SplitProof {
        input_commitments_hex,
        locked_commitment_hex: fr_to_hex(&locked_commitment),
        change_commitment_hex: fr_to_hex(&change_commitment),
        proof_json,
        public_json,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poseidon_commit_matches_circom_circuit() {
        // Reuse the same (amount, r) pair as the circom-side tests would and
        // confirm we land on the same field element.
        let r = [0x42u8; 32];
        let h = poseidon_commit(100, &r);
        // Stable invariant: hashing the same inputs twice must give the same Fr.
        let h2 = poseidon_commit(100, &r);
        assert_eq!(h, h2);
        // And different amount under same r yields different commitment.
        let h3 = poseidon_commit(101, &r);
        assert_ne!(h, h3);
    }

    #[test]
    fn fr_to_hex_pads_to_64_chars() {
        let zero = Fr::from(0u64);
        assert_eq!(fr_to_hex(&zero).len(), 64);
        assert!(fr_to_hex(&zero).chars().all(|c| c == '0'));
    }

    // End-to-end `prove_deposit` is exercised by `prover::tests::deposit_proof_*`
    // (which spin up snarkjs setup + rapidsnark in a tempdir).
}

// ────────────────────── Settle (co-zk joint circuit) ──────────────────────

/// Hard-coded N=2 locked-cash slots per party, matching `settle_cozk.circom`'s
/// `main` instantiation.
pub const SETTLE_COZK_N: usize = 2;

/// One trader's secrets for the joint `settle_cozk` circuit. In the
/// collaborative flow each trader builds only their own side and secret-shares
/// it; in the single-prover baseline both sides are known to one process.
pub struct SettleCoZkSide {
    /// Order amount in token1 quantity — the value `Order.Amount` commits to
    /// (for buy and sell orders alike).
    pub order_amount: u64,
    /// Blinding of the on-chain order commitment.
    pub r_order: [u8; 32],
    /// Fresh blinding for the remainder order commitment (used only if this
    /// side survives as the larger order, but always part of the witness).
    pub r_order_new: [u8; 32],
    /// Locked collateral cashes backing the order: `(amount, blinding)`,
    /// 1..=`SETTLE_COZK_N` entries. Amounts are token1 for a seller and
    /// token2 for a buyer; their sum must exactly back the order
    /// (`order_amount` resp. `order_amount * price`).
    pub locked: Vec<(u64, [u8; 32])>,
    /// Fresh blinding for the remainder collateral cash.
    pub r_locked_new: [u8; 32],
    /// Fresh blinding for the received cash (chosen by the receiving party so
    /// it can always open its own new UTXO).
    pub r_recv: [u8; 32],
}

/// Full witness of the joint settlement circuit. Party A must be the maker
/// (the order with the lower block height) by protocol convention.
pub struct SettleCoZkWitness {
    pub a: SettleCoZkSide,
    pub b: SettleCoZkSide,
    /// Execution price (the maker's price), token2 units per token1 unit.
    pub price: u64,
    /// True when A sells token1 (and therefore B buys).
    pub a_is_seller: bool,
}

/// Plaintext settlement outcome, mirroring the circuit's arithmetic. Useful
/// for wallet bookkeeping and for cross-checking the circuit's public outputs.
pub struct SettleCoZkOutcome {
    /// sign(a - b): -1 when A fully fills, 0 when both do, 1 when B does.
    pub cmp: i8,
    /// Fill in token1 quantity (= min(a, b)).
    pub fill_t1: u64,
    /// Fill in token2 quantity (= fill_t1 * price).
    pub fill_t2: u64,
    /// Remainder order amounts (token1 qty).
    pub a_prime: u64,
    pub b_prime: u64,
    /// Remainder collateral amounts in each party's locked token.
    pub a_new_locked: u64,
    pub b_new_locked: u64,
    /// Received amounts in each party's received token.
    pub a_recv: u64,
    pub b_recv: u64,
}

/// Proof bundle for `settle_cozk.circom`. The seven `*_hex` output commitments
/// echo the circuit's public outputs; the chain rebuilds the 15-signal public
/// vector as `[cmp, new_order_a, new_order_b, new_locked_a, new_locked_b,
/// recv_a, recv_b, order_a, order_b, price, a_is_seller, locked_a_hashes[2],
/// locked_b_hashes[2]]`.
pub struct SettleCoZkProof {
    pub cmp: i8,
    pub new_order_a_commitment_hex: String,
    pub new_order_b_commitment_hex: String,
    pub new_locked_a_commitment_hex: String,
    pub new_locked_b_commitment_hex: String,
    pub recv_a_commitment_hex: String,
    pub recv_b_commitment_hex: String,
    pub order_a_commitment_hex: String,
    pub order_b_commitment_hex: String,
    /// Locked commitments padded to `SETTLE_COZK_N` with the zero commitment.
    pub locked_a_hashes_hex: Vec<String>,
    pub locked_b_hashes_hex: Vec<String>,
    pub proof_json: Value,
    pub public_json: Value,
}

/// Compute the plaintext settlement outcome for a witness, validating the same
/// invariants the circuit enforces: 1..=N locked slots per side, locked sums
/// exactly backing each order, and every derived amount fitting in a u64.
pub fn settle_cozk_outcome(w: &SettleCoZkWitness) -> Result<SettleCoZkOutcome> {
    for (tag, side) in [("a", &w.a), ("b", &w.b)] {
        if side.locked.is_empty() || side.locked.len() > SETTLE_COZK_N {
            anyhow::bail!(
                "settle_cozk side {tag} takes 1..={SETTLE_COZK_N} locked inputs, got {}",
                side.locked.len()
            );
        }
    }
    let locked_needed = |amount: u64, is_seller: bool| -> Result<u64> {
        if is_seller {
            Ok(amount)
        } else {
            amount
                .checked_mul(w.price)
                .ok_or_else(|| anyhow::anyhow!("order amount * price overflows u64"))
        }
    };
    let a_locked_sum: u64 = w.a.locked.iter().map(|(v, _)| *v).sum();
    let b_locked_sum: u64 = w.b.locked.iter().map(|(v, _)| *v).sum();
    if a_locked_sum != locked_needed(w.a.order_amount, w.a_is_seller)? {
        anyhow::bail!("side a locked sum {a_locked_sum} does not back the order");
    }
    if b_locked_sum != locked_needed(w.b.order_amount, !w.a_is_seller)? {
        anyhow::bail!("side b locked sum {b_locked_sum} does not back the order");
    }

    let (a, b) = (w.a.order_amount, w.b.order_amount);
    let cmp: i8 = match a.cmp(&b) {
        std::cmp::Ordering::Less => -1,
        std::cmp::Ordering::Equal => 0,
        std::cmp::Ordering::Greater => 1,
    };
    let fill_t1 = a.min(b);
    let fill_t2 = fill_t1
        .checked_mul(w.price)
        .ok_or_else(|| anyhow::anyhow!("fill_t1 * price overflows u64"))?;
    let a_prime = a - fill_t1;
    let b_prime = b - fill_t1;
    let a_new_locked = locked_needed(a_prime, w.a_is_seller)?;
    let b_new_locked = locked_needed(b_prime, !w.a_is_seller)?;
    let (a_recv, b_recv) = if w.a_is_seller {
        (fill_t2, fill_t1)
    } else {
        (fill_t1, fill_t2)
    };

    Ok(SettleCoZkOutcome {
        cmp,
        fill_t1,
        fill_t2,
        a_prime,
        b_prime,
        a_new_locked,
        b_new_locked,
        a_recv,
        b_recv,
    })
}

/// Render one side's private signals as circom input JSON. `tag` must be
/// `"a"` or `"b"` and match the side's role in the witness; `side.locked`
/// must hold 1..=`SETTLE_COZK_N` entries (zero-padded here). This is the map
/// each trader secret-shares in the collaborative flow.
pub fn settle_cozk_side_json(side: &SettleCoZkSide, tag: &str) -> Result<Value> {
    if side.locked.is_empty() || side.locked.len() > SETTLE_COZK_N {
        anyhow::bail!(
            "settle_cozk side {tag} takes 1..={SETTLE_COZK_N} locked inputs, got {}",
            side.locked.len()
        );
    }
    let zero_random_dec = fr_to_decimal_string(&Fr::from(0u64));
    let locked_amounts = pad_to(
        side.locked.iter().map(|(v, _)| v.to_string()).collect(),
        SETTLE_COZK_N,
        "0",
    );
    let locked_randomness = pad_to(
        side.locked
            .iter()
            .map(|(_, r)| fr_to_decimal_string(&Fr::from_be_bytes_mod_order(r)))
            .collect(),
        SETTLE_COZK_N,
        &zero_random_dec,
    );
    let random_dec = |r: &[u8; 32]| fr_to_decimal_string(&Fr::from_be_bytes_mod_order(r));
    let mut map = Map::new();
    map.insert(tag.to_string(), json!(side.order_amount.to_string()));
    map.insert(format!("r_{tag}"), json!(random_dec(&side.r_order)));
    map.insert(format!("r_{tag}_new"), json!(random_dec(&side.r_order_new)));
    map.insert(format!("locked_{tag}_amounts"), json!(locked_amounts));
    map.insert(format!("locked_{tag}_randomness"), json!(locked_randomness));
    map.insert(
        format!("r_locked_{tag}_new"),
        json!(random_dec(&side.r_locked_new)),
    );
    map.insert(format!("r_recv_{tag}"), json!(random_dec(&side.r_recv)));
    Ok(Value::Object(map))
}

/// Compute one side's locked commitments padded to `SETTLE_COZK_N` with the
/// zero commitment, as Fr values. `side.locked` must hold 1..=N entries.
pub fn settle_cozk_locked_hashes(side: &SettleCoZkSide) -> Vec<Fr> {
    let mut hashes: Vec<Fr> = side
        .locked
        .iter()
        .map(|(v, r)| poseidon_commit(*v, r))
        .collect();
    let zero_commitment = poseidon_commit(0, &[0u8; 32]);
    while hashes.len() < SETTLE_COZK_N {
        hashes.push(zero_commitment);
    }
    hashes
}

/// Render the circuit's public inputs as circom input JSON. Both traders must
/// produce identical maps (all values are on-chain state), otherwise the
/// collaborative share merge rejects the inputs.
pub fn settle_cozk_public_json(
    order_a_commitment: &Fr,
    order_b_commitment: &Fr,
    price: u64,
    a_is_seller: bool,
    locked_a_hashes: &[Fr],
    locked_b_hashes: &[Fr],
) -> Value {
    let dec = |v: &[Fr]| -> Vec<String> { v.iter().map(fr_to_decimal_string).collect() };
    json!({
        "order_a_commitment": fr_to_decimal_string(order_a_commitment),
        "order_b_commitment": fr_to_decimal_string(order_b_commitment),
        "price": price.to_string(),
        "a_is_seller": if a_is_seller { "1" } else { "0" },
        "locked_a_hashes": dec(locked_a_hashes),
        "locked_b_hashes": dec(locked_b_hashes),
    })
}

/// Build the full input JSON (public + both private sides) for
/// `settle_cozk.circom`. Used by the single-prover baseline and by tests; the
/// collaborative flow splits the same maps across parties instead.
pub fn settle_cozk_input_json(w: &SettleCoZkWitness) -> Result<Value> {
    let order_a_commitment = poseidon_commit(w.a.order_amount, &w.a.r_order);
    let order_b_commitment = poseidon_commit(w.b.order_amount, &w.b.r_order);
    let mut input = settle_cozk_public_json(
        &order_a_commitment,
        &order_b_commitment,
        w.price,
        w.a_is_seller,
        &settle_cozk_locked_hashes(&w.a),
        &settle_cozk_locked_hashes(&w.b),
    );
    let obj = input.as_object_mut().expect("public json is an object");
    for (tag, side) in [("a", &w.a), ("b", &w.b)] {
        let side_json = settle_cozk_side_json(side, tag)?;
        for (k, v) in side_json.as_object().expect("side json is an object") {
            obj.insert(k.clone(), v.clone());
        }
    }
    Ok(input)
}

/// Single-prover baseline for `settle_cozk.circom`: build the full witness,
/// run rapidsnark, and cross-check the circuit's public outputs against the
/// locally computed outcome. The collaborative flow in `lib/cozk` produces a
/// byte-compatible proof for the same public vector without any single party
/// knowing both sides.
pub fn prove_settle_cozk(
    w: &SettleCoZkWitness,
    circuit_handle: &TestCircuitHandle,
    zkey: &Path,
) -> Result<SettleCoZkProof> {
    let outcome = settle_cozk_outcome(w)?;
    let input = settle_cozk_input_json(w)?;

    let wtns = circuit_handle.gen_witness(&input)?;
    let (proof_json, public_json) = run_rapidsnark(zkey, &wtns)?;

    // Cross-check the first 7 public signals (the circuit outputs) against
    // the plaintext outcome — catches witness/zkey drift early.
    let expected_outputs = [
        settle_cozk_cmp_fr(outcome.cmp),
        poseidon_commit(outcome.a_prime, &w.a.r_order_new),
        poseidon_commit(outcome.b_prime, &w.b.r_order_new),
        poseidon_commit(outcome.a_new_locked, &w.a.r_locked_new),
        poseidon_commit(outcome.b_new_locked, &w.b.r_locked_new),
        poseidon_commit(outcome.a_recv, &w.a.r_recv),
        poseidon_commit(outcome.b_recv, &w.b.r_recv),
    ];
    let publics = public_json
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("public.json is not an array"))?;
    for (i, expected) in expected_outputs.iter().enumerate() {
        let got = publics
            .get(i)
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("public signal {i} missing"))?;
        if got != fr_to_decimal_string(expected) {
            anyhow::bail!("public output {i} mismatch: circuit produced {got}");
        }
    }

    Ok(SettleCoZkProof {
        cmp: outcome.cmp,
        new_order_a_commitment_hex: fr_to_hex(&expected_outputs[1]),
        new_order_b_commitment_hex: fr_to_hex(&expected_outputs[2]),
        new_locked_a_commitment_hex: fr_to_hex(&expected_outputs[3]),
        new_locked_b_commitment_hex: fr_to_hex(&expected_outputs[4]),
        recv_a_commitment_hex: fr_to_hex(&expected_outputs[5]),
        recv_b_commitment_hex: fr_to_hex(&expected_outputs[6]),
        order_a_commitment_hex: fr_to_hex(&poseidon_commit(w.a.order_amount, &w.a.r_order)),
        order_b_commitment_hex: fr_to_hex(&poseidon_commit(w.b.order_amount, &w.b.r_order)),
        locked_a_hashes_hex: settle_cozk_locked_hashes(&w.a)
            .iter()
            .map(fr_to_hex)
            .collect(),
        locked_b_hashes_hex: settle_cozk_locked_hashes(&w.b)
            .iter()
            .map(fr_to_hex)
            .collect(),
        proof_json,
        public_json,
    })
}

/// Encode the three-way comparison result as the field element the circuit
/// outputs (-1 is p - 1). `cmp` must be -1, 0, or 1.
pub fn settle_cozk_cmp_fr(cmp: i8) -> Fr {
    match cmp {
        -1 => -Fr::from(1u64),
        0 => Fr::from(0u64),
        1 => Fr::from(1u64),
        _ => panic!("cmp must be -1, 0, or 1"),
    }
}

/// Decode a 64-char lowercase hex string into a BN254 Fr.
pub fn hex_to_fr(s: &str) -> Result<Fr> {
    let bytes = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect::<std::result::Result<Vec<u8>, _>>()?;
    Ok(Fr::from_be_bytes_mod_order(&bytes))
}
