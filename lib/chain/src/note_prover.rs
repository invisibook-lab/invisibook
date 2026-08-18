//! Witness builders + rapidsnark drivers for the shielded-pool circuits
//! (`note_deposit.circom`, `spend_withdraw.circom`).
//!
//! These live here rather than in `zk::wallet` because they are built on the
//! note derivations of [`crate::note`], and `zk` must not depend back on
//! this crate. The prover utilities (`TestCircuitHandle`, `run_rapidsnark`)
//! come from `zk`.

use anyhow::{Result, ensure};
use ark_bn254::Fr;
use rand::RngCore;
use serde_json::{Value, json};
use std::path::Path;

use zk::{
    circom_bridge::fr_to_decimal_string,
    prover::run_rapidsnark,
    test_circuit::TestCircuitHandle,
    wallet::{needed_collateral, poseidon2},
};

use crate::note::{
    TREE_DEPTH, fr_from_be_bytes, nk_from_sk, note_commit, note_fr_to_hex, nullifier, rho,
};

/// One input slot of a spend circuit: a real note (with its Merkle path) or
/// an Orchard-style dummy (fresh random secrets, zero value, membership
/// disabled). Build dummies with [`SpendSlot::dummy`].
#[derive(Debug, Clone)]
pub struct SpendSlot {
    pub enabled: bool,
    /// Wallet spending secret (real) or fresh random (dummy).
    pub sk: Fr,
    pub v: u64,
    pub r: Fr,
    /// Fresh random rho (dummy); ignored for real slots.
    pub rho_rand: Fr,
    pub path: [Fr; TREE_DEPTH],
    pub bits: [bool; TREE_DEPTH],
}

impl SpendSlot {
    /// A real spend of a note at `path`/`bits` (from `NoteTree::path`).
    pub fn real(sk: Fr, v: u64, r: Fr, path: [Fr; TREE_DEPTH], bits: [bool; TREE_DEPTH]) -> Self {
        SpendSlot {
            enabled: true,
            sk,
            v,
            r,
            rho_rand: Fr::from(0u64),
            path,
            bits,
        }
    }

    /// A dummy slot: fresh random `sk` and `rho_rand`, zero value, zero
    /// path. Its nullifier is a PRF image of unknown fresh secrets —
    /// unsteerable and collision-negligible.
    pub fn dummy() -> Self {
        let mut rng = rand::rng();
        let mut sk_bytes = [0u8; 32];
        let mut rho_bytes = [0u8; 32];
        rng.fill_bytes(&mut sk_bytes);
        rng.fill_bytes(&mut rho_bytes);
        SpendSlot {
            enabled: false,
            sk: fr_from_be_bytes(&sk_bytes),
            v: 0,
            r: Fr::from(0u64),
            rho_rand: fr_from_be_bytes(&rho_bytes),
            path: [Fr::from(0u64); TREE_DEPTH],
            bits: [false; TREE_DEPTH],
        }
    }

    /// The leaf index this slot's path bits encode.
    fn leaf_index(&self) -> u64 {
        self.bits
            .iter()
            .enumerate()
            .fold(0u64, |acc, (i, b)| acc | ((*b as u64) << i))
    }

    /// The nullifier this slot will publish (what the circuit outputs).
    pub fn nullifier(&self, asset: Fr) -> Fr {
        let nk = nk_from_sk(self.sk);
        if self.enabled {
            let npk = poseidon2(Fr::from(crate::note::TAG_NPK), self.sk);
            let cm = note_commit(npk, asset, self.v, self.r);
            nullifier(nk, rho(cm, self.leaf_index()))
        } else {
            nullifier(nk, self.rho_rand)
        }
    }

    fn to_json_parts(&self) -> (String, String, String, String, String) {
        (
            if self.enabled { "1" } else { "0" }.to_string(),
            fr_to_decimal_string(&self.sk),
            self.v.to_string(),
            fr_to_decimal_string(&self.r),
            fr_to_decimal_string(&self.rho_rand),
        )
    }
}

/// Witness for `note_deposit.circom`: mint one note from a bridged value.
pub struct NoteDepositWitness {
    pub v: u64,
    pub r_bridge: Fr,
    pub npk: Fr,
    pub r_note: Fr,
    pub asset: Fr,
    pub bind: Fr,
}

/// Output of [`prove_note_deposit`]: the public hexes the chain rebuilds
/// its public-input vector from, plus the snarkjs-format proof.
pub struct NoteDepositProof {
    pub bridge_commitment_hex: String,
    pub cm_out_hex: String,
    pub proof_json: Value,
    pub public_json: Value,
}

/// Build the `note_deposit` witness, run rapidsnark, and return the proof.
/// `zkey` must belong to the note_deposit circuit.
pub fn prove_note_deposit(
    w: NoteDepositWitness,
    circuit_handle: &TestCircuitHandle,
    zkey: &Path,
) -> Result<NoteDepositProof> {
    let bridge_commitment = poseidon2(Fr::from(w.v), w.r_bridge);
    let cm_out = note_commit(w.npk, w.asset, w.v, w.r_note);

    let input = json!({
        "bridge_commitment": fr_to_decimal_string(&bridge_commitment),
        "asset_id": fr_to_decimal_string(&w.asset),
        "cm_out": fr_to_decimal_string(&cm_out),
        "bind": fr_to_decimal_string(&w.bind),
        "v": w.v.to_string(),
        "r_bridge": fr_to_decimal_string(&w.r_bridge),
        "npk": fr_to_decimal_string(&w.npk),
        "r_note": fr_to_decimal_string(&w.r_note),
    });

    let wtns = circuit_handle.gen_witness(&input)?;
    let (proof_json, public_json) = run_rapidsnark(zkey, &wtns)?;

    Ok(NoteDepositProof {
        bridge_commitment_hex: note_fr_to_hex(&bridge_commitment),
        cm_out_hex: note_fr_to_hex(&cm_out),
        proof_json,
        public_json,
    })
}

/// Witness for `spend_withdraw.circom`: spend two slots (dummies allowed),
/// withdraw `v_out` through the bridge, mint the change note.
pub struct SpendWithdrawWitness {
    pub slots: [SpendSlot; 2],
    pub anchor: Fr,
    pub asset: Fr,
    pub v_out: u64,
    pub r_bridge_out: Fr,
    pub npk_change: Fr,
    pub v_change: u64,
    pub r_change: Fr,
    pub bind: Fr,
}

/// Output of [`prove_spend_withdraw`].
pub struct SpendWithdrawProof {
    pub nf_hex: [String; 2],
    pub bridge_out_commitment_hex: String,
    pub cm_change_hex: String,
    pub proof_json: Value,
    pub public_json: Value,
}

/// Build the `spend_withdraw` witness, run rapidsnark, and return the
/// proof. Enforces conservation locally before proving so a wallet bug
/// fails fast instead of producing an unsatisfiable witness.
pub fn prove_spend_withdraw(
    w: SpendWithdrawWitness,
    circuit_handle: &TestCircuitHandle,
    zkey: &Path,
) -> Result<SpendWithdrawProof> {
    let v_in: u64 = w.slots.iter().map(|s| s.v).sum();
    ensure!(
        v_in == w.v_out + w.v_change,
        "conservation violated: inputs {} != out {} + change {}",
        v_in,
        w.v_out,
        w.v_change
    );

    let nf = [w.slots[0].nullifier(w.asset), w.slots[1].nullifier(w.asset)];
    let bridge_out = poseidon2(Fr::from(w.v_out), w.r_bridge_out);
    let cm_change = note_commit(w.npk_change, w.asset, w.v_change, w.r_change);

    let dec = fr_to_decimal_string;
    let slot_parts: Vec<_> = w.slots.iter().map(|s| s.to_json_parts()).collect();
    let paths: Vec<Vec<String>> = w
        .slots
        .iter()
        .map(|s| s.path.iter().map(dec).collect())
        .collect();
    let bits: Vec<Vec<String>> = w
        .slots
        .iter()
        .map(|s| s.bits.iter().map(|b| (*b as u8).to_string()).collect())
        .collect();

    let input = json!({
        "anchor": dec(&w.anchor),
        "nf_0": dec(&nf[0]),
        "nf_1": dec(&nf[1]),
        "asset_id": dec(&w.asset),
        "bridge_out_commitment": dec(&bridge_out),
        "cm_change": dec(&cm_change),
        "bind": dec(&w.bind),
        "enabled": [slot_parts[0].0, slot_parts[1].0],
        "sk": [slot_parts[0].1, slot_parts[1].1],
        "v": [slot_parts[0].2, slot_parts[1].2],
        "r": [slot_parts[0].3, slot_parts[1].3],
        "rho_rand": [slot_parts[0].4, slot_parts[1].4],
        "path": paths,
        "path_bits": bits,
        "v_out": w.v_out.to_string(),
        "r_bridge_out": dec(&w.r_bridge_out),
        "npk_change": dec(&w.npk_change),
        "v_change": w.v_change.to_string(),
        "r_change": dec(&w.r_change),
    });

    let wtns = circuit_handle.gen_witness(&input)?;
    let (proof_json, public_json) = run_rapidsnark(zkey, &wtns)?;

    Ok(SpendWithdrawProof {
        nf_hex: [note_fr_to_hex(&nf[0]), note_fr_to_hex(&nf[1])],
        bridge_out_commitment_hex: note_fr_to_hex(&bridge_out),
        cm_change_hex: note_fr_to_hex(&cm_change),
        proof_json,
        public_json,
    })
}

// ────────────────────── SendOrder (admission collateral) ──────────────────────

/// Witness for `send_order.circom`: spend separate two-slot banks for the
/// collateral asset and the native fee asset. When both are `invis`, either
/// bank may fund the combined lock + fee equation.
pub struct SendOrderWitness {
    pub collateral_slots: [SpendSlot; 2],
    pub fee_slots: [SpendSlot; 2],
    pub anchor: Fr,
    pub lock_asset: Fr,
    pub native_asset: Fr,
    pub q: u64,
    pub r_locked: Fr,
    pub price: u64,
    pub side_sell: bool,
    pub fee: u64,
    pub npk_collateral_change: Fr,
    pub v_collateral_change: u64,
    pub r_collateral_change: Fr,
    pub npk_fee_change: Fr,
    pub v_fee_change: u64,
    pub r_fee_change: Fr,
    pub bind: Fr,
}

impl SendOrderWitness {
    /// The collateral this order locks (= q·price buy / q sell).
    pub fn locked_value(&self) -> u64 {
        required_collateral(self.q, self.price, self.side_sell)
    }

    /// Public outputs the caller needs BEFORE proving (they enter bind):
    /// (locked_commitment, collateral change, native-fee change).
    pub fn output_commitments(&self) -> (Fr, Fr, Fr) {
        (
            locked_commitment(self.q, self.price, self.side_sell, self.r_locked),
            note_commit(
                self.npk_collateral_change,
                self.lock_asset,
                self.v_collateral_change,
                self.r_collateral_change,
            ),
            note_commit(
                self.npk_fee_change,
                self.native_asset,
                self.v_fee_change,
                self.r_fee_change,
            ),
        )
    }
}

/// Output of [`prove_send_order`].
pub struct SendOrderProof {
    pub collateral_nf_hex: [String; 2],
    pub fee_nf_hex: [String; 2],
    pub locked_commitment_hex: String,
    pub cm_collateral_change_hex: String,
    pub cm_fee_change_hex: String,
    pub proof_json: Value,
    pub public_json: Value,
}

/// Build the `send_order` witness and prove. Publics order:
/// [anchor, coll_nf_0, coll_nf_1, fee_nf_0, fee_nf_1, lock_asset_id,
/// native_asset_id, locked_commitment, fee, cm_coll_change, cm_fee_change,
/// collateral_price, side, bind].
pub fn prove_send_order(
    w: SendOrderWitness,
    circuit_handle: &TestCircuitHandle,
    zkey: &Path,
) -> Result<SendOrderProof> {
    let collateral_in: u128 = w.collateral_slots.iter().map(|s| u128::from(s.v)).sum();
    let fee_in: u128 = w.fee_slots.iter().map(|s| u128::from(s.v)).sum();
    let locked_value = checked_required_collateral(w.q, w.price, w.side_sell)
        .ok_or_else(|| anyhow::anyhow!("required collateral exceeds 64 bits"))?;
    if w.lock_asset == w.native_asset {
        ensure!(
            collateral_in + fee_in
                == u128::from(locked_value)
                    + u128::from(w.fee)
                    + u128::from(w.v_collateral_change)
                    + u128::from(w.v_fee_change),
            "combined native-asset conservation violated"
        );
    } else {
        ensure!(
            collateral_in == u128::from(locked_value) + u128::from(w.v_collateral_change),
            "collateral-asset conservation violated"
        );
        ensure!(
            fee_in == u128::from(w.fee) + u128::from(w.v_fee_change),
            "native-fee conservation violated"
        );
    }

    let collateral_nf = [
        w.collateral_slots[0].nullifier(w.lock_asset),
        w.collateral_slots[1].nullifier(w.lock_asset),
    ];
    let fee_nf = [
        w.fee_slots[0].nullifier(w.native_asset),
        w.fee_slots[1].nullifier(w.native_asset),
    ];
    let (locked_commitment, cm_collateral_change, cm_fee_change) = w.output_commitments();

    let dec = fr_to_decimal_string;
    let json_parts = |slots: &[SpendSlot; 2]| {
        let parts: Vec<_> = slots.iter().map(|s| s.to_json_parts()).collect();
        let paths: Vec<Vec<String>> = slots
            .iter()
            .map(|s| s.path.iter().map(dec).collect())
            .collect();
        let bits: Vec<Vec<String>> = slots
            .iter()
            .map(|s| s.bits.iter().map(|b| (*b as u8).to_string()).collect())
            .collect();
        (parts, paths, bits)
    };
    let (coll_parts, coll_paths, coll_bits) = json_parts(&w.collateral_slots);
    let (fee_parts, fee_paths, fee_bits) = json_parts(&w.fee_slots);

    let input = json!({
        "anchor": dec(&w.anchor),
        "coll_nf_0": dec(&collateral_nf[0]),
        "coll_nf_1": dec(&collateral_nf[1]),
        "fee_nf_0": dec(&fee_nf[0]),
        "fee_nf_1": dec(&fee_nf[1]),
        "lock_asset_id": dec(&w.lock_asset),
        "native_asset_id": dec(&w.native_asset),
        "locked_commitment": dec(&locked_commitment),
        "fee": w.fee.to_string(),
        "cm_coll_change": dec(&cm_collateral_change),
        "cm_fee_change": dec(&cm_fee_change),
        "collateral_price": w.price.to_string(),
        "side": if w.side_sell { "1" } else { "0" },
        "bind": dec(&w.bind),
        "coll_enabled": [coll_parts[0].0, coll_parts[1].0],
        "coll_sk": [coll_parts[0].1, coll_parts[1].1],
        "coll_v": [coll_parts[0].2, coll_parts[1].2],
        "coll_r": [coll_parts[0].3, coll_parts[1].3],
        "coll_rho_rand": [coll_parts[0].4, coll_parts[1].4],
        "coll_path": coll_paths,
        "coll_path_bits": coll_bits,
        "fee_enabled": [fee_parts[0].0, fee_parts[1].0],
        "fee_sk": [fee_parts[0].1, fee_parts[1].1],
        "fee_v": [fee_parts[0].2, fee_parts[1].2],
        "fee_r": [fee_parts[0].3, fee_parts[1].3],
        "fee_rho_rand": [fee_parts[0].4, fee_parts[1].4],
        "fee_path": fee_paths,
        "fee_path_bits": fee_bits,
        "q": w.q.to_string(),
        "r_locked": dec(&w.r_locked),
        "npk_coll_change": dec(&w.npk_collateral_change),
        "v_coll_change": w.v_collateral_change.to_string(),
        "r_coll_change": dec(&w.r_collateral_change),
        "npk_fee_change": dec(&w.npk_fee_change),
        "v_fee_change": w.v_fee_change.to_string(),
        "r_fee_change": dec(&w.r_fee_change),
    });
    let wtns = circuit_handle.gen_witness(&input)?;
    let (proof_json, public_json) = run_rapidsnark(zkey, &wtns)?;
    Ok(SendOrderProof {
        collateral_nf_hex: [
            note_fr_to_hex(&collateral_nf[0]),
            note_fr_to_hex(&collateral_nf[1]),
        ],
        fee_nf_hex: [note_fr_to_hex(&fee_nf[0]), note_fr_to_hex(&fee_nf[1])],
        locked_commitment_hex: note_fr_to_hex(&locked_commitment),
        cm_collateral_change_hex: note_fr_to_hex(&cm_collateral_change),
        cm_fee_change_hex: note_fr_to_hex(&cm_fee_change),
        proof_json,
        public_json,
    })
}

/// Witness for `claim_fees.circom`: the producer mints a note for its
/// accrued fee `amount` under its own key.
pub struct ClaimFeesWitness {
    pub asset: Fr,
    pub amount: u64,
    pub npk: Fr,
    pub r_note: Fr,
    pub bind: Fr,
}

impl ClaimFeesWitness {
    pub fn cm_out(&self) -> Fr {
        note_commit(self.npk, self.asset, self.amount, self.r_note)
    }
}

/// Output of [`prove_claim_fees`].
pub struct ClaimFeesProof {
    pub cm_out_hex: String,
    pub proof_json: Value,
    pub public_json: Value,
}

/// Build the `claim_fees` witness and prove. Publics: [asset_id, amount,
/// cm_out, bind].
pub fn prove_claim_fees(
    w: ClaimFeesWitness,
    circuit_handle: &TestCircuitHandle,
    zkey: &Path,
) -> Result<ClaimFeesProof> {
    let dec = fr_to_decimal_string;
    let cm_out = w.cm_out();
    let input = json!({
        "asset_id": dec(&w.asset),
        "amount": w.amount.to_string(),
        "cm_out": dec(&cm_out),
        "bind": dec(&w.bind),
        "npk": dec(&w.npk),
        "r_note": dec(&w.r_note),
    });
    let wtns = circuit_handle.gen_witness(&input)?;
    let (proof_json, public_json) = run_rapidsnark(zkey, &wtns)?;
    Ok(ClaimFeesProof {
        cm_out_hex: note_fr_to_hex(&cm_out),
        proof_json,
        public_json,
    })
}

// ────────────────────── Settlement (paper's π_A / π_B) ──────────────────────

/// The collateral a side must have locked: q·price for a buyer, q for a
/// seller. Thin delegate to [`needed_collateral`], the ONE definition of the
/// settle circuits' collateral equation (it lives in `zk`, which owns the
/// circuit conventions); kept under this name for the chain-side callers.
pub fn required_collateral(q: u64, price: u64, side_sell: bool) -> u64 {
    needed_collateral(q, price, side_sell)
}

/// Checked admission-time collateral arithmetic for untrusted UI/API input.
/// The circuits range-constrain the result to 64 bits; callers must reject
/// an overflowing buy instead of letting Rust wrap or panic before proving.
pub fn checked_required_collateral(q: u64, price: u64, side_sell: bool) -> Option<u64> {
    if side_sell {
        Some(q)
    } else {
        q.checked_mul(price)
    }
}

/// The order's collateral commitment `P2(needed(q, side), r)` — the single
/// commitment an order carries in the locked-only model. Shared by every
/// settle witness (my own locked value, the counterparty's, the residual).
pub fn locked_commitment(q: u64, price: u64, side_sell: bool, r: Fr) -> Fr {
    poseidon2(Fr::from(required_collateral(q, price, side_sell)), r)
}

/// Witness for `settle_small.circom` (the fully filled side): the whole
/// locked collateral transfers to the counterparty as one pool note.
/// Locked-only model: the order carries one collateral commitment
/// `P2(needed(q, side), r_locked)`; `q` is a pure witness.
/// `npk_ctr`/`r_note` arrive from the counterparty over the settlement
/// channel — the RECEIVER picked them, so it already persisted the opening.
pub struct SettleSmallWitness {
    pub q: u64,
    pub r_locked: Fr,
    pub collateral_price: u64,
    pub execution_price: u64,
    pub side_sell: bool,
    pub pay_asset: Fr,
    pub npk_ctr: Fr,
    pub r_note: Fr,
    pub npk_refund: Fr,
    pub r_refund: Fr,
    pub bind: Fr,
}

impl SettleSmallWitness {
    /// The amount transferred at the immutable execution price.
    pub fn payout_value(&self) -> u64 {
        required_collateral(self.q, self.execution_price, self.side_sell)
    }

    pub fn refund_value(&self) -> u64 {
        required_collateral(self.q, self.collateral_price, self.side_sell) - self.payout_value()
    }

    /// The order's collateral commitment (the `locked` public input).
    pub fn locked_commitment(&self) -> Fr {
        locked_commitment(self.q, self.collateral_price, self.side_sell, self.r_locked)
    }

    /// The payout note's commitment — needed by the caller BEFORE proving
    /// (it enters the request's bind transcript).
    pub fn output_cms(&self) -> (Fr, Fr) {
        let payout = note_commit(
            self.npk_ctr,
            self.pay_asset,
            self.payout_value(),
            self.r_note,
        );
        let refund = note_commit(
            self.npk_refund,
            self.pay_asset,
            self.refund_value(),
            self.r_refund,
        );
        (payout, refund)
    }
}

/// Output of [`prove_settle_small`].
pub struct SettleSmallProof {
    pub cm_note_out_hex: String,
    pub cm_refund_out_hex: String,
    pub payout_value: u64,
    pub refund_value: u64,
    pub proof_json: Value,
    pub public_json: Value,
}

/// Build the `settle_small` witness and prove. Publics order:
/// [locked, collateral_price, execution_price, side, pay_asset,
/// cm_note_out, cm_refund_out, bind].
pub fn prove_settle_small(
    w: SettleSmallWitness,
    circuit_handle: &TestCircuitHandle,
    zkey: &Path,
) -> Result<SettleSmallProof> {
    let dec = fr_to_decimal_string;
    let locked = w.locked_commitment();
    let (cm_note_out, cm_refund_out) = w.output_cms();

    let input = json!({
        "locked": dec(&locked),
        "collateral_price": w.collateral_price.to_string(),
        "execution_price": w.execution_price.to_string(),
        "side": if w.side_sell { "1" } else { "0" },
        "pay_asset": dec(&w.pay_asset),
        "cm_note_out": dec(&cm_note_out),
        "cm_refund_out": dec(&cm_refund_out),
        "bind": dec(&w.bind),
        "q": w.q.to_string(),
        "r_locked": dec(&w.r_locked),
        "npk_ctr": dec(&w.npk_ctr),
        "r_note": dec(&w.r_note),
        "npk_refund": dec(&w.npk_refund),
        "r_refund": dec(&w.r_refund),
    });
    let wtns = circuit_handle.gen_witness(&input)?;
    let (proof_json, public_json) = run_rapidsnark(zkey, &wtns)?;
    Ok(SettleSmallProof {
        cm_note_out_hex: note_fr_to_hex(&cm_note_out),
        cm_refund_out_hex: note_fr_to_hex(&cm_refund_out),
        payout_value: w.payout_value(),
        refund_value: w.refund_value(),
        proof_json,
        public_json,
    })
}

/// Witness for `settle_large.circom` (the partially filled side): pays the
/// fill to the counterparty and re-commits the residual collateral under
/// fresh randomness. `(q_ctr, r_locked_ctr)` is the smaller side's revealed
/// collateral opening — the circuit opens THEIR on-chain collateral with
/// the OPPOSITE side, so the fill cannot be understated.
pub struct SettleLargeWitness {
    pub q: u64,
    pub r_locked: Fr,
    pub q_ctr: u64,
    pub r_locked_ctr: Fr,
    pub collateral_price: u64,
    pub ctr_collateral_price: u64,
    pub execution_price: u64,
    pub side_sell: bool,
    pub r_locked_residual: Fr,
    pub pay_asset: Fr,
    pub npk_ctr: Fr,
    pub r_note: Fr,
    pub npk_refund: Fr,
    pub r_refund: Fr,
    pub bind: Fr,
}

impl SettleLargeWitness {
    pub fn residual_q(&self) -> u64 {
        self.q - self.q_ctr
    }

    /// My total collateral: needed(q, side).
    pub fn locked_value(&self) -> u64 {
        required_collateral(self.q, self.collateral_price, self.side_sell)
    }

    /// My on-chain collateral commitment (the `locked` public input).
    pub fn locked_commitment(&self) -> Fr {
        locked_commitment(self.q, self.collateral_price, self.side_sell, self.r_locked)
    }

    /// The counterparty's collateral commitment, opened with the OPPOSITE
    /// side (the `locked_ctr` public input).
    pub fn locked_ctr_commitment(&self) -> Fr {
        locked_commitment(
            self.q_ctr,
            self.ctr_collateral_price,
            !self.side_sell,
            self.r_locked_ctr,
        )
    }

    pub fn residual_locked(&self) -> u64 {
        required_collateral(self.residual_q(), self.collateral_price, self.side_sell)
    }

    pub fn fill_value(&self) -> u64 {
        required_collateral(self.q_ctr, self.execution_price, self.side_sell)
    }

    pub fn refund_value(&self) -> u64 {
        self.locked_value() - self.residual_locked() - self.fill_value()
    }

    /// The two output commitments — needed BEFORE proving for bind.
    pub fn output_cms(&self) -> (Fr, Fr, Fr) {
        let cm_locked_res = locked_commitment(
            self.residual_q(),
            self.collateral_price,
            self.side_sell,
            self.r_locked_residual,
        );
        let cm_note = note_commit(self.npk_ctr, self.pay_asset, self.fill_value(), self.r_note);
        let cm_refund = note_commit(
            self.npk_refund,
            self.pay_asset,
            self.refund_value(),
            self.r_refund,
        );
        (cm_locked_res, cm_note, cm_refund)
    }
}

/// Output of [`prove_settle_large`].
pub struct SettleLargeProof {
    pub cm_locked_residual_hex: String,
    pub cm_note_out_hex: String,
    pub cm_refund_out_hex: String,
    pub residual_q: u64,
    pub fill_value: u64,
    pub refund_value: u64,
    pub proof_json: Value,
    pub public_json: Value,
}

/// Build the `settle_large` witness and prove. Publics order:
/// [locked, locked_ctr, collateral_price, ctr_collateral_price,
/// execution_price, side, cm_locked_residual, pay_asset, cm_note_out,
/// cm_refund_out, bind].
pub fn prove_settle_large(
    w: SettleLargeWitness,
    circuit_handle: &TestCircuitHandle,
    zkey: &Path,
) -> Result<SettleLargeProof> {
    ensure!(w.q >= w.q_ctr, "larger side must have q >= q_ctr");
    let dec = fr_to_decimal_string;
    let locked = w.locked_commitment();
    let locked_ctr = w.locked_ctr_commitment();
    let (cm_locked_res, cm_note_out, cm_refund_out) = w.output_cms();

    let input = json!({
        "locked": dec(&locked),
        "locked_ctr": dec(&locked_ctr),
        "collateral_price": w.collateral_price.to_string(),
        "ctr_collateral_price": w.ctr_collateral_price.to_string(),
        "execution_price": w.execution_price.to_string(),
        "side": if w.side_sell { "1" } else { "0" },
        "cm_locked_residual": dec(&cm_locked_res),
        "pay_asset": dec(&w.pay_asset),
        "cm_note_out": dec(&cm_note_out),
        "cm_refund_out": dec(&cm_refund_out),
        "bind": dec(&w.bind),
        "q": w.q.to_string(),
        "r_locked": dec(&w.r_locked),
        "q_ctr": w.q_ctr.to_string(),
        "r_locked_ctr": dec(&w.r_locked_ctr),
        "r_locked_res": dec(&w.r_locked_residual),
        "npk_ctr": dec(&w.npk_ctr),
        "r_note": dec(&w.r_note),
        "npk_refund": dec(&w.npk_refund),
        "r_refund": dec(&w.r_refund),
    });
    let wtns = circuit_handle.gen_witness(&input)?;
    let (proof_json, public_json) = run_rapidsnark(zkey, &wtns)?;
    Ok(SettleLargeProof {
        cm_locked_residual_hex: note_fr_to_hex(&cm_locked_res),
        cm_note_out_hex: note_fr_to_hex(&cm_note_out),
        cm_refund_out_hex: note_fr_to_hex(&cm_refund_out),
        residual_q: w.residual_q(),
        fill_value: w.fill_value(),
        refund_value: w.refund_value(),
        proof_json,
        public_json,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        note::{asset_id, empty_roots, npk_from_sk},
        note_tree::NoteTree,
    };
    use std::sync::Mutex;
    use zk::setup::{DevSetup, dev_setup_snarkjs};

    /// `dev_setup_snarkjs` writes shared cache files; two tests racing on
    /// the same circuit can read a half-written zkey. Serialize all setups.
    fn locked_setup(name: &str) -> DevSetup {
        static LOCK: Mutex<()> = Mutex::new(());
        let _guard = LOCK.lock().unwrap();
        dev_setup_snarkjs(name).expect("snarkjs setup")
    }

    fn rep(b: u8) -> [u8; 32] {
        [b; 32]
    }

    /// Full round trip: build the golden 3-leaf tree, spend leaf1 with one
    /// dummy slot, withdraw part of it, mint change — prove with rapidsnark
    /// and check the emitted publics. Also pins the public-input ORDER the
    /// chain rebuilds: [anchor, nf_0, nf_1, asset, bridge_out, cm_change, bind].
    #[test]
    fn spend_withdraw_round_trips_through_rapidsnark() {
        let sk1 = fr_from_be_bytes(&rep(0x42));
        let sk2 = fr_from_be_bytes(&rep(0x43));
        let eth = asset_id("ETH").unwrap();
        let usdt = asset_id("USDT").unwrap();

        let mut tree = NoteTree::new();
        tree.append(note_commit(
            npk_from_sk(sk1),
            eth,
            7,
            fr_from_be_bytes(&rep(0x33)),
        ));
        tree.append(note_commit(
            npk_from_sk(sk2),
            usdt,
            1_000_000,
            fr_from_be_bytes(&rep(0x34)),
        ));
        tree.append(note_commit(
            npk_from_sk(sk1),
            eth,
            5,
            fr_from_be_bytes(&rep(0x35)),
        ));

        let (path, bits) = tree.path(1);
        let slots = [
            SpendSlot::real(sk2, 1_000_000, fr_from_be_bytes(&rep(0x34)), path, bits),
            SpendSlot::dummy(),
        ];
        let w = SpendWithdrawWitness {
            slots,
            anchor: tree.root(),
            asset: usdt,
            v_out: 400_000,
            r_bridge_out: fr_from_be_bytes(&rep(0x51)),
            npk_change: npk_from_sk(sk2),
            v_change: 600_000,
            r_change: fr_from_be_bytes(&rep(0x52)),
            bind: fr_from_be_bytes(&rep(0x53)),
        };

        let setup = locked_setup("spend_withdraw");
        let handle = TestCircuitHandle::from_compiled(&setup.circuit_dir).expect("handle");
        let proof = prove_spend_withdraw(w, &handle, &setup.zkey).expect("prove");

        let public = proof.public_json.as_array().expect("public array");
        assert_eq!(
            public.len(),
            7,
            "publics: anchor,nf0,nf1,asset,bridge,change,bind"
        );
        // public[0] = anchor, [1..2] = nfs — cross-check against our own hexes.
        let dec_to_hex = |v: &serde_json::Value| {
            use ark_ff::PrimeField;
            let f = Fr::from_be_bytes_mod_order(&num_bigint_dec_to_be(v.as_str().unwrap()));
            note_fr_to_hex(&f)
        };
        assert_eq!(dec_to_hex(&public[1]), proof.nf_hex[0]);
        assert_eq!(dec_to_hex(&public[2]), proof.nf_hex[1]);
        assert_eq!(dec_to_hex(&public[4]), proof.bridge_out_commitment_hex);
        assert_eq!(dec_to_hex(&public[5]), proof.cm_change_hex);
    }

    /// Spending under the wrong asset must fail witness generation: the
    /// same opening cannot satisfy the commitment under another assetID.
    #[test]
    fn wrong_asset_is_rejected() {
        let sk2 = fr_from_be_bytes(&rep(0x43));
        let usdt = asset_id("USDT").unwrap();
        let eth = asset_id("ETH").unwrap();

        let mut tree = NoteTree::new();
        tree.append(note_commit(
            npk_from_sk(sk2),
            usdt,
            100,
            fr_from_be_bytes(&rep(0x34)),
        ));
        let (path, bits) = tree.path(0);
        let w = SpendWithdrawWitness {
            slots: [
                SpendSlot::real(sk2, 100, fr_from_be_bytes(&rep(0x34)), path, bits),
                SpendSlot::dummy(),
            ],
            anchor: tree.root(),
            asset: eth, // wrong asset for the note being spent
            v_out: 100,
            r_bridge_out: fr_from_be_bytes(&rep(0x51)),
            npk_change: npk_from_sk(sk2),
            v_change: 0,
            r_change: fr_from_be_bytes(&rep(0x52)),
            bind: fr_from_be_bytes(&rep(0x53)),
        };
        let setup = locked_setup("spend_withdraw");
        let handle = TestCircuitHandle::from_compiled(&setup.circuit_dir).expect("handle");
        assert!(prove_spend_withdraw(w, &handle, &setup.zkey).is_err());
    }

    /// note_deposit round trip.
    #[test]
    fn note_deposit_round_trips_through_rapidsnark() {
        let sk1 = fr_from_be_bytes(&rep(0x42));
        let w = NoteDepositWitness {
            v: 2_000,
            r_bridge: fr_from_be_bytes(&rep(0x61)),
            npk: npk_from_sk(sk1),
            r_note: fr_from_be_bytes(&rep(0x62)),
            asset: asset_id("ETH").unwrap(),
            bind: fr_from_be_bytes(&rep(0x63)),
        };
        let setup = locked_setup("note_deposit");
        let handle = TestCircuitHandle::from_compiled(&setup.circuit_dir).expect("handle");
        let proof = prove_note_deposit(w, &handle, &setup.zkey).expect("prove");
        let public = proof.public_json.as_array().expect("public array");
        assert_eq!(public.len(), 4, "publics: bridge,asset,cm_out,bind");
    }

    /// Decimal string → big-endian bytes (for cross-checking rapidsnark's
    /// decimal publics against our hex renderings).
    fn num_bigint_dec_to_be(dec: &str) -> Vec<u8> {
        let mut acc: Vec<u8> = vec![0];
        for ch in dec.bytes() {
            assert!(ch.is_ascii_digit());
            let mut carry = (ch - b'0') as u32;
            for byte in acc.iter_mut().rev() {
                let cur = (*byte as u32) * 10 + carry;
                *byte = (cur & 0xff) as u8;
                carry = cur >> 8;
            }
            while carry > 0 {
                acc.insert(0, (carry & 0xff) as u8);
                carry >>= 8;
            }
        }
        acc
    }

    // The empty-roots table is exercised transitively by every path above;
    // touch it here so the import is load-bearing.
    #[test]
    fn empty_roots_table_is_consistent() {
        let roots = empty_roots();
        assert_eq!(roots.len(), TREE_DEPTH + 1);
    }

    /// SendOrder round trip: a buyer of q=10 at price=3 locks 30 token2,
    /// pays fee=2 from a separate native note. Publics (14).
    /// Also: understating the collateral (locking less than q·price) is
    /// impossible because locked_value is computed in-circuit — a mismatched
    /// r_locked fails the commitment check.
    #[test]
    fn send_order_round_trips_through_rapidsnark() {
        let sk = fr_from_be_bytes(&rep(0x43));
        let fee_sk = fr_from_be_bytes(&rep(0x44));
        let usdt = asset_id("USDT").unwrap();
        let invis = asset_id("invis").unwrap();
        let mut tree = NoteTree::new();
        tree.append(note_commit(
            npk_from_sk(sk),
            usdt,
            40,
            fr_from_be_bytes(&rep(0x34)),
        ));
        tree.append(note_commit(
            npk_from_sk(fee_sk),
            invis,
            5,
            fr_from_be_bytes(&rep(0x35)),
        ));
        let (coll_path, coll_bits) = tree.path(0);
        let (fee_path, fee_bits) = tree.path(1);
        let w = SendOrderWitness {
            collateral_slots: [
                SpendSlot::real(sk, 40, fr_from_be_bytes(&rep(0x34)), coll_path, coll_bits),
                SpendSlot::dummy(),
            ],
            fee_slots: [
                SpendSlot::real(fee_sk, 5, fr_from_be_bytes(&rep(0x35)), fee_path, fee_bits),
                SpendSlot::dummy(),
            ],
            anchor: tree.root(),
            lock_asset: usdt,
            native_asset: invis,
            q: 10,
            r_locked: fr_from_be_bytes(&rep(0xB2)),
            price: 3,
            side_sell: false,
            fee: 2,
            npk_collateral_change: npk_from_sk(sk),
            v_collateral_change: 10,
            r_collateral_change: fr_from_be_bytes(&rep(0xB3)),
            npk_fee_change: npk_from_sk(fee_sk),
            v_fee_change: 3,
            r_fee_change: fr_from_be_bytes(&rep(0xB5)),
            bind: fr_from_be_bytes(&rep(0xB4)),
        };
        assert_eq!(w.locked_value(), 30);
        let setup = locked_setup("send_order");
        let handle = TestCircuitHandle::from_compiled(&setup.circuit_dir).expect("handle");
        let proof = prove_send_order(w, &handle, &setup.zkey).expect("prove");
        assert_eq!(proof.public_json.as_array().unwrap().len(), 14);
    }

    /// ClaimFees round trip: the producer mints a note for its accrued 500.
    #[test]
    fn claim_fees_round_trips_through_rapidsnark() {
        let sk = fr_from_be_bytes(&rep(0x45));
        let w = ClaimFeesWitness {
            asset: asset_id("USDT").unwrap(),
            amount: 500,
            npk: npk_from_sk(sk),
            r_note: fr_from_be_bytes(&rep(0xC1)),
            bind: fr_from_be_bytes(&rep(0xC2)),
        };
        let setup = locked_setup("claim_fees");
        let handle = TestCircuitHandle::from_compiled(&setup.circuit_dir).expect("handle");
        let proof = prove_claim_fees(w, &handle, &setup.zkey).expect("prove");
        assert_eq!(proof.public_json.as_array().unwrap().len(), 4);
    }

    /// SettleSmall round trip: a seller fully filled at q=60, price=3 —
    /// its 60 token1 collateral becomes the counterparty's note.
    /// Publics include collateral/execution prices and a refund note (8).
    #[test]
    fn settle_small_round_trips_through_rapidsnark() {
        let sk_ctr = fr_from_be_bytes(&rep(0x44));
        let w = SettleSmallWitness {
            q: 60,
            r_locked: fr_from_be_bytes(&rep(0x72)),
            collateral_price: 3,
            execution_price: 3,
            side_sell: true,
            pay_asset: asset_id("ETH").unwrap(),
            npk_ctr: npk_from_sk(sk_ctr),
            r_note: fr_from_be_bytes(&rep(0x73)),
            npk_refund: npk_from_sk(sk_ctr),
            r_refund: fr_from_be_bytes(&rep(0x75)),
            bind: fr_from_be_bytes(&rep(0x74)),
        };
        let setup = locked_setup("settle_small");
        let handle = TestCircuitHandle::from_compiled(&setup.circuit_dir).expect("handle");
        let proof = prove_settle_small(w, &handle, &setup.zkey).expect("prove");
        assert_eq!(proof.payout_value, 60);
        assert_eq!(proof.public_json.as_array().unwrap().len(), 8);
    }

    /// SettleLarge round trip: a buyer of q=80 at price=3 (locked 240
    /// token2) filled against a 60-quantity SELLING counterparty (locked
    /// 60 token1) — pays 180, re-locks 60 for the residual 20. Publics: 8.
    /// Also: understating the fill (wrong counterparty opening) must fail.
    #[test]
    fn settle_large_round_trips_and_rejects_understated_fill() {
        let sk_ctr = fr_from_be_bytes(&rep(0x44));
        let ctr_r_locked = fr_from_be_bytes(&rep(0x71));
        let make = |q_ctr: u64| SettleLargeWitness {
            q: 80,
            r_locked: fr_from_be_bytes(&rep(0x76)),
            q_ctr,
            r_locked_ctr: ctr_r_locked,
            collateral_price: 3,
            ctr_collateral_price: 3,
            execution_price: 3,
            side_sell: false,
            r_locked_residual: fr_from_be_bytes(&rep(0x78)),
            pay_asset: asset_id("USDT").unwrap(),
            npk_ctr: npk_from_sk(sk_ctr),
            r_note: fr_from_be_bytes(&rep(0x79)),
            npk_refund: npk_from_sk(sk_ctr),
            r_refund: fr_from_be_bytes(&rep(0x7B)),
            bind: fr_from_be_bytes(&rep(0x7A)),
        };
        let setup = locked_setup("settle_large");
        let handle = TestCircuitHandle::from_compiled(&setup.circuit_dir).expect("handle");

        let proof = prove_settle_large(make(60), &handle, &setup.zkey).expect("prove");
        assert_eq!(proof.residual_q, 20);
        assert_eq!(proof.fill_value, 180);
        assert_eq!(proof.public_json.as_array().unwrap().len(), 11);

        // Understating the fill: claim the counterparty ordered only 10.
        // The counterparty's real collateral is P2(needed(60, sell)=60,
        // r_locked_ctr); a fabricated q_ctr opens a DIFFERENT commitment —
        // the chain supplies locked_ctr from the match row, so the lying
        // proof's publics can never match the chain-side rebuild.
        let cheat = make(10);
        let real_locked_ctr = poseidon2(Fr::from(60u64), ctr_r_locked);
        let cheat_locked_ctr = cheat.locked_ctr_commitment();
        assert_ne!(
            note_fr_to_hex(&real_locked_ctr),
            note_fr_to_hex(&cheat_locked_ctr),
            "a fabricated counterparty quantity yields a different collateral cm — \
             the chain's order-row rebuild rejects the proof"
        );
        let cheat_proof = prove_settle_large(cheat, &handle, &setup.zkey).expect("proves");
        // The proof itself is valid — but over the WRONG public locked_ctr;
        // its publics cannot match the chain's rebuild of the real order.
        let publics = cheat_proof.public_json.as_array().unwrap();
        assert_ne!(
            publics[1].as_str().unwrap(),
            fr_to_decimal_string(&real_locked_ctr),
            "cheating publics differ from the chain-side rebuild"
        );
    }
}
