//! Shielded-pool note primitives: domain tags, key derivation, the note
//! commitment chain, and nullifier derivation.
//!
//! This module is the Rust half of the frozen protocol spec (plan rev. 3,
//! "Protocol equations"). The Go twin lives in `chain/core/pool.go`, the
//! circom twin in `lib/zk/templates/note.circom`. All three are pinned
//! byte-for-byte by `spec/golden.json`; change nothing here without
//! regenerating the golden vectors in all three languages.
//!
//! Derivations (`P2` = 2-input circomlib Poseidon over BN254 Fr):
//!
//! ```text
//! nk  = P2(TAG_NK,  sk)          npk = P2(TAG_NPK, sk)
//! cm  = P2( P2( P2( P2(TAG_CM, npk), assetID ), v ), r )
//! rho = P2( P2(TAG_RHO, cm), leafIndex )
//! nf  = P2( P2(TAG_NF,  nk), rho )
//! ```

use ark_bn254::Fr;
use ark_ff::PrimeField;
use sha2::{Digest, Sha256};
use zk::wallet::{fr_to_hex, poseidon2};

/// Domain tags namespacing every Poseidon use (spec constants — never reuse).
pub const TAG_NK: u64 = 1;
pub const TAG_NPK: u64 = 2;
pub const TAG_CM: u64 = 3;
pub const TAG_RHO: u64 = 4;
pub const TAG_NF: u64 = 5;

/// Note commitment tree depth (2^20 ≈ 1M notes; matches Go and circom).
pub const TREE_DEPTH: usize = 20;

/// Longest token symbol accepted by `asset_id` (a 32-byte string could
/// exceed the field modulus and alias another symbol after reduction).
pub const MAX_TOKEN_SYMBOL_BYTES: usize = 31;

/// Interpret 32 bytes as a big-endian integer reduced into Fr.
/// The reduction convention every secret (sk, r) enters the field by.
pub fn fr_from_be_bytes(bytes: &[u8; 32]) -> Fr {
    Fr::from_be_bytes_mod_order(bytes)
}

/// The empty tree leaf: Fr of the ASCII bytes `"invisibook.empty"`.
/// Deliberately a raw constant, not a Poseidon image — no real note
/// commitment can collide with it.
pub fn empty_leaf() -> Fr {
    Fr::from_be_bytes_mod_order(b"invisibook.empty")
}

/// `EMPTY_ROOTS[d]` = root of an empty subtree of depth `d`:
/// `E_0 = EMPTY_LEAF`, `E_{d+1} = P2(E_d, E_d)`.
pub fn empty_roots() -> [Fr; TREE_DEPTH + 1] {
    let mut roots = [empty_leaf(); TREE_DEPTH + 1];
    for d in 1..=TREE_DEPTH {
        roots[d] = poseidon2(roots[d - 1], roots[d - 1]);
    }
    roots
}

/// Map a token symbol to its field-element assetID: the UTF-8 bytes read as
/// a big-endian integer. `token` must be 1..=31 bytes so no reduction ever
/// happens and distinct symbols stay distinct.
pub fn asset_id(token: &str) -> Result<Fr, String> {
    let bytes = token.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_TOKEN_SYMBOL_BYTES {
        return Err(format!(
            "token symbol must be 1..={MAX_TOKEN_SYMBOL_BYTES} bytes, got {} ({token:?})",
            bytes.len()
        ));
    }
    Ok(Fr::from_be_bytes_mod_order(bytes))
}

/// Nullifier key: `nk = P2(TAG_NK, sk)`. Never leaves the wallet.
pub fn nk_from_sk(sk: Fr) -> Fr {
    poseidon2(Fr::from(TAG_NK), sk)
}

/// Receiving key ("shielded address"): `npk = P2(TAG_NPK, sk)`.
pub fn npk_from_sk(sk: Fr) -> Fr {
    poseidon2(Fr::from(TAG_NPK), sk)
}

/// Note commitment: the tagged nested chain
/// `cm = P2(P2(P2(P2(TAG_CM, npk), assetID), v), r)`.
/// `v` must fit the protocol's 64-bit monetary range (enforced in-circuit).
pub fn note_commit(npk: Fr, asset: Fr, v: u64, r: Fr) -> Fr {
    let c = poseidon2(Fr::from(TAG_CM), npk);
    let c = poseidon2(c, asset);
    let c = poseidon2(c, Fr::from(v));
    poseidon2(c, r)
}

/// `rho = P2(P2(TAG_RHO, cm), leafIndex)` — binds the nullifier to the
/// note's position in the tree (one note, one nullifier).
pub fn rho(cm: Fr, leaf_index: u64) -> Fr {
    poseidon2(poseidon2(Fr::from(TAG_RHO), cm), Fr::from(leaf_index))
}

/// `nf = P2(P2(TAG_NF, nk), rho)`. For real notes `rho` comes from
/// [`rho`]; for dummy input slots it is a fresh random field element
/// (same formula, so a dummy nf is an unsteerable PRF image).
pub fn nullifier(nk: Fr, rho: Fr) -> Fr {
    poseidon2(poseidon2(Fr::from(TAG_NF), nk), rho)
}

/// Convenience: the nullifier of a real note at `leaf_index`, from its
/// owner's spending secret.
pub fn note_nullifier(sk: Fr, cm: Fr, leaf_index: u64) -> Fr {
    nullifier(nk_from_sk(sk), rho(cm, leaf_index))
}

/// One note's full opening as the wallet stores it. `r_bytes` is the raw
/// 32-byte blinding (reduced BE into Fr when hashing).
#[derive(Debug, Clone)]
pub struct NoteOpening {
    pub sk: Fr,
    pub token: String,
    pub v: u64,
    pub r_bytes: [u8; 32],
}

impl NoteOpening {
    /// Recompute this opening's commitment. `token` must be a valid symbol.
    pub fn commitment(&self) -> Result<Fr, String> {
        Ok(note_commit(
            npk_from_sk(self.sk),
            asset_id(&self.token)?,
            self.v,
            fr_from_be_bytes(&self.r_bytes),
        ))
    }
}

/// Compute the `bind` public input: SHA-256 over u32-BE length-prefixed
/// fields, reduced BE into Fr. Callers pass the canonical field list of the
/// request (domain string first); the layout is pinned by the golden vector
/// and must match Go's `core.BindHash`.
pub fn bind_hash(fields: &[&[u8]]) -> Fr {
    let mut h = Sha256::new();
    for f in fields {
        h.update((f.len() as u32).to_be_bytes());
        h.update(f);
    }
    let digest: [u8; 32] = h.finalize().into();
    Fr::from_be_bytes_mod_order(&digest)
}

/// Render an Fr as the 64-char lowercase big-endian hex the chain stores.
pub fn note_fr_to_hex(f: &Fr) -> String {
    fr_to_hex(f)
}

/// ASCII domain every bind transcript starts with (Go: `bindDomain`).
pub const BIND_DOMAIN: &str = "invisibook.bind.v1";

/// Circuit-family version in every bind transcript (Go: `bindVersion`).
pub const BIND_VERSION: u32 = 1;

/// Bind for a NoteDeposit request. Field layout mirrors Go
/// `core.noteDepositBind` exactly; hex strings enter as ASCII bytes.
pub fn note_deposit_bind(
    chain_id: u64,
    token: &str,
    bridge_commitment_hex: &str,
    cm_out_hex: &str,
) -> Fr {
    bind_hash(&[
        BIND_DOMAIN.as_bytes(),
        &chain_id.to_be_bytes(),
        b"note_deposit",
        &BIND_VERSION.to_be_bytes(),
        token.as_bytes(),
        bridge_commitment_hex.as_bytes(),
        cm_out_hex.as_bytes(),
    ])
}

/// Bind for a SendOrder v4 request (Go: `core.sendOrderBind`). The order
/// id, nullifiers, and the two output commitments weld the proof to the
/// exact signed request (locked-only model: no quantity commitment).
#[allow(clippy::too_many_arguments)]
pub fn send_order_bind(
    chain_id: u64,
    order_id: &str,
    kind: u8,
    trade_type: u8,
    token1: &str,
    token2: &str,
    collateral_price: u64,
    lock_token: &str,
    coll_nf0_hex: &str,
    coll_nf1_hex: &str,
    fee_nf0_hex: &str,
    fee_nf1_hex: &str,
    locked_commitment_hex: &str,
    fee: u64,
    cm_coll_change_hex: &str,
    cm_fee_change_hex: &str,
) -> Fr {
    bind_hash(&[
        BIND_DOMAIN.as_bytes(),
        &chain_id.to_be_bytes(),
        b"send_order",
        &BIND_VERSION.to_be_bytes(),
        order_id.as_bytes(),
        &[kind],
        &[trade_type],
        token1.as_bytes(),
        token2.as_bytes(),
        &collateral_price.to_be_bytes(),
        lock_token.as_bytes(),
        coll_nf0_hex.as_bytes(),
        coll_nf1_hex.as_bytes(),
        fee_nf0_hex.as_bytes(),
        fee_nf1_hex.as_bytes(),
        locked_commitment_hex.as_bytes(),
        &fee.to_be_bytes(),
        cm_coll_change_hex.as_bytes(),
        cm_fee_change_hex.as_bytes(),
    ])
}

/// Bind for a ClaimFees request (Go: `core.claimFeesBind`).
pub fn claim_fees_bind(
    chain_id: u64,
    producer_pubkey: &str,
    token: &str,
    amount: u64,
    cm_out_hex: &str,
) -> Fr {
    bind_hash(&[
        BIND_DOMAIN.as_bytes(),
        &chain_id.to_be_bytes(),
        b"claim_fees",
        &BIND_VERSION.to_be_bytes(),
        producer_pubkey.as_bytes(),
        token.as_bytes(),
        &amount.to_be_bytes(),
        cm_out_hex.as_bytes(),
    ])
}

/// Bind for a SettleSmall request (Go: `core.settleSmallBind`). The other
/// publics (collateral, price, side, asset) are rebuilt by the chain from
/// its own order state; bind welds the proof to the pair and the payout
/// note.
pub fn settle_small_bind(
    chain_id: u64,
    order_id: &str,
    match_order_id: &str,
    cm_note_out_hex: &str,
    cm_refund_out_hex: &str,
) -> Fr {
    bind_hash(&[
        BIND_DOMAIN.as_bytes(),
        &chain_id.to_be_bytes(),
        b"settle_small",
        &BIND_VERSION.to_be_bytes(),
        order_id.as_bytes(),
        match_order_id.as_bytes(),
        cm_note_out_hex.as_bytes(),
        cm_refund_out_hex.as_bytes(),
    ])
}

/// Bind for a SettleLarge request (Go: `core.settleLargeBind`). Locked-only
/// model: the residual is a single collateral commitment.
pub fn settle_large_bind(
    chain_id: u64,
    order_id: &str,
    match_order_id: &str,
    cm_locked_residual_hex: &str,
    cm_note_out_hex: &str,
    cm_refund_out_hex: &str,
) -> Fr {
    bind_hash(&[
        BIND_DOMAIN.as_bytes(),
        &chain_id.to_be_bytes(),
        b"settle_large",
        &BIND_VERSION.to_be_bytes(),
        order_id.as_bytes(),
        match_order_id.as_bytes(),
        cm_locked_residual_hex.as_bytes(),
        cm_note_out_hex.as_bytes(),
        cm_refund_out_hex.as_bytes(),
    ])
}

/// Bind for a NoteWithdraw request (Go: `core.noteWithdrawBind`).
#[allow(clippy::too_many_arguments)]
pub fn note_withdraw_bind(
    chain_id: u64,
    token: &str,
    anchor_hex: &str,
    nf0_hex: &str,
    nf1_hex: &str,
    bridge_out_hex: &str,
    cm_change_hex: &str,
) -> Fr {
    bind_hash(&[
        BIND_DOMAIN.as_bytes(),
        &chain_id.to_be_bytes(),
        b"spend_withdraw",
        &BIND_VERSION.to_be_bytes(),
        token.as_bytes(),
        anchor_hex.as_bytes(),
        nf0_hex.as_bytes(),
        nf1_hex.as_bytes(),
        bridge_out_hex.as_bytes(),
        cm_change_hex.as_bytes(),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn golden() -> Value {
        let raw = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../spec/golden.json"
        ))
        .expect("spec/golden.json must exist");
        serde_json::from_str(&raw).expect("golden.json must parse")
    }

    fn hexv(g: &Value, key: &str) -> String {
        g[key].as_str().expect(key).to_string()
    }

    #[test]
    fn golden_keys_and_assets() {
        let g = golden();
        let sk1 = fr_from_be_bytes(&[0x42; 32]);
        assert_eq!(note_fr_to_hex(&nk_from_sk(sk1)), hexv(&g, "nk1"));
        assert_eq!(note_fr_to_hex(&npk_from_sk(sk1)), hexv(&g, "npk1"));
        assert_eq!(
            note_fr_to_hex(&asset_id("ETH").unwrap()),
            hexv(&g, "asset_eth")
        );
        assert_eq!(
            note_fr_to_hex(&asset_id("USDT").unwrap()),
            hexv(&g, "asset_usdt")
        );
        assert!(asset_id("").is_err());
        assert!(asset_id("X".repeat(32).as_str()).is_err());
    }

    #[test]
    fn golden_commitments_and_nullifiers() {
        let g = golden();
        let sk1 = fr_from_be_bytes(&[0x42; 32]);
        let sk2 = fr_from_be_bytes(&[0x43; 32]);
        let l0 = note_commit(
            npk_from_sk(sk1),
            asset_id("ETH").unwrap(),
            7,
            fr_from_be_bytes(&[0x33; 32]),
        );
        let l1 = note_commit(
            npk_from_sk(sk2),
            asset_id("USDT").unwrap(),
            1_000_000,
            fr_from_be_bytes(&[0x34; 32]),
        );
        assert_eq!(note_fr_to_hex(&l0), hexv(&g, "leaf0"));
        assert_eq!(note_fr_to_hex(&l1), hexv(&g, "leaf1"));

        assert_eq!(note_fr_to_hex(&rho(l1, 1)), hexv(&g, "rho_leaf1"));
        assert_eq!(
            note_fr_to_hex(&note_nullifier(sk2, l1, 1)),
            hexv(&g, "nf_leaf1")
        );

        // Dummy slot: same formula over fresh random secrets.
        let nf_dummy = nullifier(
            nk_from_sk(fr_from_be_bytes(&[0x66; 32])),
            fr_from_be_bytes(&[0x77; 32]),
        );
        assert_eq!(note_fr_to_hex(&nf_dummy), hexv(&g, "nf_dummy"));
    }

    #[test]
    fn golden_empty_roots_and_bind() {
        let g = golden();
        assert_eq!(note_fr_to_hex(&empty_leaf()), hexv(&g, "empty_leaf"));
        assert_eq!(
            note_fr_to_hex(&empty_roots()[TREE_DEPTH]),
            hexv(&g, "empty_root_20")
        );

        let bind = bind_hash(&[
            b"invisibook.bind.v1",
            &1926u64.to_be_bytes(),
            b"spend_withdraw",
            &1u32.to_be_bytes(),
            b"abc",
            b"hello",
        ]);
        assert_eq!(note_fr_to_hex(&bind), hexv(&g, "bind"));
    }
}
