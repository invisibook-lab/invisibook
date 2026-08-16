//! The 2-party settlement session per the paper (§VI): everything crypto
//! between "QUIC connected" and "comparison proof + both signatures + each
//! side's settle witness in hand", over a single `MpcFabric`.
//!
//! The MPC's ONLY job is the comparison (π_cmp). Everything after cmp is
//! public — payouts, residual re-commitments — is each party's OWN work,
//! proven later with the single-prover settle_small / settle_large
//! circuits: by then the smaller side has revealed its opening, so each
//! party holds its complete witness alone.
//!
//! Protocol (both parties run the identical program; sender-selection is by
//! party id, and every fabric operation is enqueued in canonical A-then-B
//! order so the dataflow op-ids align):
//!
//! 1. Fingerprint preamble over the chain-sourced public inputs — a stale
//!    chain read aborts before any secret flows.
//! 2. Share both order amounts + blindings; verify each opens its ON-CHAIN
//!    order commitment inside the MPC (Poseidon on shares).
//! 3. Three-way compare, opening only `cmp`.
//! 4. The smaller party reveals its plaintext (amount, blinding) — the
//!    paper's sanctioned disclosure, needed by the larger side's π_B; both
//!    parties then open `share − revealed` and require zero, so a lying
//!    reveal aborts instantly.
//! 5. Each side derives its incoming payout note's opening (its own fresh
//!    blinding, its app-provided npk) and PERSISTS it (witness.json WAL)
//!    BEFORE the (npk, r) pair is handed to the payer — the payer can only
//!    mint what my disk already remembers.
//! 6. The two (npk, r) pairs are exchanged; the WAL is updated with the
//!    counterparty's pair (my settle proof needs it).
//! 7. Signatures over (order_a, order_b, cmp) are ferried from the host app
//!    (`SigIo`) and exchanged; then the collaborative prove of π_cmp runs
//!    and the proof is locally verified before it is returned.

use std::{fs, path::Path};

use anyhow::{Context, Result, ensure};
use ark_bn254::{Bn254, Fr, G1Projective};
use ark_ff::PrimeField;
use ark_mpc::{
    MpcFabric, PARTY0, PARTY1,
    algebra::{AuthenticatedScalarResult, Scalar},
};
use mpc_plonk::proof_system::structs::{ProvingKey, VerifyingKey};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};

use crate::{
    mpc_compare::compare_three_way,
    mpc_poseidon::poseidon_hash,
    poseidon::{asset_fr, commit, fr_to_hex, hash2, note_commit},
    prove::{ProveTimings, prove_collaborative_timed, verify_settle},
    relation::{SettlePublic, SidePrivate},
};

/// Maximum locked collateral cashes per side (2-slot shape on chain).
pub const MAX_LOCKED: usize = 2;

/// One locked collateral cash of this trader: plaintext amount + blinding.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LockedCash {
    pub amount: u64,
    /// 64-char hex of the 32-byte blinding factor.
    pub random: String,
}

/// This trader's private witness material.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MyPrivate {
    /// Hidden order amount (token1 quantity), the value `Order.Amount`
    /// commits to.
    pub order_amount: u64,
    /// 64-char hex blinding of the on-chain order commitment.
    pub r_order: String,
    /// Locked collateral cashes, 1..=2 entries.
    pub locked: Vec<LockedCash>,
}

/// Everything the app hands the session binary. Public fields must be
/// chain-sourced by the app; `my` is this trader's local witness;
/// `my_recv_npk` is a fresh shielded receiving key this wallet derived for
/// its incoming payout note. The id and token fields are echo-only: they
/// flow untouched into `witness.json` so crash recovery can rebuild local
/// records without re-deriving them.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionInput {
    /// "trader-a" (maker, PARTY0, dials) or "trader-b" (taker, PARTY1).
    pub role: String,
    pub order_a_id: String,
    pub order_b_id: String,
    pub my_order_id: String,
    pub my_input_cash_ids: Vec<String>,
    pub my_lock_token: String,
    pub my_recv_token: String,
    pub price: u64,
    pub a_is_seller: bool,
    /// On-chain `Order.Amount` commitment hexes of the two orders.
    pub order_a: String,
    pub order_b: String,
    /// On-chain locked cash commitment hexes, zero-commitment padded to 2.
    pub locked_a: [String; 2],
    pub locked_b: [String; 2],
    /// 64-char hex Fr: this wallet's fresh receiving key for its payout
    /// note (never reuse across trades — one key, one note).
    pub my_recv_npk: String,
    pub my: MyPrivate,
}

/// This trader's plaintext settlement outcome — everything it needs to
/// (a) keep its incoming payout note spendable and (b) prove its OWN
/// settle circuit (settle_small when `i_am_smaller`, else settle_large).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MyOutcome {
    /// True when this trader is the a-side (maker).
    pub is_a: bool,
    /// True when this side fully fills (cmp == 0 counts as smaller: both
    /// sides settle via the small path).
    pub i_am_smaller: bool,
    pub cmp: i8,
    /// The executed quantity min(a, b) in token1 units.
    pub fill: u64,

    // ── My incoming payout note (I chose npk and r; the counterparty's
    //    settle proof mints it) ──
    pub recv_amount: u64,
    pub recv_token: String,
    pub recv_npk: String,
    /// 64-char hex blinding I drew for my payout note.
    pub r_recv: String,
    /// NoteCommit(recv_npk, recv_token, recv_amount, r_recv) — the cm my
    /// wallet watches for on chain.
    pub recv_commitment: String,

    // ── The counterparty's payout note (MY settle proof mints it) ──
    pub ctr_recv_npk: String,
    pub ctr_r_recv: String,

    // ── Larger side only (empty/zero when i_am_smaller): the revealed
    //    counterparty opening + my residual re-commitments ──
    pub ctr_order_amount: u64,
    pub ctr_r_order: String,
    pub new_order_amount: u64,
    pub r_order_new: String,
    pub new_order_commitment: String,
    pub new_locked_amount: u64,
    pub r_locked_new: String,
    pub new_locked_commitment: String,
}

/// Crash-recovery record. First written BEFORE this side's (npk, r) pair
/// leaves the process (my own secrets), rewritten complete after the
/// exchange (the counterparty's pair, which my settle proof needs).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionWitness {
    pub order_a_id: String,
    pub order_b_id: String,
    pub my_order_id: String,
    pub my_input_cash_ids: Vec<String>,
    pub my_lock_token: String,
    pub my_recv_token: String,
    pub cmp: i8,
    pub my: MyOutcome,
}

/// The session's final product: everything the app needs to submit the
/// comparison, prove its own settle circuit, and persist.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionResult {
    pub cmp: i8,
    pub public: SettlePublic,
    /// Hex of the ark-compressed PLONK π_cmp (the on-chain wire format).
    pub proof_hex: String,
    /// Both traders' 128-char hex ed25519 signatures over the canonical
    /// compare message (opaque to this crate; the app verifies them).
    pub sig_a: String,
    pub sig_b: String,
    pub my: MyOutcome,
    pub timings: ProveTimings,
}

/// The payload the host app must sign: just the comparison result (the
/// order ids the host already knows complete the canonical message).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NeedSig {
    pub cmp: i8,
}

/// Host-side signature ferry. `request_sig` is called at most once per
/// session, from a blocking context, and must return this trader's 128-char
/// hex ed25519 signature over the canonical compare message.
pub trait SigIo: Send {
    fn request_sig(&mut self, need: &NeedSig) -> Result<String>;
}

/// Parse a 64-char hex string into 32 bytes. Rejects other lengths.
fn hex32(s: &str, what: &str) -> Result<[u8; 32]> {
    let raw = hex::decode(s).with_context(|| format!("{what}: invalid hex"))?;
    ensure!(
        raw.len() == 32,
        "{what}: expected 32 bytes, got {}",
        raw.len()
    );
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

/// Fr of a 32-byte blinding, wallet convention (big-endian reduction).
fn blinding_fr(bytes: &[u8; 32]) -> Fr {
    Fr::from_be_bytes_mod_order(bytes)
}

/// Fr of a 64-char big-endian commitment hex.
fn commitment_fr(s: &str, what: &str) -> Result<Fr> {
    Ok(Fr::from_be_bytes_mod_order(&hex32(s, what)?))
}

/// Local pre-network sanity: this trader's witness must open its own side
/// of the chain-sourced public inputs, and the collateral must exactly back
/// the order at the execution price. Distinct error strings keep failures
/// attributable (corrupt local records vs stale chain reads).
pub fn sanity_check_input(input: &SessionInput) -> Result<()> {
    ensure!(
        input.role == "trader-a" || input.role == "trader-b",
        "role must be trader-a or trader-b"
    );
    let i_am_a = input.role == "trader-a";
    ensure!(
        !input.my.locked.is_empty() && input.my.locked.len() <= MAX_LOCKED,
        "locked cash count must be 1..={MAX_LOCKED}"
    );
    // The recv npk must be a well-formed field element hex.
    commitment_fr(&input.my_recv_npk, "my_recv_npk")?;

    // The order commitment must open with my witness.
    let my_order_hex = if i_am_a {
        &input.order_a
    } else {
        &input.order_b
    };
    let r_order = hex32(&input.my.r_order, "r_order")?;
    let opened = fr_to_hex(&commit(input.my.order_amount, &r_order));
    ensure!(
        &opened == my_order_hex,
        "corrupt local cash records: witness does not open the on-chain order commitment"
    );

    // Each locked slot must open its chain hex (zero-pad slots included).
    let my_locked_hex = if i_am_a {
        &input.locked_a
    } else {
        &input.locked_b
    };
    for (slot, hex_expected) in my_locked_hex.iter().enumerate() {
        let (amount, random) = match input.my.locked.get(slot) {
            Some(l) => (l.amount, hex32(&l.random, "locked random")?),
            None => (0, [0u8; 32]),
        };
        let opened = fr_to_hex(&commit(amount, &random));
        ensure!(
            &opened == hex_expected,
            "corrupt local cash records: locked slot {slot} does not open its on-chain commitment"
        );
    }

    // Collateral backing at the execution price (equal-price limitation).
    let i_am_seller = i_am_a == input.a_is_seller;
    let locked_sum: u128 = input.my.locked.iter().map(|l| l.amount as u128).sum();
    let needed: u128 = if i_am_seller {
        input.my.order_amount as u128
    } else {
        input.my.order_amount as u128 * input.price as u128
    };
    ensure!(
        locked_sum == needed,
        "collateral does not back the order at the execution price"
    );
    Ok(())
}

/// Scale a token1 quantity into one side's payment leg: sellers move fill
/// token1, buyers move fill·price token2. Bounds the result to u64 so every
/// minted note stays spendable by the 64-bit circuits.
fn scale_leg(amount: u64, by_price: bool, price: u64, what: &str) -> Result<u64> {
    let v = if by_price {
        amount as u128 * price as u128
    } else {
        amount as u128
    };
    ensure!(
        v <= u64::MAX as u128,
        "{what} amount {v} exceeds 64 bits and would be unspendable"
    );
    Ok(v as u64)
}

/// Poseidon-fold fingerprint of the chain-sourced public inputs, exchanged
/// before any secret flows so divergent chain reads abort with a clear
/// error instead of a MAC failure deep inside the protocol.
fn input_fingerprint(input: &SessionInput) -> Result<Fr> {
    let mut vec = vec![
        commitment_fr(&input.order_a, "order_a")?,
        commitment_fr(&input.order_b, "order_b")?,
        Fr::from(input.price),
        Fr::from(input.a_is_seller as u64),
    ];
    for h in input.locked_a.iter().chain(input.locked_b.iter()) {
        vec.push(commitment_fr(h, "locked hash")?);
    }
    let mut h = Fr::from(vec.len() as u64);
    for v in vec {
        h = hash2(h, v);
    }
    Ok(h)
}

/// Split a 64-byte signature into 4 x 16-byte scalars for fabric transport.
/// Each 16-byte chunk is far below the BN254 modulus, so the round-trip is
/// exact. `sig_hex` must be 128 hex chars.
fn sig_to_scalars(sig_hex: &str) -> Result<Vec<Scalar<G1Projective>>> {
    let raw = hex::decode(sig_hex).context("signature is not valid hex")?;
    ensure!(raw.len() == 64, "signature must be 64 bytes");
    Ok(raw
        .chunks(16)
        .map(Scalar::from_be_bytes_mod_order)
        .collect())
}

/// Reassemble a 128-char hex signature from its 4 x 16-byte scalar limbs.
/// `Scalar::to_bytes_be` returns a fixed 32-byte big-endian encoding; each
/// limb must therefore carry its 16 bytes in the low half with the high
/// half zero (rejecting a malformed peer payload).
fn scalars_to_sig(limbs: &[Scalar<G1Projective>]) -> Result<String> {
    ensure!(limbs.len() == 4, "signature payload must have 4 limbs");
    let mut raw = Vec::with_capacity(64);
    for limb in limbs {
        let be = limb.to_bytes_be();
        ensure!(be.len() == 32, "unexpected scalar encoding length");
        ensure!(
            be[..16].iter().all(|b| *b == 0),
            "signature limb exceeds 16 bytes"
        );
        raw.extend_from_slice(&be[16..]);
    }
    Ok(hex::encode(raw))
}

/// Convert an opened scalar to u64, rejecting values >= 2^64. The fixed
/// 32-byte big-endian encoding must be zero above its low 8 bytes.
fn scalar_to_u64(s: &Scalar<G1Projective>, what: &str) -> Result<u64> {
    let be = s.to_bytes_be();
    ensure!(be.len() == 32, "unexpected scalar encoding length");
    ensure!(
        be[..24].iter().all(|b| *b == 0),
        "{what} does not fit in a u64"
    );
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&be[24..]);
    Ok(u64::from_be_bytes(buf))
}

/// Open a shared value and require it to be exactly zero. `what` names the
/// check in the error message.
async fn open_expect_zero(v: &AuthenticatedScalarResult<G1Projective>, what: &str) -> Result<()> {
    let opened = v
        .open_authenticated()
        .await
        .map_err(|e| anyhow::anyhow!("{what}: MAC check failed: {e:?}"))?;
    ensure!(
        opened == Scalar::from(0u64),
        "{what}: check value opened non-zero"
    );
    Ok(())
}

/// Session configuration bundled to reduce function argument count.
pub struct SessionConfig<'a> {
    pub pk: &'a ProvingKey<Bn254>,
    pub vk: &'a VerifyingKey<Bn254>,
    pub out_dir: &'a Path,
}

/// Run the full settlement session on an established fabric. `my_party`
/// must match `input.role` (PARTY0 for trader-a). `sig_io` ferries the
/// one signature request to the host app. `witness.json` is written into
/// `out_dir` before any money-critical secret leaves this process. `emit`
/// receives (phase-name, human message) progress pairs.
pub async fn run_session<F>(
    fabric: MpcFabric<G1Projective>,
    my_party: u64,
    input: &SessionInput,
    sig_io: &mut dyn SigIo,
    config: SessionConfig<'_>,
    mut emit: F,
) -> Result<SessionResult>
where
    F: FnMut(&str, &str) + Send,
{
    let i_am_a = input.role == "trader-a";
    ensure!(
        (i_am_a && my_party == PARTY0) || (!i_am_a && my_party == PARTY1),
        "role does not match fabric party id"
    );
    let i_am_seller = i_am_a == input.a_is_seller;

    // ── Preamble: agree on the chain-sourced statement ──
    emit("preamble", "cross-checking public statement with peer");
    let fp = Scalar::new(input_fingerprint(input)?);
    let fp_a = fabric.share_plaintext(fp, PARTY0);
    let fp_b = fabric.share_plaintext(fp, PARTY1);
    let (fp_a, fp_b) = (fp_a.await, fp_b.await);
    ensure!(
        fp_a == fp_b,
        "the two traders read different on-chain statements — refusing to continue (stale chain read?)"
    );

    // ── Share witnesses and bind them to the on-chain commitments ──
    emit(
        "compare",
        "verifying commitments and comparing amounts in MPC",
    );
    let my_amount_scalar = Scalar::from(input.my.order_amount);
    let my_r_order = Scalar::new(blinding_fr(&hex32(&input.my.r_order, "r_order")?));
    let zero = Scalar::from(0u64);
    // Canonical order: A's amount, A's blinding, B's amount, B's blinding.
    let pick = |owner_is_a: bool, mine: Scalar<G1Projective>| {
        if owner_is_a == i_am_a { mine } else { zero }
    };
    let v_a = fabric.share_scalar(pick(true, my_amount_scalar), PARTY0);
    let r_a = fabric.share_scalar(pick(true, my_r_order), PARTY0);
    let v_b = fabric.share_scalar(pick(false, my_amount_scalar), PARTY1);
    let r_b = fabric.share_scalar(pick(false, my_r_order), PARTY1);

    let order_a_pub = Scalar::new(commitment_fr(&input.order_a, "order_a")?);
    let order_b_pub = Scalar::new(commitment_fr(&input.order_b, "order_b")?);
    let bind_a = &poseidon_hash(&fabric, &v_a, &r_a) - order_a_pub;
    let bind_b = &poseidon_hash(&fabric, &v_b, &r_b) - order_b_pub;
    open_expect_zero(&bind_a, "order A commitment binding").await?;
    open_expect_zero(&bind_b, "order B commitment binding").await?;

    // ── Three-way comparison, opening only cmp ──
    let cmp = compare_three_way(&fabric, &v_a, &v_b).await?;
    emit("compare", &format!("cmp = {cmp}"));

    // ── The smaller party reveals its opening (paper's sanctioned leak:
    //    the larger side's π_B must open the smaller's commitment) ──
    let i_am_smaller = cmp == 0 || (cmp == 1) != i_am_a;
    let (fill, ctr_order_amount, ctr_r_order) = if cmp == 0 {
        (input.my.order_amount, 0u64, String::new())
    } else {
        emit("reveal", "revealing the smaller side's opening");
        let smaller_party = if cmp == 1 { PARTY1 } else { PARTY0 };
        let reveal_mine = my_party == smaller_party;
        let payload: Vec<Scalar<G1Projective>> = if reveal_mine {
            vec![my_amount_scalar, my_r_order]
        } else {
            vec![zero, zero]
        };
        let revealed: Vec<Scalar<G1Projective>> =
            fabric.share_plaintext(payload, smaller_party).await;
        ensure!(revealed.len() == 2, "malformed reveal payload from peer");
        // Bind the plaintext reveal to the MPC-verified shares: a lying
        // reveal aborts here, not as a rejected settle proof later.
        let (v_smaller, r_smaller) = if cmp == 1 { (&v_b, &r_b) } else { (&v_a, &r_a) };
        let v_diff = v_smaller - revealed[0];
        let r_diff = r_smaller - revealed[1];
        open_expect_zero(&v_diff, "reveal amount consistency").await?;
        open_expect_zero(&r_diff, "reveal blinding consistency").await?;

        if reveal_mine {
            (input.my.order_amount, 0u64, String::new())
        } else {
            let q_ctr = scalar_to_u64(&revealed[0], "revealed amount")?;
            let mut r = [0u8; 32];
            let be = revealed[1].to_bytes_be();
            ensure!(be.len() == 32, "unexpected scalar encoding length");
            r.copy_from_slice(&be);
            (q_ctr, q_ctr, hex::encode(r))
        }
    };

    // ── Derive my incoming payout note's opening + my residuals ──
    emit("outputs", "deriving payout-note openings");
    let mut rng = OsRng;
    // Blindings are drawn AS field elements (raw bytes reduced immediately,
    // stored in canonical 32-byte BE form): the exchange transports Fr
    // values, so a non-canonical raw encoding would come back different on
    // the other side.
    let mut draw = || {
        let mut b = [0u8; 32];
        rng.fill_bytes(&mut b);
        let mut canonical = [0u8; 32];
        let be = Scalar::<G1Projective>::new(blinding_fr(&b)).to_bytes_be();
        canonical.copy_from_slice(&be);
        canonical
    };
    // My payout: what the counterparty pays me, in my recv token.
    let recv_amount = scale_leg(fill, i_am_seller, input.price, "receive")?;
    let r_recv = draw();
    let recv_npk_fr = commitment_fr(&input.my_recv_npk, "my_recv_npk")?;
    let recv_asset = asset_fr(&input.my_recv_token)?;
    let recv_commitment = fr_to_hex(&note_commit(recv_npk_fr, recv_asset, recv_amount, &r_recv));

    // My residuals (larger side only; zero commitments are never minted by
    // the small path so the fields stay empty there).
    let (new_order_amount, r_order_new, new_order_commitment) = if i_am_smaller {
        (0u64, String::new(), String::new())
    } else {
        let remainder = input.my.order_amount - fill;
        let r = draw();
        (remainder, hex::encode(r), fr_to_hex(&commit(remainder, &r)))
    };
    let (new_locked_amount, r_locked_new, new_locked_commitment) = if i_am_smaller {
        (0u64, String::new(), String::new())
    } else {
        let residual_locked = scale_leg(new_order_amount, !i_am_seller, input.price, "new locked")?;
        let r = draw();
        (
            residual_locked,
            hex::encode(r),
            fr_to_hex(&commit(residual_locked, &r)),
        )
    };

    let mut my_outcome = MyOutcome {
        is_a: i_am_a,
        i_am_smaller,
        cmp,
        fill,
        recv_amount,
        recv_token: input.my_recv_token.clone(),
        recv_npk: input.my_recv_npk.clone(),
        r_recv: hex::encode(r_recv),
        recv_commitment,
        ctr_recv_npk: String::new(),
        ctr_r_recv: String::new(),
        ctr_order_amount,
        ctr_r_order,
        new_order_amount,
        r_order_new,
        new_order_commitment,
        new_locked_amount,
        r_locked_new,
        new_locked_commitment,
    };

    // ── WAL v1: MY money-critical secrets on disk BEFORE my (npk, r)
    //    reaches the payer (they can only mint what my disk remembers) ──
    let write_wal = |outcome: &MyOutcome| -> Result<()> {
        let witness = SessionWitness {
            order_a_id: input.order_a_id.clone(),
            order_b_id: input.order_b_id.clone(),
            my_order_id: input.my_order_id.clone(),
            my_input_cash_ids: input.my_input_cash_ids.clone(),
            my_lock_token: input.my_lock_token.clone(),
            my_recv_token: input.my_recv_token.clone(),
            cmp,
            my: outcome.clone(),
        };
        fs::create_dir_all(config.out_dir).context("creating session out dir")?;
        let path = config.out_dir.join("witness.json");
        fs::write(&path, serde_json::to_string_pretty(&witness)?).context("writing witness.json")
    };
    write_wal(&my_outcome)?;

    // ── Exchange (npk, r) so each payer can mint the other's note ──
    emit("outputs", "exchanging payout-note keys");
    let my_pair: Vec<Scalar<G1Projective>> =
        vec![Scalar::new(recv_npk_fr), Scalar::new(blinding_fr(&r_recv))];
    let dummy_pair: Vec<Scalar<G1Projective>> = vec![zero; 2];
    let pick_pair = |owner_is_a: bool| {
        if owner_is_a == i_am_a {
            my_pair.clone()
        } else {
            dummy_pair.clone()
        }
    };
    let pair_a: Vec<Scalar<G1Projective>> = fabric.share_plaintext(pick_pair(true), PARTY0).await;
    let pair_b: Vec<Scalar<G1Projective>> = fabric.share_plaintext(pick_pair(false), PARTY1).await;
    ensure!(
        pair_a.len() == 2 && pair_b.len() == 2,
        "malformed payout-note payload from peer"
    );
    let mine_echo = if i_am_a { &pair_a } else { &pair_b };
    ensure!(
        mine_echo == &my_pair,
        "own payout-note pair did not round-trip through the fabric"
    );
    let ctr_pair = if i_am_a { &pair_b } else { &pair_a };
    let scalar_hex = |s: &Scalar<G1Projective>| hex::encode(s.to_bytes_be());
    my_outcome.ctr_recv_npk = scalar_hex(&ctr_pair[0]);
    my_outcome.ctr_r_recv = scalar_hex(&ctr_pair[1]);

    // ── WAL v2: complete (my settle proof needs the counterparty's pair) ──
    write_wal(&my_outcome)?;

    // ── Signature ferry + in-fabric exchange (before the prove) ──
    emit("sig", "requesting compare signature from the host");
    let my_sig = tokio::task::block_in_place(|| sig_io.request_sig(&NeedSig { cmp }))?;
    let my_limbs = sig_to_scalars(&my_sig)?;
    let dummy_limbs: Vec<Scalar<G1Projective>> = vec![zero; 4];
    let pick_limbs = |owner_is_a: bool| {
        if owner_is_a == i_am_a {
            my_limbs.clone()
        } else {
            dummy_limbs.clone()
        }
    };
    let limbs_a: Vec<Scalar<G1Projective>> = fabric.share_plaintext(pick_limbs(true), PARTY0).await;
    let limbs_b: Vec<Scalar<G1Projective>> =
        fabric.share_plaintext(pick_limbs(false), PARTY1).await;
    let sig_a = scalars_to_sig(&limbs_a)?;
    let sig_b = scalars_to_sig(&limbs_b)?;
    let mine_sig = if i_am_a { &sig_a } else { &sig_b };
    ensure!(
        mine_sig == &my_sig,
        "own signature did not round-trip through the fabric"
    );

    // ── Collaborative prove of π_cmp + verify-before-release ──
    emit("prove", "collaboratively proving the comparison");
    let public = SettlePublic {
        cmp,
        order_a: commitment_fr(&input.order_a, "order_a")?,
        order_b: commitment_fr(&input.order_b, "order_b")?,
    };
    let side = SidePrivate {
        order_amount: input.my.order_amount,
        r_order: hex32(&input.my.r_order, "r_order")?,
    };
    let (proof, timings) =
        prove_collaborative_timed(fabric.clone(), my_party, &side, &public, config.pk).await?;

    emit("verify", "verifying the proof locally before release");
    verify_settle(config.vk, &public, &proof)?;
    let mut proof_bytes = Vec::new();
    ark_serialize::CanonicalSerialize::serialize_compressed(&proof, &mut proof_bytes)
        .context("serializing proof")?;

    Ok(SessionResult {
        cmp,
        public,
        proof_hex: hex::encode(proof_bytes),
        sig_a,
        sig_b,
        my: my_outcome,
        timings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// scale_leg mirrors both settle circuits' collateral arithmetic and
    /// bounds every leg to u64.
    #[test]
    fn scale_leg_bounds_and_scales() {
        assert_eq!(scale_leg(60, false, 3, "x").unwrap(), 60);
        assert_eq!(scale_leg(60, true, 3, "x").unwrap(), 180);
        assert!(scale_leg(u64::MAX, true, 2, "x").is_err());
    }

    /// The note commitment helper matches the wallet convention pinned by
    /// spec/golden.json (leaf1: sk2's USDT note of 1_000_000 under r=0x34).
    #[test]
    fn note_commit_matches_golden_leaf1() {
        use crate::poseidon::{TAG_CM, hash2};
        let _ = TAG_CM; // tag is baked into note_commit
        // npk = P2(TAG_NPK=2, sk2), sk2 = 0x43 * 32 reduced.
        let sk2 = Fr::from_be_bytes_mod_order(&[0x43u8; 32]);
        let npk = hash2(Fr::from(2u64), sk2);
        let usdt = asset_fr("USDT").unwrap();
        let cm = note_commit(npk, usdt, 1_000_000, &[0x34u8; 32]);
        // Golden value from spec/golden.json ("leaf1").
        let golden: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../spec/golden.json"))
                .expect("spec/golden.json must exist"),
        )
        .unwrap();
        assert_eq!(fr_to_hex(&cm), golden["leaf1"].as_str().unwrap());
    }
}
