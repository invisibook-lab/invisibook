//! The full 2-party settlement session: everything crypto between "QUIC
//! connected" and "standard PLONK proof + both signatures in hand", over a
//! single `MpcFabric`.
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
//! 4. The smaller party reveals its plaintext amount (the protocol-
//!    sanctioned leak); both parties then open `v_smaller - revealed` and
//!    require zero, so a lying reveal aborts instantly instead of surfacing
//!    as an unsatisfiable circuit after the expensive prove.
//! 5. Each side draws fresh blindings, computes its three output
//!    commitments natively, and the six hexes are exchanged; both assemble
//!    the byte-identical `SettlePublic`.
//! 6. `witness.json` is written to disk BEFORE any signature leaves this
//!    process: the peer cannot submit without my signature, so everything
//!    the chain can ever land is recoverable from my disk first.
//! 7. Signatures are ferried from the host app (`SigIo`) and exchanged over
//!    the fabric; then the collaborative prove runs and the proof is
//!    locally verified before it is returned.

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
    poseidon::{commit, fr_to_hex, hash2},
    prove::{ProveTimings, prove_collaborative_timed, verify_settle},
    relation::{MAX_LOCKED, SettlePublic, SidePrivate},
};

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
/// chain-sourced by the app; `my` is this trader's local witness. The id
/// and token fields are echo-only: they flow untouched into `witness.json`
/// so crash recovery can rebuild local records without re-deriving them.
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
    pub my: MyPrivate,
}

/// This trader's plaintext settlement outcome: the amounts and blindings it
/// must persist to keep its new UTXOs spendable.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MyOutcome {
    /// True when this trader is the a-side (maker).
    pub is_a: bool,
    pub recv_amount: u64,
    /// 64-char hex blinding of the receive commitment.
    pub r_recv: String,
    pub recv_commitment: String,
    /// Remainder order amount (0 when this side fully fills).
    pub new_order_amount: u64,
    pub r_order_new: String,
    pub new_order_commitment: String,
    /// Remainder collateral in this side's locked token.
    pub new_locked_amount: u64,
    pub r_locked_new: String,
    pub new_locked_commitment: String,
}

/// Crash-recovery record written BEFORE any signature leaves the process.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionWitness {
    pub order_a_id: String,
    pub order_b_id: String,
    pub my_order_id: String,
    pub my_input_cash_ids: Vec<String>,
    pub my_lock_token: String,
    pub my_recv_token: String,
    pub cmp: i8,
    pub new_order_a: String,
    pub new_order_b: String,
    pub new_locked_a: String,
    pub new_locked_b: String,
    pub recv_a: String,
    pub recv_b: String,
    pub my: MyOutcome,
}

/// The session's final product: everything the app needs to sign-check,
/// submit, and persist.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionResult {
    pub cmp: i8,
    pub public: SettlePublic,
    /// Hex of the ark-compressed PLONK proof (the on-chain wire format).
    pub proof_hex: String,
    /// Both traders' 128-char hex ed25519 signatures over the canonical
    /// settlement message (opaque to this crate; the app verifies them).
    pub sig_a: String,
    pub sig_b: String,
    pub my: MyOutcome,
    pub timings: ProveTimings,
}

/// The commitment payload the host app must sign, emitted after the output
/// exchange. Field order matches the canonical settlement message.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NeedSig {
    pub cmp: i8,
    pub new_order_a: String,
    pub new_order_b: String,
    pub new_locked_a: String,
    pub new_locked_b: String,
    pub recv_a: String,
    pub recv_b: String,
}

/// Host-side signature ferry. `request_sig` is called at most once per
/// session, from a blocking context, and must return this trader's 128-char
/// hex ed25519 signature over the canonical settlement message built from
/// `need` plus the order ids the host already knows.
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

/// Compute this side's three output commitments and outcome amounts from
/// its own secrets plus the (revealed or own) fill. Mirrors one side of
/// `relation::compute_public`: remainder in u128 with a u64 bound so every
/// minted commitment stays spendable by the 64-bit circuits. `fill` must be
/// `min(a, b)` and therefore `<= my_amount`.
pub fn compute_my_outputs(
    my_amount: u64,
    fill: u64,
    price: u64,
    i_am_seller: bool,
    is_a: bool,
) -> Result<(MyOutcome, [u8; 32], [u8; 32], [u8; 32])> {
    ensure!(fill <= my_amount, "fill exceeds this side's order amount");
    let remainder = my_amount - fill;

    // Token scaling per side: a seller's collateral and remainder are in
    // token1 (no scaling); a buyer's are in token2 (scaled by price).
    // Receives are the opposite leg: seller receives fill*price token2,
    // buyer receives fill token1.
    let scale = |amount: u64, by_price: bool, what: &str| -> Result<u64> {
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
    };
    let new_locked_amount = scale(remainder, !i_am_seller, "new locked")?;
    let recv_amount = scale(fill, i_am_seller, "receive")?;

    let mut rng = OsRng;
    let mut draw = || {
        let mut b = [0u8; 32];
        rng.fill_bytes(&mut b);
        b
    };
    let r_order_new = draw();
    let r_locked_new = draw();
    let r_recv = draw();

    let outcome = MyOutcome {
        is_a,
        recv_amount,
        r_recv: hex::encode(r_recv),
        recv_commitment: fr_to_hex(&commit(recv_amount, &r_recv)),
        new_order_amount: remainder,
        r_order_new: hex::encode(r_order_new),
        new_order_commitment: fr_to_hex(&commit(remainder, &r_order_new)),
        new_locked_amount,
        r_locked_new: hex::encode(r_locked_new),
        new_locked_commitment: fr_to_hex(&commit(new_locked_amount, &r_locked_new)),
    };
    Ok((outcome, r_order_new, r_locked_new, r_recv))
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
/// `out_dir` before the signature leaves this process. `emit` receives
/// (phase-name, human message) progress pairs.
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

    // ── The smaller party reveals its amount (protocol-sanctioned) ──
    let fill: u64 = if cmp == 0 {
        input.my.order_amount
    } else {
        emit("reveal", "revealing the smaller side's fill");
        let smaller_party = if cmp == 1 { PARTY1 } else { PARTY0 };
        let i_am_smaller = my_party == smaller_party;
        let payload = if i_am_smaller {
            Scalar::from(input.my.order_amount)
        } else {
            zero
        };
        let revealed: Scalar<G1Projective> = fabric.share_plaintext(payload, smaller_party).await;
        // Bind the plaintext reveal to the MPC-verified amount: a lying
        // reveal aborts here, not as an unsatisfiable circuit after the
        // expensive prove.
        let v_smaller = if cmp == 1 { &v_b } else { &v_a };
        let diff = v_smaller - revealed;
        open_expect_zero(&diff, "fill reveal consistency").await?;
        if i_am_smaller {
            input.my.order_amount
        } else {
            scalar_to_u64(&revealed, "revealed fill")?
        }
    };

    // ── Per-side outputs, exchanged so both hold the identical statement ──
    emit("outputs", "computing and exchanging output commitments");
    let (my_outcome, r_order_new, r_locked_new, r_recv) = compute_my_outputs(
        input.my.order_amount,
        fill,
        input.price,
        i_am_seller,
        i_am_a,
    )?;
    let my_scalars: Vec<Scalar<G1Projective>> = vec![
        Scalar::new(commitment_fr(
            &my_outcome.new_order_commitment,
            "own output",
        )?),
        Scalar::new(commitment_fr(
            &my_outcome.new_locked_commitment,
            "own output",
        )?),
        Scalar::new(commitment_fr(&my_outcome.recv_commitment, "own output")?),
    ];
    let dummy: Vec<Scalar<G1Projective>> = vec![zero; 3];
    let pick_vec = |owner_is_a: bool| {
        if owner_is_a == i_am_a {
            my_scalars.clone()
        } else {
            dummy.clone()
        }
    };
    let out_a: Vec<Scalar<G1Projective>> = fabric.share_plaintext(pick_vec(true), PARTY0).await;
    let out_b: Vec<Scalar<G1Projective>> = fabric.share_plaintext(pick_vec(false), PARTY1).await;
    ensure!(
        out_a.len() == 3 && out_b.len() == 3,
        "malformed output-commitment payload from peer"
    );
    // My own exchanged values must round-trip exactly.
    let mine_echo = if i_am_a { &out_a } else { &out_b };
    ensure!(
        mine_echo == &my_scalars,
        "own output commitments did not round-trip through the fabric"
    );

    let scalar_fr =
        |s: &Scalar<G1Projective>| -> Fr { Fr::from_be_bytes_mod_order(&s.to_bytes_be()) };
    let public = SettlePublic {
        cmp,
        new_order_a: scalar_fr(&out_a[0]),
        new_locked_a: scalar_fr(&out_a[1]),
        recv_a: scalar_fr(&out_a[2]),
        new_order_b: scalar_fr(&out_b[0]),
        new_locked_b: scalar_fr(&out_b[1]),
        recv_b: scalar_fr(&out_b[2]),
        order_a: commitment_fr(&input.order_a, "order_a")?,
        order_b: commitment_fr(&input.order_b, "order_b")?,
        // Execution price: token2 units per one token1 (the seller receives
        // `fill * price` token2, the buyer pays it). Public and shared by both
        // sides, so it needs no commitment.
        price: input.price,
        a_is_seller: input.a_is_seller,
        locked_a: [
            commitment_fr(&input.locked_a[0], "locked_a[0]")?,
            commitment_fr(&input.locked_a[1], "locked_a[1]")?,
        ],
        locked_b: [
            commitment_fr(&input.locked_b[0], "locked_b[0]")?,
            commitment_fr(&input.locked_b[1], "locked_b[1]")?,
        ],
    };

    // ── Witness WAL: on disk before any signature leaves this process ──
    let witness = SessionWitness {
        order_a_id: input.order_a_id.clone(),
        order_b_id: input.order_b_id.clone(),
        my_order_id: input.my_order_id.clone(),
        my_input_cash_ids: input.my_input_cash_ids.clone(),
        my_lock_token: input.my_lock_token.clone(),
        my_recv_token: input.my_recv_token.clone(),
        cmp,
        new_order_a: fr_to_hex(&public.new_order_a),
        new_order_b: fr_to_hex(&public.new_order_b),
        new_locked_a: fr_to_hex(&public.new_locked_a),
        new_locked_b: fr_to_hex(&public.new_locked_b),
        recv_a: fr_to_hex(&public.recv_a),
        recv_b: fr_to_hex(&public.recv_b),
        my: my_outcome.clone(),
    };
    fs::create_dir_all(config.out_dir).context("creating session out dir")?;
    let witness_path = config.out_dir.join("witness.json");
    fs::write(&witness_path, serde_json::to_string_pretty(&witness)?)
        .context("writing witness.json")?;

    // ── Signature ferry + in-fabric exchange (before the prove) ──
    emit("sig", "requesting settlement signature from the host");
    let need = NeedSig {
        cmp,
        new_order_a: witness.new_order_a.clone(),
        new_order_b: witness.new_order_b.clone(),
        new_locked_a: witness.new_locked_a.clone(),
        new_locked_b: witness.new_locked_b.clone(),
        recv_a: witness.recv_a.clone(),
        recv_b: witness.recv_b.clone(),
    };
    let my_sig = tokio::task::block_in_place(|| sig_io.request_sig(&need))?;
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

    // ── Collaborative prove + verify-before-release ──
    emit("prove", "collaboratively proving (this takes a while)");
    let side = SidePrivate {
        order_amount: input.my.order_amount,
        r_order: hex32(&input.my.r_order, "r_order")?,
        r_order_new,
        locked: input
            .my
            .locked
            .iter()
            .map(|l| Ok((l.amount, hex32(&l.random, "locked random")?)))
            .collect::<Result<Vec<_>>>()?,
        r_locked_new,
        r_recv,
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
    use super::{MyOutcome, compute_my_outputs};
    use crate::{
        poseidon::fr_to_hex,
        relation::{SidePrivate, compute_public},
    };

    /// Build a SidePrivate for the cross-check against `compute_public`.
    fn side(amount: u64, locked: Vec<(u64, [u8; 32])>) -> SidePrivate {
        SidePrivate {
            order_amount: amount,
            r_order: [0x11; 32],
            r_order_new: [0x12; 32],
            locked,
            r_locked_new: [0x13; 32],
            r_recv: [0x14; 32],
        }
    }

    /// Re-derive one side's commitments from a MyOutcome's plaintext fields
    /// to confirm internal consistency (amount/blinding open commitment).
    fn outcome_opens(outcome: &MyOutcome) {
        use crate::poseidon::commit;
        let open = |amount: u64, r_hex: &str, expected: &str, what: &str| {
            let mut r = [0u8; 32];
            r.copy_from_slice(&hex::decode(r_hex).unwrap());
            assert_eq!(fr_to_hex(&commit(amount, &r)), expected, "{what}");
        };
        open(
            outcome.recv_amount,
            &outcome.r_recv,
            &outcome.recv_commitment,
            "recv",
        );
        open(
            outcome.new_order_amount,
            &outcome.r_order_new,
            &outcome.new_order_commitment,
            "new_order",
        );
        open(
            outcome.new_locked_amount,
            &outcome.r_locked_new,
            &outcome.new_locked_commitment,
            "new_locked",
        );
    }

    /// The union of both sides' `compute_my_outputs` must reproduce the
    /// plaintext amounts `compute_public` derives, for every cmp branch and
    /// both role assignments.
    #[test]
    fn my_outputs_union_matches_compute_public() {
        for a_is_seller in [true, false] {
            for (a_amt, b_amt) in [(80u64, 60u64), (60, 80), (60, 60)] {
                let price = 3u64;
                let (a_locked, b_locked) = if a_is_seller {
                    (a_amt, b_amt * price)
                } else {
                    (a_amt * price, b_amt)
                };
                let a = side(a_amt, vec![(a_locked, [0xA3; 32])]);
                let b = side(b_amt, vec![(b_locked, [0xB3; 32])]);
                let reference = compute_public(&a, &b, price, a_is_seller).unwrap();

                let fill = a_amt.min(b_amt);
                let (out_a, ..) =
                    compute_my_outputs(a_amt, fill, price, a_is_seller, true).unwrap();
                let (out_b, ..) =
                    compute_my_outputs(b_amt, fill, price, !a_is_seller, false).unwrap();

                assert_eq!(
                    i8::from(reference.cmp),
                    match a_amt.cmp(&b_amt) {
                        std::cmp::Ordering::Greater => 1,
                        std::cmp::Ordering::Equal => 0,
                        std::cmp::Ordering::Less => -1,
                    }
                );
                // Amounts must match the reference derivation exactly.
                assert_eq!(out_a.new_order_amount, a_amt - fill);
                assert_eq!(out_b.new_order_amount, b_amt - fill);
                let scale = |v: u64, by_price: bool| if by_price { v * price } else { v };
                assert_eq!(out_a.new_locked_amount, scale(a_amt - fill, !a_is_seller));
                assert_eq!(out_b.new_locked_amount, scale(b_amt - fill, a_is_seller));
                assert_eq!(out_a.recv_amount, scale(fill, a_is_seller));
                assert_eq!(out_b.recv_amount, scale(fill, !a_is_seller));
                // Fresh blindings: commitments must self-open.
                outcome_opens(&out_a);
                outcome_opens(&out_b);
            }
        }
    }

    /// Overflowing token2 scaling must be rejected, not wrapped.
    #[test]
    fn my_outputs_rejects_u64_overflow() {
        // Buyer remainder scaled by price overflows u64.
        let result = compute_my_outputs(u64::MAX, 1, 2, false, true);
        assert!(result.is_err());
    }
}
