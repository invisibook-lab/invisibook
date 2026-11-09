//! The 2-party settlement session per the paper (§VI): everything crypto
//! between "QUIC connected" and "comparison proof + both signatures + each
//! side's settle witness in hand", over a single `MpcFabric`.
//!
//! The MPC's ONLY job is the comparison (π_cmp). Settlement outputs and
//! residual re-commitments are each party's OWN work, proven later with the
//! single-prover settle_small / settle_large circuits. After both owners'
//! proof shares reconstruct and verify π_cmp on chain, both sides exchange
//! and durably record their payout-note keys. Only then does the smaller side
//! disclose its opening over the per-round encrypted channel. Once that
//! plaintext is delivered, each party can finish its witness and proof
//! locally: there is no remaining peer or MPC dependency. The payout-key WAL
//! is currently a compliant-client invariant only: its pairs are not
//! owner-signed/on-chain and the later settle circuits do not publicly bind
//! the peer's pre-reveal choice.
//!
//! Protocol (both parties run the identical program; sender-selection is by
//! party id, and every fabric operation is enqueued in canonical A-then-B
//! order so the dataflow op-ids align):
//!
//! 1. Fingerprint preamble over the chain-sourced public inputs — a stale
//!    chain read aborts before any secret flows.
//! 2. Share both order quantities + collateral blindings; verify each
//!    side's `needed(q, side)` opens its ON-CHAIN collateral commitment
//!    inside the MPC (share-local price scaling + Poseidon on shares).
//!    Locked-only model: the collateral commitment is the order's ONLY
//!    commitment — there is no separate quantity commitment.
//! 3. Three-way compare, opening only `cmp`.
//! 4. Exchange owner signatures and collaboratively prove π_cmp. Fiat--Shamir
//!    public components are retained as the common canonical template; the
//!    final two KZG points are not opened between the peers.
//! 5. Each owner submits its identity/deadline-bound native final-point share
//!    and blocks until the chain reconstructs and verifies π_cmp for this
//!    match round. Verification also creates the settlement-leg round and
//!    its absolute ten-block deadline.
//! 6. Each side derives its incoming payout-note opening, persists its own
//!    `(npk, r)` before publishing it, exchanges both pairs, and persists the
//!    peer pair too. Both `payout_keys.json` WALs are complete before reveal.
//! 7. The smaller party sends its quantity and collateral blinding under
//!    X25519/ChaCha20-Poly1305. The receiver validates the plaintext locally
//!    against the comparison-proof-bound on-chain commitment. No MPC round or
//!    peer exchange follows successful disclosure.
//! 8. Each side derives the remaining output/residual data locally, completes
//!    `witness.json`, and hands its own witness to the host for proving.

use std::{fs, path::Path};

use anyhow::{Context, Result, anyhow, ensure};
use ark_bn254::{Bn254, Fr, G1Projective};
use ark_ff::PrimeField;
use ark_mpc::{
    MpcFabric, PARTY0, PARTY1,
    algebra::{AuthenticatedScalarResult, Scalar},
};
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use mpc_plonk::proof_system::structs::{ProvingKey, VerifyingKey};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use crate::{
    mpc_compare::compare_three_way,
    mpc_poseidon::poseidon_hash,
    poseidon::{asset_fr, commit, fr_to_hex, hash2, note_commit},
    proof_share::encode_compare_proof_share_hex,
    prove::{ProveTimings, prove_collaborative_share_timed},
    relation::{SettlePublic, SidePrivate, needed_collateral},
    stats::{StepTimer, StepTimings},
};

/// This trader's private witness material (locked-only model): the opening
/// of its on-chain `Order.LockedCommitment` row — the order's ONLY
/// commitment. The committed value is derived: `needed(q, side)` = q for a
/// sell, q·price for a buy.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MyPrivate {
    /// Hidden order quantity (token1 units) backing the collateral.
    pub order_amount: u64,
    /// 64-char hex blinding of the on-chain collateral commitment.
    pub r_locked: String,
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
    pub my_lock_token: String,
    pub my_recv_token: String,
    /// Each order's public collateral price (limit price, or market
    /// protection price). They may differ for crossing orders.
    pub price_a: u64,
    pub price_b: u64,
    /// Immutable price selected by the matcher for asset transfer.
    pub execution_price: u64,
    pub a_is_seller: bool,
    /// On-chain `Order.LockedCommitment` hexes of the two orders — each
    /// order's single commitment in the locked-only model.
    pub locked_a: String,
    pub locked_b: String,
    /// 64-char hex Fr: this wallet's fresh receiving key for its payout
    /// note (never reuse across trades — one key, one note).
    pub my_recv_npk: String,
    /// Fresh key for the price-improvement refund note minted by this
    /// trader's own settlement leg (zero-valued for sellers/equal prices).
    pub my_refund_npk: String,
    /// Ephemeral X25519 secret and the peer's chain-authenticated public key.
    /// They encrypt the smaller-side opening end to end above QUIC.
    pub transport_secret: String,
    pub peer_transport_pubkey: String,
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

    // ── My price-improvement refund note (MY settle proof mints it) ──
    pub refund_amount: u64,
    pub refund_token: String,
    pub refund_npk: String,
    pub r_refund: String,
    pub refund_commitment: String,

    // ── The counterparty's payout note (MY settle proof mints it) ──
    pub ctr_recv_npk: String,
    pub ctr_r_recv: String,

    // ── Larger side only (empty/zero when i_am_smaller): the revealed
    //    counterparty opening + my residual re-commitment ──
    /// The counterparty's revealed quantity.
    pub ctr_order_amount: u64,
    /// The counterparty's revealed collateral blinding (canonical hex).
    pub ctr_r_locked: String,
    /// Unfilled quantity kept on the book — wallet bookkeeping only; the
    /// residual COLLATERAL commitment below is the only re-commitment
    /// (locked-only model: no residual quantity commitment exists).
    pub new_order_amount: u64,
    pub new_locked_amount: u64,
    pub r_locked_new: String,
    pub new_locked_commitment: String,
}

/// Complete post-reveal crash-recovery record used to generate this owner's
/// settlement proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionWitness {
    pub order_a_id: String,
    pub order_b_id: String,
    pub my_order_id: String,
    pub my_lock_token: String,
    pub my_recv_token: String,
    pub cmp: i8,
    pub my: MyOutcome,
}

/// Minimal write-ahead record for the pre-reveal payout-key exchange. Both
/// owners persist their own key before publishing it and persist the peer's
/// key before the smaller opening is sent. Consequently, once a reveal can
/// occur, either honest host already has the payout material its settlement
/// proof needs.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct PayoutKeyWitness {
    order_a_id: String,
    order_b_id: String,
    my_order_id: String,
    my_recv_npk: String,
    r_recv: String,
    ctr_recv_npk: String,
    ctr_r_recv: String,
}

/// The session's final product: everything the app needs to submit the
/// comparison, prove its own settle circuit, and persist.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionResult {
    pub cmp: i8,
    pub public: SettlePublic,
    /// Hex of this owner's canonical native collaborative-proof share.
    pub proof_share_hex: String,
    /// Both traders' 128-char hex ed25519 signatures over the canonical
    /// compare message (opaque to this crate; the app verifies them).
    pub sig_a: String,
    pub sig_b: String,
    pub my: MyOutcome,
    pub timings: ProveTimings,
    /// Wall-clock the session spent BLOCKED in the host's
    /// `confirm_compare_onchain` hook (chain latency, NOT cryptography —
    /// report it separately from the MPC/prove phases).
    #[serde(default)]
    pub onchain_wait_ms: f64,
    /// Retained in the stats schema for backwards compatibility. Native proof
    /// shares are first reconstructed and verified on chain, so this is zero.
    #[serde(default)]
    pub verify_ms: f64,
    /// Wall-clock of every protocol step, labelled to match
    /// `docs/settlement_protocol.md` §2.2.
    #[serde(default)]
    pub steps: StepTimings,
}

/// The payload the host app must sign: just the comparison result (the
/// order ids the host already knows complete the canonical message).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NeedSig {
    pub cmp: i8,
}

/// The compare artifacts handed to the host BEFORE any reveal, so the host
/// can land its owner-bound native proof share on chain first. Carries the
/// proven `cmp`, this party's share payload, and both comparison signatures.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompareReady {
    pub cmp: i8,
    pub public: SettlePublic,
    /// Hex of this owner's canonical native collaborative-proof share.
    pub proof_share_hex: String,
    pub sig_a: String,
    pub sig_b: String,
}

/// Host-side ferry between the session and the chain.
///
/// `request_sig` is called at most once per session, from a blocking
/// context, and must return this trader's 128-char hex ed25519 signature
/// over the canonical compare message.
///
/// `confirm_compare_onchain` is called AFTER π_cmp + both signatures are
/// ready but BEFORE the smaller side reveals its opening. The host MUST
/// submit the comparison on chain and block until both orders are confirmed
/// `Settling`; only then does it return `Ok`. Returning `Err` aborts the
/// session before any secret leaves the process. A submitted comparison
/// share may remain as an audit trace, but there is no quantity reveal to
/// misattribute. This is the ordering that keeps a
/// malicious larger side from extracting the smaller's quantity by aborting
/// after the reveal (the reveal now never precedes the on-chain anchor).
pub trait SigIo: Send {
    fn request_sig(&mut self, need: &NeedSig) -> Result<String>;
    fn confirm_compare_onchain(&mut self, ready: &CompareReady) -> Result<()>;
}

/// Parse a 64-char hex string into 32 bytes. Rejects other lengths.
pub(crate) fn hex32(s: &str, what: &str) -> Result<[u8; 32]> {
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
pub(crate) fn blinding_fr(bytes: &[u8; 32]) -> Fr {
    Fr::from_be_bytes_mod_order(bytes)
}

/// Fr of a 64-char big-endian commitment hex.
pub(crate) fn commitment_fr(s: &str, what: &str) -> Result<Fr> {
    Ok(Fr::from_be_bytes_mod_order(&hex32(s, what)?))
}

/// Local pre-network sanity: this trader's witness must open its own side
/// of the chain-sourced public inputs — `needed(q, side)` at the execution
/// price must commit to the on-chain collateral commitment. Distinct error
/// strings keep failures attributable (corrupt local records vs stale
/// chain reads).
pub fn sanity_check_input(input: &SessionInput) -> Result<()> {
    ensure!(
        input.role == "trader-a" || input.role == "trader-b",
        "role must be trader-a or trader-b"
    );
    let i_am_a = input.role == "trader-a";
    // The recv npk must be a well-formed field element hex.
    commitment_fr(&input.my_recv_npk, "my_recv_npk")?;
    commitment_fr(&input.my_refund_npk, "my_refund_npk")?;

    // needed(q, side) must fit u64 (the 64-bit circuits) and open my
    // on-chain collateral commitment.
    let i_am_seller = i_am_a == input.a_is_seller;
    let my_price = if i_am_a { input.price_a } else { input.price_b };
    let needed = needed_collateral(input.my.order_amount, my_price, i_am_seller)
        .context("required collateral exceeds 64 bits")?;
    let my_locked_hex = if i_am_a {
        &input.locked_a
    } else {
        &input.locked_b
    };
    let r_locked = hex32(&input.my.r_locked, "r_locked")?;
    let opened_locked = fr_to_hex(&commit(needed, &r_locked));
    ensure!(
        &opened_locked == my_locked_hex,
        "corrupt local order records: witness does not open the on-chain collateral commitment"
    );
    Ok(())
}

/// Scale a token1 quantity into one side's payment leg: sellers move fill
/// token1, buyers move fill·price token2. That is the collateral equation
/// [`needed_collateral`] with the buyer side selected by `by_price`, so both
/// go through the one helper — including its u64 bound, which keeps every
/// minted note spendable by the 64-bit circuits.
pub(crate) fn scale_leg(amount: u64, by_price: bool, price: u64, what: &str) -> Result<u64> {
    needed_collateral(amount, price, !by_price)
        .with_context(|| format!("{what} amount exceeds 64 bits and would be unspendable"))
}

fn decode_32(value: &str, what: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(value).with_context(|| format!("decoding {what}"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("{what} must be exactly 32 bytes"))
}

fn reveal_aad(input: &SessionInput) -> Vec<u8> {
    format!(
        "invisibook-amount-reveal-v1:{}:{}:{}:{}:{}:{}",
        input.order_a_id,
        input.order_b_id,
        input.price_a,
        input.price_b,
        input.execution_price,
        input.a_is_seller as u8,
    )
    .into_bytes()
}

fn reveal_cipher(input: &SessionInput) -> Result<(ChaCha20Poly1305, [u8; 12], Vec<u8>)> {
    let secret = StaticSecret::from(decode_32(&input.transport_secret, "transport_secret")?);
    let peer = X25519PublicKey::from(decode_32(
        &input.peer_transport_pubkey,
        "peer_transport_pubkey",
    )?);
    let shared = secret.diffie_hellman(&peer);
    ensure!(
        shared.as_bytes().iter().any(|byte| *byte != 0),
        "invalid all-zero X25519 shared secret"
    );
    let aad = reveal_aad(input);
    let mut key_hash = Sha256::new();
    key_hash.update(b"invisibook-amount-reveal-key-v1");
    key_hash.update(shared.as_bytes());
    key_hash.update(&aad);
    let key: [u8; 32] = key_hash.finalize().into();
    let mut nonce_hash = Sha256::new();
    nonce_hash.update(b"invisibook-amount-reveal-nonce-v1");
    nonce_hash.update(&aad);
    let nonce_digest = nonce_hash.finalize();
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&nonce_digest[..12]);
    Ok((ChaCha20Poly1305::new((&key).into()), nonce, aad))
}

/// Poseidon-fold fingerprint of the chain-sourced public inputs, exchanged
/// before any secret flows so divergent chain reads abort with a clear
/// error instead of a MAC failure deep inside the protocol.
pub(crate) fn input_fingerprint(input: &SessionInput) -> Result<Fr> {
    let vec = vec![
        commitment_fr(&input.locked_a, "locked_a")?,
        commitment_fr(&input.locked_b, "locked_b")?,
        Fr::from(input.price_a),
        Fr::from(input.price_b),
        Fr::from(input.execution_price),
        Fr::from(input.a_is_seller as u64),
    ];
    let mut h = Fr::from(vec.len() as u64);
    for v in vec {
        h = hash2(h, v);
    }
    Ok(h)
}

/// Split a 64-byte signature into 4 x 16-byte scalars for fabric transport.
/// Each 16-byte chunk is far below the BN254 modulus, so the round-trip is
/// exact. `sig_hex` must be 128 hex chars.
pub(crate) fn sig_to_scalars(sig_hex: &str) -> Result<Vec<Scalar<G1Projective>>> {
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
pub(crate) fn scalars_to_sig(limbs: &[Scalar<G1Projective>]) -> Result<String> {
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
pub(crate) fn scalar_to_u64(s: &Scalar<G1Projective>, what: &str) -> Result<u64> {
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
pub(crate) async fn open_expect_zero(
    v: &AuthenticatedScalarResult<G1Projective>,
    what: &str,
) -> Result<()> {
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
    // Per-step stopwatch; labels match docs/settlement_protocol.md §2.2.
    let mut step = StepTimer::new();

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

    step.lap("1 preamble fingerprint");

    // ── Share witnesses and bind them to the on-chain commitments ──
    emit(
        "compare",
        "verifying commitments and comparing amounts in MPC",
    );
    let my_amount_scalar = Scalar::from(input.my.order_amount);
    let my_r_locked = Scalar::new(blinding_fr(&hex32(&input.my.r_locked, "r_locked")?));
    let zero = Scalar::from(0u64);
    // Canonical order: A's quantity, A's blinding, B's quantity, B's
    // blinding — the blindings are the collateral blindings (locked-only).
    let pick = |owner_is_a: bool, mine: Scalar<G1Projective>| {
        if owner_is_a == i_am_a { mine } else { zero }
    };
    let q_a = fabric.share_scalar(pick(true, my_amount_scalar), PARTY0);
    let r_a = fabric.share_scalar(pick(true, my_r_locked), PARTY0);
    let q_b = fabric.share_scalar(pick(false, my_amount_scalar), PARTY1);
    let r_b = fabric.share_scalar(pick(false, my_r_locked), PARTY1);

    // needed(q, side) on shares: the side flags and price are public, so
    // the scaling is share-local (no Beaver triples). A's flag is
    // a_is_seller; B is always the opposite side.
    let needed_of = |q: &AuthenticatedScalarResult<G1Projective>, price: u64, is_seller: bool| {
        if is_seller {
            q.clone()
        } else {
            q * Scalar::from(price)
        }
    };
    let needed_a = needed_of(&q_a, input.price_a, input.a_is_seller);
    let needed_b = needed_of(&q_b, input.price_b, !input.a_is_seller);
    let locked_a_pub = Scalar::new(commitment_fr(&input.locked_a, "locked_a")?);
    let locked_b_pub = Scalar::new(commitment_fr(&input.locked_b, "locked_b")?);
    let bind_a = &poseidon_hash(&fabric, &needed_a, &r_a) - locked_a_pub;
    let bind_b = &poseidon_hash(&fabric, &needed_b, &r_b) - locked_b_pub;
    open_expect_zero(&bind_a, "order A collateral binding").await?;
    open_expect_zero(&bind_b, "order B collateral binding").await?;
    step.lap("2 share inputs + collateral binding");

    // ── Three-way comparison of the quantities, opening only cmp ──
    let cmp = compare_three_way(&fabric, &q_a, &q_b).await?;
    step.lap("3 three-way compare");
    emit("compare", &format!("cmp = {cmp}"));

    // ── Signature ferry + in-fabric exchange (over the compared result;
    //    both run BEFORE the reveal so the compare can land on chain first) ──
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

    step.lap("4 signature ferry + exchange");

    // ── Collaborative prove of π_cmp, retaining this party's final shares ──
    emit("prove", "collaboratively proving the comparison");
    let public = SettlePublic {
        cmp,
        locked_a: commitment_fr(&input.locked_a, "locked_a")?,
        locked_b: commitment_fr(&input.locked_b, "locked_b")?,
        price_a: input.price_a,
        price_b: input.price_b,
        a_is_seller: input.a_is_seller,
    };
    let side = SidePrivate {
        order_amount: input.my.order_amount,
        r_locked: hex32(&input.my.r_locked, "r_locked")?,
    };
    let (proof_share, timings) =
        prove_collaborative_share_timed(fabric.clone(), my_party, &side, &public, config.pk)
            .await?;
    let proof_share_hex = encode_compare_proof_share_hex(&proof_share)?;
    let verify_ms = 0.0;
    step.lap("5 collaborative prove + native share export");

    // ── Pre-reveal gate: each host submits its own proof share and
    //    BLOCKS until both owner shares reconstruct and verify on chain;
    //    only then may the smaller side reveal. Nothing secret has left this
    //    process yet, so a timeout releases both orders without punishment. ──
    let ready = CompareReady {
        cmp,
        public: public.clone(),
        proof_share_hex: proof_share_hex.clone(),
        sig_a: sig_a.clone(),
        sig_b: sig_b.clone(),
    };
    emit(
        "compare-onchain",
        "landing the comparison on chain before any reveal",
    );
    let onchain_start = std::time::Instant::now();
    tokio::task::block_in_place(|| sig_io.confirm_compare_onchain(&ready))?;
    let onchain_wait_ms = onchain_start.elapsed().as_secs_f64() * 1e3;
    step.lap("6 on-chain compare anchor (host wait)");

    // ── Pre-reveal payout-key exchange ──
    // Generate and WAL my incoming note key before publishing it, then WAL
    // the peer's pair before any quantity opening can leave the smaller side.
    // After this barrier there is no peer-dependent setup left that could
    // prevent an honest owner from constructing its settlement proof.
    emit("outputs", "exchanging payout-note keys before reveal");
    let mut rng = OsRng;
    // Blindings are sampled as field elements and stored in canonical
    // 32-byte BE form because the exchange transports Fr values.
    let mut draw = || {
        let mut b = [0u8; 32];
        rng.fill_bytes(&mut b);
        let mut canonical = [0u8; 32];
        let be = Scalar::<G1Projective>::new(blinding_fr(&b)).to_bytes_be();
        canonical.copy_from_slice(&be);
        canonical
    };
    let r_recv = draw();
    let recv_npk_fr = commitment_fr(&input.my_recv_npk, "my_recv_npk")?;
    let write_payout_wal = |ctr_recv_npk: &str, ctr_r_recv: &str| -> Result<()> {
        let witness = PayoutKeyWitness {
            order_a_id: input.order_a_id.clone(),
            order_b_id: input.order_b_id.clone(),
            my_order_id: input.my_order_id.clone(),
            my_recv_npk: input.my_recv_npk.clone(),
            r_recv: hex::encode(r_recv),
            ctr_recv_npk: ctr_recv_npk.to_owned(),
            ctr_r_recv: ctr_r_recv.to_owned(),
        };
        fs::create_dir_all(config.out_dir).context("creating session out dir")?;
        fs::write(
            config.out_dir.join("payout_keys.json"),
            serde_json::to_string_pretty(&witness)?,
        )
        .context("writing payout_keys.json")
    };
    write_payout_wal("", "")?;

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
    let ctr_recv_npk = scalar_hex(&ctr_pair[0]);
    let ctr_r_recv = scalar_hex(&ctr_pair[1]);
    write_payout_wal(&ctr_recv_npk, &ctr_r_recv)?;
    step.lap("7 payout-note keys + pre-reveal WAL");

    // ── The smaller party reveals its opening (compare is now ON-CHAIN;
    //    the larger side's π_B must open the smaller's commitment) ──
    let i_am_smaller = cmp == 0 || (cmp == 1) != i_am_a;
    let (fill, ctr_order_amount, ctr_r_locked) = if cmp == 0 {
        (input.my.order_amount, 0u64, String::new())
    } else {
        emit("reveal", "revealing the smaller side's opening");
        let smaller_party = if cmp == 1 { PARTY1 } else { PARTY0 };
        let reveal_mine = my_party == smaller_party;
        let (cipher, nonce_bytes, aad) = reveal_cipher(input)?;
        let ciphertext = if reveal_mine {
            let mut plaintext = Vec::with_capacity(64);
            plaintext.extend_from_slice(&my_amount_scalar.to_bytes_be());
            plaintext.extend_from_slice(&my_r_locked.to_bytes_be());
            cipher
                .encrypt(
                    Nonce::from_slice(&nonce_bytes),
                    Payload {
                        msg: &plaintext,
                        aad: &aad,
                    },
                )
                .map_err(|_| anyhow!("encrypting smaller-side opening"))?
        } else {
            vec![0u8; 80]
        };
        ensure!(
            ciphertext.len() == 80,
            "unexpected reveal ciphertext length"
        );
        let encrypted_limbs: Vec<Scalar<G1Projective>> = fabric
            .share_plaintext(bytes_to_scalars(&ciphertext), smaller_party)
            .await;
        let encrypted = scalars_to_bytes(&encrypted_limbs, 80)?;
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: &encrypted,
                    aad: &aad,
                },
            )
            .map_err(|_| anyhow!("authenticating smaller-side encrypted opening"))?;
        ensure!(plaintext.len() == 64, "malformed decrypted reveal payload");
        let revealed = [
            Scalar::<G1Projective>::from_be_bytes_mod_order(&plaintext[..32]),
            Scalar::<G1Projective>::from_be_bytes_mod_order(&plaintext[32..]),
        ];
        if reveal_mine {
            (input.my.order_amount, 0u64, String::new())
        } else {
            let q_ctr = scalar_to_u64(&revealed[0], "revealed amount")?;
            let mut r = [0u8; 32];
            let be = revealed[1].to_bytes_be();
            ensure!(be.len() == 32, "unexpected scalar encoding length");
            r.copy_from_slice(&be);
            // No MPC round is allowed after disclosure: validate the reveal
            // locally against the already proof-bound on-chain collateral
            // commitment. A malicious receiver can now disconnect without
            // preventing the honest smaller owner from completing locally.
            let (price, is_seller, locked) = if cmp == 1 {
                (input.price_b, !input.a_is_seller, public.locked_b)
            } else {
                (input.price_a, input.a_is_seller, public.locked_a)
            };
            let revealed_locked = needed_collateral(q_ctr, price, is_seller)?;
            ensure!(
                commit(revealed_locked, &r) == locked,
                "smaller-side reveal does not open its on-chain collateral commitment"
            );
            (q_ctr, q_ctr, hex::encode(r))
        }
    };

    step.lap("8 smaller-side reveal");

    // ── Derive my incoming payout note's opening + my residuals ──
    emit("outputs", "deriving payout-note openings");
    // My payout: what the counterparty pays me, in my recv token.
    let recv_amount = scale_leg(fill, i_am_seller, input.execution_price, "receive")?;
    let recv_asset = asset_fr(&input.my_recv_token)?;
    let recv_commitment = fr_to_hex(&note_commit(recv_npk_fr, recv_asset, recv_amount, &r_recv));

    // My residual (larger side only; zero commitments are never minted by
    // the small path so the fields stay empty there). Locked-only model:
    // the residual collateral commitment `P2(needed(q_res, side), r)` is
    // the ONLY re-commitment; the residual quantity itself is plain wallet
    // bookkeeping.
    let new_order_amount = if i_am_smaller {
        0u64
    } else {
        input.my.order_amount - fill
    };
    let (new_locked_amount, r_locked_new, new_locked_commitment) = if i_am_smaller {
        (0u64, String::new(), String::new())
    } else {
        let my_price = if i_am_a { input.price_a } else { input.price_b };
        let residual_locked = scale_leg(new_order_amount, !i_am_seller, my_price, "new locked")?;
        let r = draw();
        (
            residual_locked,
            hex::encode(r),
            fr_to_hex(&commit(residual_locked, &r)),
        )
    };

    let my_price = if i_am_a { input.price_a } else { input.price_b };
    let original_locked = needed_collateral(input.my.order_amount, my_price, i_am_seller)?;
    let payment = needed_collateral(fill, input.execution_price, i_am_seller)?;
    let refund_amount = original_locked
        .checked_sub(new_locked_amount)
        .and_then(|v| v.checked_sub(payment))
        .context("execution price violates this order's collateral bound")?;
    let r_refund = draw();
    let refund_npk_fr = commitment_fr(&input.my_refund_npk, "my_refund_npk")?;
    let refund_asset = asset_fr(&input.my_lock_token)?;
    let refund_commitment = fr_to_hex(&note_commit(
        refund_npk_fr,
        refund_asset,
        refund_amount,
        &r_refund,
    ));

    let my_outcome = MyOutcome {
        is_a: i_am_a,
        i_am_smaller,
        cmp,
        fill,
        recv_amount,
        recv_token: input.my_recv_token.clone(),
        recv_npk: input.my_recv_npk.clone(),
        r_recv: hex::encode(r_recv),
        recv_commitment,
        refund_amount,
        refund_token: input.my_lock_token.clone(),
        refund_npk: input.my_refund_npk.clone(),
        r_refund: hex::encode(r_refund),
        refund_commitment,
        ctr_recv_npk,
        ctr_r_recv,
        ctr_order_amount,
        ctr_r_locked,
        new_order_amount,
        new_locked_amount,
        r_locked_new,
        new_locked_commitment,
    };

    // ── Complete post-reveal WAL. The payout keys were already persisted
    //    before disclosure; this adds fill, refund, residual and (for the
    //    larger side) the counterparty's revealed opening. ──
    let write_wal = |outcome: &MyOutcome| -> Result<()> {
        let witness = SessionWitness {
            order_a_id: input.order_a_id.clone(),
            order_b_id: input.order_b_id.clone(),
            my_order_id: input.my_order_id.clone(),
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
    step.lap("9 outputs + complete WAL");

    Ok(SessionResult {
        cmp,
        public,
        proof_share_hex,
        sig_a,
        sig_b,
        my: my_outcome,
        timings,
        onchain_wait_ms,
        verify_ms,
        steps: step.finish(),
    })
}

// ────────────────────── Settle-leg exchange (SettlePair) ──────────────────────

/// One side's settle artifacts. Production submits this owner-bound leg
/// directly; the exchange helper below remains for benchmark compatibility.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SettleLeg {
    /// True when this leg belongs to order A (the maker side).
    pub is_a: bool,
    pub cm_note_out: String,
    pub cm_refund_out: String,
    pub signature: String,
    pub zk_proof: String,
    #[serde(default)]
    pub cm_locked_residual: String,
}

/// Chunk arbitrary bytes into 16-byte big-endian scalars (each far below
/// the BN254 modulus, so the round-trip is exact). The final chunk is
/// zero-padded; the true length travels separately.
fn bytes_to_scalars(bytes: &[u8]) -> Vec<Scalar<G1Projective>> {
    bytes
        .chunks(16)
        .map(|c| {
            let mut buf = [0u8; 16];
            buf[..c.len()].copy_from_slice(c);
            Scalar::from_be_bytes_mod_order(&buf)
        })
        .collect()
}

/// Reassemble bytes from 16-byte scalar limbs, truncating to `len`. Each
/// limb must fit 16 bytes (its high half zero) or the peer sent garbage.
fn scalars_to_bytes(limbs: &[Scalar<G1Projective>], len: usize) -> Result<Vec<u8>> {
    ensure!(
        len <= limbs.len() * 16,
        "peer-announced length exceeds the transported payload"
    );
    let mut raw = Vec::with_capacity(limbs.len() * 16);
    for limb in limbs {
        let be = limb.to_bytes_be();
        ensure!(be.len() == 32, "unexpected scalar encoding length");
        ensure!(
            be[..16].iter().all(|b| *b == 0),
            "payload limb exceeds 16 bytes"
        );
        raw.extend_from_slice(&be[16..]);
    }
    raw.truncate(len);
    Ok(raw)
}

/// Exchange one arbitrary byte payload per party over the fabric: two
/// plaintext rounds (lengths, then 16-byte-chunked payloads). Both parties
/// must call it with the same round structure; returns (A's, B's) bytes.
async fn exchange_bytes(
    fabric: &MpcFabric<G1Projective>,
    my_party: u64,
    mine: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    let i_am_a = my_party == PARTY0;
    let zero = Scalar::from(0u64);
    // Round 1: lengths.
    let my_len = Scalar::from(mine.len() as u64);
    let pick_len = |owner_is_a: bool| if owner_is_a == i_am_a { my_len } else { zero };
    let len_a = fabric.share_plaintext(pick_len(true), PARTY0);
    let len_b = fabric.share_plaintext(pick_len(false), PARTY1);
    let (len_a, len_b) = (len_a.await, len_b.await);
    let len_a = scalar_to_u64(&len_a, "A payload length")? as usize;
    let len_b = scalar_to_u64(&len_b, "B payload length")? as usize;
    // Cap: a settle leg (proof JSON + signature) is a few KB; 1 MB is
    // already far beyond any legitimate payload.
    ensure!(
        len_a <= 1 << 20 && len_b <= 1 << 20,
        "peer announced an oversized payload"
    );

    // Round 2: payloads, dummy-padded so both parties enqueue identical
    // network ops (the fabric requires aligned op streams).
    let my_limbs = bytes_to_scalars(mine);
    let (my_len_bytes, ctr_len_bytes) = if i_am_a {
        (len_a, len_b)
    } else {
        (len_b, len_a)
    };
    ensure!(
        my_len_bytes == mine.len(),
        "own length did not round-trip through the fabric"
    );
    let dummy = vec![zero; ctr_len_bytes.div_ceil(16)];
    let pick_limbs = |owner_is_a: bool| {
        if owner_is_a == i_am_a {
            my_limbs.clone()
        } else {
            dummy.clone()
        }
    };
    let limbs_a: Vec<Scalar<G1Projective>> = fabric.share_plaintext(pick_limbs(true), PARTY0).await;
    let limbs_b: Vec<Scalar<G1Projective>> =
        fabric.share_plaintext(pick_limbs(false), PARTY1).await;
    let bytes_a = scalars_to_bytes(&limbs_a, len_a)?;
    let bytes_b = scalars_to_bytes(&limbs_b, len_b)?;
    let mine_echo = if i_am_a { &bytes_a } else { &bytes_b };
    ensure!(
        mine_echo.as_slice() == mine,
        "own payload did not round-trip through the fabric"
    );
    Ok((bytes_a, bytes_b))
}

/// Legacy benchmark helper that exchanges the two settle legs over the
/// fabric. Production no longer exchanges peer proofs. `my_leg.is_a` must
/// match this party's role (PARTY0 = A). Returns (leg_a, leg_b).
pub async fn exchange_settle_legs(
    fabric: &MpcFabric<G1Projective>,
    my_party: u64,
    my_leg: &SettleLeg,
) -> Result<(SettleLeg, SettleLeg)> {
    ensure!(
        my_leg.is_a == (my_party == PARTY0),
        "leg role does not match fabric party id"
    );
    let mine = serde_json::to_vec(my_leg).context("serializing settle leg")?;
    let (bytes_a, bytes_b) = exchange_bytes(fabric, my_party, &mine).await?;
    let leg_a: SettleLeg =
        serde_json::from_slice(&bytes_a).context("parsing A's settle leg from peer")?;
    let leg_b: SettleLeg =
        serde_json::from_slice(&bytes_b).context("parsing B's settle leg from peer")?;
    ensure!(
        leg_a.is_a && !leg_b.is_a,
        "exchanged legs carry inconsistent roles"
    );
    Ok((leg_a, leg_b))
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
