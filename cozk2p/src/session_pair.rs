//! The MERGED 2-party settlement session: ONE collaborative proof covers
//! the comparison AND both settlement legs, so the session ends with a
//! chain-ready `SettlePairCoZk2p` payload — no reveal before settlement,
//! no per-side Groth16 settle proofs, no leg exchange.
//!
//! Differences from the split session (`session.rs`):
//!
//! - The output commitments (both payout notes, both residual pairs) are
//!   COMPUTED UNDER MPC and opened: they depend on both parties' secrets
//!   (`fill = min(q_a, q_b)`), and opening a hiding commitment reveals
//!   nothing.
//! - Neither quantity is revealed to anyone before the settlement is
//!   FINAL on chain (stronger than the split flow's F1, which reveals the
//!   smaller opening after the compare anchor). Only after the host
//!   confirms the settlement does the smaller side reveal the fill so the
//!   larger side learns its payout amount and residual opening.
//! - There is no counterparty (npk, r) exchange: the chain mints both
//!   notes from the jointly proven statement, so each side's note secrets
//!   never leave its process at all.
//!
//! Griefing caveat (documented, matches the split flow's post-reveal
//! abort class): a counterparty that vanishes AFTER the on-chain
//! settlement but BEFORE the fill reveal leaves the larger side with a
//! minted-but-unknown-amount payout note. The WAL keeps the session
//! recoverable; the amount can be re-learned only from the counterparty.

use std::fs;

use anyhow::{Context, Result, ensure};
use ark_bn254::G1Projective;
use ark_mpc::{
    MpcFabric, PARTY0, PARTY1,
    algebra::{AuthenticatedScalarResult, Scalar},
};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};

use crate::{
    mpc_compare::compare_three_way,
    mpc_poseidon::poseidon_hash,
    poseidon::{TAG_CM, asset_fr, fr_to_hex},
    prove::ProveTimings,
    prove_pair::{prove_pair_collaborative_timed, verify_settle_pair},
    relation_pair::{PairPublic, PairSidePrivate},
    session::{
        MyOutcome, SessionConfig, SessionInput, SessionWitness, blinding_fr, commitment_fr, hex32,
        input_fingerprint, open_expect_zero, sanity_check_input, scalar_to_u64, scalars_to_sig,
        scale_leg, sig_to_scalars,
    },
};

/// The payload the host app must sign for the merged writing: the full
/// public statement (the order ids the host already knows complete the
/// canonical `SettlePairCoZk2p` message).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NeedSigPair {
    pub cmp: i8,
    pub public: PairPublic,
}

/// The settle artifacts handed to the host: everything the atomic
/// `SettlePairCoZk2p` writing needs. The host MUST submit it and block
/// until the settlement is confirmed on chain; only then does the session
/// continue with the fill reveal.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PairReady {
    pub cmp: i8,
    pub public: PairPublic,
    /// Hex of the ark-compressed merged PLONK proof.
    pub proof_hex: String,
    pub sig_a: String,
    pub sig_b: String,
}

/// Host-side ferry for the merged session. `request_sig` returns this
/// trader's 128-char hex ed25519 signature over the canonical merged
/// settle message. `confirm_settle_onchain` must submit the writing and
/// block until it is confirmed final (or return `Err` to abort — nothing
/// secret has left the process at that point).
pub trait PairSigIo: Send {
    fn request_sig(&mut self, need: &NeedSigPair) -> Result<String>;
    fn confirm_settle_onchain(&mut self, ready: &PairReady) -> Result<()>;
}

/// The merged session's final product.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionResultPair {
    pub cmp: i8,
    pub public: PairPublic,
    pub proof_hex: String,
    pub sig_a: String,
    pub sig_b: String,
    pub my: MyOutcome,
    pub timings: ProveTimings,
    /// Wall-clock spent BLOCKED in `confirm_settle_onchain` (chain
    /// latency, not cryptography).
    #[serde(default)]
    pub onchain_wait_ms: f64,
}

/// Lift a public field element into the fabric's authenticated domain.
fn lift_public(
    fabric: &MpcFabric<G1Projective>,
    v: ark_bn254::Fr,
) -> AuthenticatedScalarResult<G1Projective> {
    Scalar::new(v) * &fabric.one_authenticated()
}

/// The note commitment chain over shares:
/// `P2(P2(P2(P2(TAG_CM, npk), asset), v), r)` with a public asset.
fn mpc_note_commit(
    fabric: &MpcFabric<G1Projective>,
    npk: &AuthenticatedScalarResult<G1Projective>,
    asset: ark_bn254::Fr,
    v: &AuthenticatedScalarResult<G1Projective>,
    r: &AuthenticatedScalarResult<G1Projective>,
) -> AuthenticatedScalarResult<G1Projective> {
    let tag = lift_public(fabric, ark_bn254::Fr::from(TAG_CM));
    let asset = lift_public(fabric, asset);
    let c = poseidon_hash(fabric, &tag, npk);
    let c = poseidon_hash(fabric, &c, &asset);
    let c = poseidon_hash(fabric, &c, v);
    poseidon_hash(fabric, &c, r)
}

/// Open an authenticated share to a plaintext field element.
async fn open_value(
    v: &AuthenticatedScalarResult<G1Projective>,
    what: &str,
) -> Result<ark_bn254::Fr> {
    let opened = v
        .open_authenticated()
        .await
        .map_err(|e| anyhow::anyhow!("{what}: MAC check failed: {e:?}"))?;
    Ok(opened.inner())
}

/// Run the merged settlement session on an established fabric. `my_party`
/// must match `input.role` (PARTY0 for trader-a). Reuses the split
/// session's `SessionInput`; the extra fresh blindings (residuals, note)
/// are drawn inside. `witness.json` is written into `config.out_dir`
/// before the proof is handed to the host, and completed after the
/// post-settlement fill reveal.
pub async fn run_session_pair<F>(
    fabric: MpcFabric<G1Projective>,
    my_party: u64,
    input: &SessionInput,
    sig_io: &mut dyn PairSigIo,
    config: SessionConfig<'_>,
    mut emit: F,
) -> Result<SessionResultPair>
where
    F: FnMut(&str, &str) + Send,
{
    let i_am_a = input.role == "trader-a";
    ensure!(
        (i_am_a && my_party == PARTY0) || (!i_am_a && my_party == PARTY1),
        "role does not match fabric party id"
    );
    sanity_check_input(input)?;
    let i_am_seller = i_am_a == input.a_is_seller;
    let a_is_seller = input.a_is_seller;
    let price = input.price;

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

    // ── Draw my fresh secrets (blindings as canonical Fr bytes) ──
    let mut rng = OsRng;
    let mut draw = || {
        let mut b = [0u8; 32];
        rng.fill_bytes(&mut b);
        let mut canonical = [0u8; 32];
        let be = Scalar::<G1Projective>::new(blinding_fr(&b)).to_bytes_be();
        canonical.copy_from_slice(&be);
        canonical
    };
    let r_q_res = draw();
    let r_locked_res = draw();
    let r_note = draw();
    let recv_npk_fr = commitment_fr(&input.my_recv_npk, "my_recv_npk")?;
    let my_side = PairSidePrivate {
        order_amount: input.my.order_amount,
        r_order: hex32(&input.my.r_order, "r_order")?,
        r_locked: hex32(&input.my.r_locked, "r_locked")?,
        r_q_res,
        r_locked_res,
        recv_npk: recv_npk_fr,
        r_note,
    };

    // ── Share both sides' inputs (canonical order: A's group, then B's) ──
    emit(
        "compare",
        "verifying commitments and comparing amounts in MPC",
    );
    let zero = Scalar::from(0u64);
    let my_vals: Vec<Scalar<G1Projective>> = vec![
        Scalar::from(input.my.order_amount),
        Scalar::new(blinding_fr(&my_side.r_order)),
        Scalar::new(blinding_fr(&my_side.r_locked)),
        Scalar::new(blinding_fr(&r_q_res)),
        Scalar::new(blinding_fr(&r_locked_res)),
        Scalar::new(recv_npk_fr),
        Scalar::new(blinding_fr(&r_note)),
    ];
    let share_group = |owner: u64| -> Vec<AuthenticatedScalarResult<G1Projective>> {
        let vals = if (owner == PARTY0) == i_am_a {
            my_vals.clone()
        } else {
            vec![zero; 7]
        };
        vals.into_iter()
            .map(|v| fabric.share_scalar(v, owner))
            .collect()
    };
    let ga = share_group(PARTY0);
    let gb = share_group(PARTY1);
    let (v_a, r_ord_a, r_lck_a, r_qr_a, r_lr_a, npk_a, r_nt_a) =
        (&ga[0], &ga[1], &ga[2], &ga[3], &ga[4], &ga[5], &ga[6]);
    let (v_b, r_ord_b, r_lck_b, r_qr_b, r_lr_b, npk_b, r_nt_b) =
        (&gb[0], &gb[1], &gb[2], &gb[3], &gb[4], &gb[5], &gb[6]);

    // ── Bind the shared witnesses to the on-chain commitments (early
    //    abort on a lying counterparty, before any expensive phase) ──
    let order_a_pub = Scalar::new(commitment_fr(&input.order_a, "order_a")?);
    let order_b_pub = Scalar::new(commitment_fr(&input.order_b, "order_b")?);
    let bind_a = &poseidon_hash(&fabric, v_a, r_ord_a) - order_a_pub;
    let bind_b = &poseidon_hash(&fabric, v_b, r_ord_b) - order_b_pub;
    open_expect_zero(&bind_a, "order A commitment binding").await?;
    open_expect_zero(&bind_b, "order B commitment binding").await?;

    // Collateral binding: needed = q (seller) or q*price (buyer); the
    // side flags and price are public, so scaling is share-local.
    let needed = |q: &AuthenticatedScalarResult<G1Projective>, is_seller: bool| {
        if is_seller {
            q.clone()
        } else {
            q * Scalar::from(price)
        }
    };
    let needed_a = needed(v_a, a_is_seller);
    let needed_b = needed(v_b, !a_is_seller);
    let locked_a_pub = Scalar::new(commitment_fr(&input.locked_a[0], "locked_a")?);
    let locked_b_pub = Scalar::new(commitment_fr(&input.locked_b[0], "locked_b")?);
    let bind_la = &poseidon_hash(&fabric, &needed_a, r_lck_a) - locked_a_pub;
    let bind_lb = &poseidon_hash(&fabric, &needed_b, r_lck_b) - locked_b_pub;
    open_expect_zero(&bind_la, "collateral A commitment binding").await?;
    open_expect_zero(&bind_lb, "collateral B commitment binding").await?;

    // ── Three-way comparison, opening only cmp ──
    let cmp = compare_three_way(&fabric, v_a, v_b).await?;
    emit("compare", &format!("cmp = {cmp}"));

    // ── Compute the output commitments over shares and open them ──
    emit(
        "outputs",
        "computing payout and residual commitments in MPC",
    );
    // fill = min(q_a, q_b): cmp is public, so the selection is public.
    let fill_share = if cmp >= 0 { v_b.clone() } else { v_a.clone() };
    let q_res_a = v_a - &fill_share;
    let q_res_b = v_b - &fill_share;
    let locked_res_a = needed(&q_res_a, a_is_seller);
    let locked_res_b = needed(&q_res_b, !a_is_seller);
    // The seller receives the token2 leg (fill*price), the buyer the
    // token1 leg (fill).
    let recv_of = |is_seller: bool| {
        if is_seller {
            &fill_share * Scalar::from(price)
        } else {
            fill_share.clone()
        }
    };
    let recv_a = recv_of(a_is_seller);
    let recv_b = recv_of(!a_is_seller);

    let my_recv_asset = asset_fr(&input.my_recv_token)?;
    // Each side's recv asset: mine is input-supplied; the counterparty's
    // is my LOCK token (I pay what I locked).
    let ctr_recv_asset = asset_fr(&input.my_lock_token)?;
    let (asset_recv_a, asset_recv_b) = if i_am_a {
        (my_recv_asset, ctr_recv_asset)
    } else {
        (ctr_recv_asset, my_recv_asset)
    };

    let cm_qr_a = poseidon_hash(&fabric, &q_res_a, r_qr_a);
    let cm_qr_b = poseidon_hash(&fabric, &q_res_b, r_qr_b);
    let cm_lr_a = poseidon_hash(&fabric, &locked_res_a, r_lr_a);
    let cm_lr_b = poseidon_hash(&fabric, &locked_res_b, r_lr_b);
    let cm_note_a = mpc_note_commit(&fabric, npk_a, asset_recv_a, &recv_a, r_nt_a);
    let cm_note_b = mpc_note_commit(&fabric, npk_b, asset_recv_b, &recv_b, r_nt_b);

    let public = PairPublic {
        cmp,
        cm_note_out_a: open_value(&cm_note_a, "payout note A").await?,
        cm_note_out_b: open_value(&cm_note_b, "payout note B").await?,
        cm_q_res_a: open_value(&cm_qr_a, "residual quantity A").await?,
        cm_locked_res_a: open_value(&cm_lr_a, "residual collateral A").await?,
        cm_q_res_b: open_value(&cm_qr_b, "residual quantity B").await?,
        cm_locked_res_b: open_value(&cm_lr_b, "residual collateral B").await?,
        cm_q_a: commitment_fr(&input.order_a, "order_a")?,
        cm_q_b: commitment_fr(&input.order_b, "order_b")?,
        locked_a: commitment_fr(&input.locked_a[0], "locked_a")?,
        locked_b: commitment_fr(&input.locked_b[0], "locked_b")?,
        price,
        a_is_seller,
        asset_recv_a,
        asset_recv_b,
    };

    // ── Signature ferry + in-fabric exchange over the full statement ──
    emit("sig", "requesting settle-pair signature from the host");
    let need = NeedSigPair {
        cmp,
        public: public.clone(),
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

    // ── Collaborative prove of the merged relation + local verify ──
    emit(
        "prove",
        "collaboratively proving compare + both settle legs",
    );
    let (proof, timings) =
        prove_pair_collaborative_timed(fabric.clone(), my_party, &my_side, &public, config.pk)
            .await?;
    emit("verify", "verifying the proof locally before release");
    verify_settle_pair(config.vk, &public, &proof)?;
    let mut proof_bytes = Vec::new();
    ark_serialize::CanonicalSerialize::serialize_compressed(&proof, &mut proof_bytes)
        .context("serializing proof")?;
    let proof_hex = hex::encode(proof_bytes);

    // ── Outcome bookkeeping. The larger side does not know the fill yet
    //    (it is revealed only AFTER settlement finality), so its amounts
    //    stay zero until WAL v2. ──
    let i_am_smaller = cmp == 0 || (cmp == 1) != i_am_a;
    let fill_known = if i_am_smaller {
        Some(input.my.order_amount)
    } else {
        None
    };
    let my_recv_cm = if i_am_a {
        public.cm_note_out_a
    } else {
        public.cm_note_out_b
    };
    let (my_cm_q_res, my_cm_locked_res) = if i_am_a {
        (public.cm_q_res_a, public.cm_locked_res_a)
    } else {
        (public.cm_q_res_b, public.cm_locked_res_b)
    };
    let mut my_outcome = MyOutcome {
        is_a: i_am_a,
        i_am_smaller,
        cmp,
        fill: fill_known.unwrap_or(0),
        recv_amount: fill_known
            .map(|f| scale_leg(f, i_am_seller, price, "receive"))
            .transpose()?
            .unwrap_or(0),
        recv_token: input.my_recv_token.clone(),
        recv_npk: input.my_recv_npk.clone(),
        r_recv: hex::encode(r_note),
        recv_commitment: fr_to_hex(&my_recv_cm),
        // The merged flow never exchanges note secrets: the chain mints
        // both notes from the jointly proven statement.
        ctr_recv_npk: String::new(),
        ctr_r_recv: String::new(),
        ctr_order_amount: 0,
        ctr_r_order: String::new(),
        new_order_amount: 0,
        r_order_new: if i_am_smaller {
            String::new()
        } else {
            hex::encode(r_q_res)
        },
        new_order_commitment: if i_am_smaller {
            String::new()
        } else {
            fr_to_hex(&my_cm_q_res)
        },
        new_locked_amount: 0,
        r_locked_new: if i_am_smaller {
            String::new()
        } else {
            hex::encode(r_locked_res)
        },
        new_locked_commitment: if i_am_smaller {
            String::new()
        } else {
            fr_to_hex(&my_cm_locked_res)
        },
    };
    // Smaller side fully fills: no residuals at all (chain closes it).
    if i_am_smaller {
        my_outcome.new_order_amount = 0;
        my_outcome.new_locked_amount = 0;
    } else {
        // Residual amounts become known after the fill reveal (WAL v2).
    }

    // ── WAL v1: my note secrets on disk BEFORE the proof leaves ──
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

    // ── Anchor: the settlement itself. The host submits the merged
    //    writing and blocks until it is FINAL; abort here reveals nothing
    //    (no quantity has left either process). ──
    let ready = PairReady {
        cmp,
        public: public.clone(),
        proof_hex: proof_hex.clone(),
        sig_a: sig_a.clone(),
        sig_b: sig_b.clone(),
    };
    emit("settle-onchain", "landing the merged settlement on chain");
    let onchain_start = std::time::Instant::now();
    tokio::task::block_in_place(|| sig_io.confirm_settle_onchain(&ready))?;
    let onchain_wait_ms = onchain_start.elapsed().as_secs_f64() * 1e3;

    // ── Post-finality reveal: the smaller side reveals the fill so the
    //    larger side learns its payout amount and residual opening. Bound
    //    to the MPC-verified share (a lying reveal aborts). ──
    if cmp != 0 {
        emit("reveal", "revealing the fill to the larger side");
        let smaller_party = if cmp == 1 { PARTY1 } else { PARTY0 };
        let reveal_mine = my_party == smaller_party;
        let payload: Vec<Scalar<G1Projective>> = if reveal_mine {
            vec![Scalar::from(input.my.order_amount)]
        } else {
            vec![zero]
        };
        let revealed: Vec<Scalar<G1Projective>> =
            fabric.share_plaintext(payload, smaller_party).await;
        ensure!(revealed.len() == 1, "malformed reveal payload from peer");
        let diff = &fill_share - revealed[0];
        open_expect_zero(&diff, "fill reveal consistency").await?;

        if !reveal_mine {
            let fill = scalar_to_u64(&revealed[0], "revealed fill")?;
            my_outcome.fill = fill;
            my_outcome.recv_amount = scale_leg(fill, i_am_seller, price, "receive")?;
            let remainder = input.my.order_amount - fill;
            my_outcome.new_order_amount = remainder;
            my_outcome.new_locked_amount = scale_leg(remainder, !i_am_seller, price, "new locked")?;
        }
    }

    // ── WAL v2: complete ──
    write_wal(&my_outcome)?;

    Ok(SessionResultPair {
        cmp,
        public,
        proof_hex,
        sig_a,
        sig_b,
        my: my_outcome,
        timings,
        onchain_wait_ms,
    })
}
