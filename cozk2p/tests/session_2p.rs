//! End-to-end tests of the full settlement session (`session::run_session`):
//! two traders over a mock MPC fabric run comparison, reveal, output
//! exchange, signature ferry, collaborative prove, and local verify —
//! producing identical, independently verifiable results.

use std::{fs, path::PathBuf};

use anyhow::Result;
use ark_ff::PrimeField;
use ark_mpc::{PARTY0, algebra::Scalar, test_helpers::execute_mock_mpc};
use ark_serialize::CanonicalDeserialize;
use cozk2p::{
    dev_keys,
    poseidon::{commit, fr_to_hex},
    session::{LockedCash, MyPrivate, NeedSig, SessionConfig, SessionInput, SigIo, run_session},
    verify_settle,
};
use mpc_plonk::proof_system::structs::Proof;

/// Fixed dummy signatures: content is opaque to the session (the app layer
/// verifies real ed25519 signatures); the session only ferries them.
const SIG_A: &str = "aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11\
                     aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11";
const SIG_B: &str = "bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22\
                     bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22";

/// Test ferry returning a fixed signature and recording the request.
struct TestSigIo {
    sig: &'static str,
    seen: Option<NeedSig>,
}

impl SigIo for TestSigIo {
    fn request_sig(&mut self, need: &NeedSig) -> Result<String> {
        self.seen = Some(need.clone());
        Ok(self.sig.to_string())
    }
}

/// The sample trade: A (maker) sells 80 token1 at price 3, B buys 60.
/// cmp = 1, fill = 60; A keeps 20 on the book and receives 180 token2.
fn inputs() -> (SessionInput, SessionInput) {
    let price = 3u64;
    let order_a = fr_to_hex(&commit(80, &[0xA1; 32]));
    let order_b = fr_to_hex(&commit(60, &[0xB1; 32]));
    let zero = fr_to_hex(&commit(0, &[0u8; 32]));
    let locked_a = [fr_to_hex(&commit(80, &[0xA3; 32])), zero.clone()];
    let locked_b = [fr_to_hex(&commit(180, &[0xB3; 32])), zero];

    let npk_hex = |seed: u8| fr_to_hex(&commit(seed as u64, &[seed; 32]));
    let base = |role: &str, my: MyPrivate| SessionInput {
        role: role.to_string(),
        order_a_id: "order-a".into(),
        order_b_id: "order-b".into(),
        my_order_id: if role == "trader-a" {
            "order-a".into()
        } else {
            "order-b".into()
        },
        my_input_cash_ids: vec![format!("{role}-cash")],
        my_lock_token: if role == "trader-a" { "ETH" } else { "USDT" }.into(),
        my_recv_token: if role == "trader-a" { "USDT" } else { "ETH" }.into(),
        price,
        a_is_seller: true,
        order_a: order_a.clone(),
        order_b: order_b.clone(),
        locked_a: locked_a.clone(),
        locked_b: locked_b.clone(),
        my_recv_npk: npk_hex(if role == "trader-a" { 0x51 } else { 0x52 }),
        my,
    };
    let a = base(
        "trader-a",
        MyPrivate {
            order_amount: 80,
            r_order: hex::encode([0xA1u8; 32]),
            locked: vec![LockedCash {
                amount: 80,
                random: hex::encode([0xA3u8; 32]),
            }],
        },
    );
    let b = base(
        "trader-b",
        MyPrivate {
            order_amount: 60,
            r_order: hex::encode([0xB1u8; 32]),
            locked: vec![LockedCash {
                amount: 180,
                random: hex::encode([0xB3u8; 32]),
            }],
        },
    );
    (a, b)
}

/// Unique per-party scratch dir for witness/result files.
fn out_dir(tag: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("cozk2p-session-test-{}-{tag}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    dir
}

/// The full happy path: both parties end with identical results, the proof
/// verifies, and every plaintext outcome opens its commitment.
#[tokio::test(flavor = "multi_thread")]
async fn session_happy_path() {
    let (input_a, input_b) = inputs();
    let (pk, vk) = dev_keys(&cozk2p::default_cache_dir()).unwrap();
    let dir_a = out_dir("a");
    let dir_b = out_dir("b");

    let (res_a, res_b) = execute_mock_mpc(|fabric| {
        let (input_a, input_b, pk, vk) = (input_a.clone(), input_b.clone(), pk.clone(), vk.clone());
        let (dir_a, dir_b) = (dir_a.clone(), dir_b.clone());
        async move {
            let party = fabric.party_id();
            let (input, dir, sig) = if party == PARTY0 {
                (input_a, dir_a, SIG_A)
            } else {
                (input_b, dir_b, SIG_B)
            };
            let mut sig_io = TestSigIo { sig, seen: None };
            let result = run_session(
                fabric.clone(),
                party,
                &input,
                &mut sig_io,
                SessionConfig {
                    pk: &pk,
                    vk: &vk,
                    out_dir: &dir,
                },
                |_, _| {},
            )
            .await
            .expect("session must succeed on the honest sample trade");
            (result, sig_io.seen)
        }
    })
    .await;
    let (result_a, need_a) = res_a;
    let (result_b, need_b) = res_b;

    // Identical public statement, proof, and signatures on both sides.
    assert_eq!(result_a.cmp, 1);
    assert_eq!(result_b.cmp, 1);
    assert_eq!(
        serde_json::to_string(&result_a.public).unwrap(),
        serde_json::to_string(&result_b.public).unwrap()
    );
    assert_eq!(result_a.proof_hex, result_b.proof_hex);
    assert_eq!(result_a.sig_a, SIG_A);
    assert_eq!(result_a.sig_b, SIG_B);
    assert_eq!(result_b.sig_a, SIG_A);
    assert_eq!(result_b.sig_b, SIG_B);

    // The signed payloads matched the comparison on both sides.
    assert_eq!(need_a.expect("A must have been asked to sign").cmp, 1);
    assert_eq!(need_b.expect("B must have been asked to sign").cmp, 1);

    // The proof round-trips through the on-chain wire format and verifies.
    let proof_bytes = hex::decode(&result_a.proof_hex).unwrap();
    let proof = Proof::deserialize_compressed(proof_bytes.as_slice()).unwrap();
    verify_settle(&vk, &result_a.public, &proof).expect("proof must verify");

    // Plaintext outcomes per the sample trade: A (larger) receives 180
    // USDT and keeps 20 on the book; B (smaller) receives 60 ETH and got
    // A's revealed... no — B is smaller, so B REVEALED and A holds B's
    // opening. Each side's incoming payout is a NOTE commitment under its
    // own fresh npk.
    use cozk2p::poseidon::{asset_fr, note_commit};
    let open_note = |npk_hex: &str, token: &str, amount: u64, r_hex: &str, expected: &str| {
        let npk = ark_bn254::Fr::from_be_bytes_mod_order(&hex::decode(npk_hex).unwrap());
        let mut r = [0u8; 32];
        r.copy_from_slice(&hex::decode(r_hex).unwrap());
        let cm = note_commit(npk, asset_fr(token).unwrap(), amount, &r);
        assert_eq!(fr_to_hex(&cm), expected);
    };
    // A: larger side.
    assert!(!result_a.my.i_am_smaller);
    assert_eq!(result_a.my.fill, 60);
    assert_eq!(result_a.my.recv_amount, 180);
    assert_eq!(result_a.my.new_order_amount, 20);
    assert_eq!(result_a.my.new_locked_amount, 20);
    assert_eq!(
        result_a.my.ctr_order_amount, 60,
        "A holds B's revealed opening"
    );
    open_note(
        &result_a.my.recv_npk,
        "USDT",
        180,
        &result_a.my.r_recv,
        &result_a.my.recv_commitment,
    );
    // B: smaller side, fully filled, no residuals.
    assert!(result_b.my.i_am_smaller);
    assert_eq!(result_b.my.recv_amount, 60);
    assert_eq!(result_b.my.new_order_amount, 0);
    assert_eq!(result_b.my.ctr_order_amount, 0);
    open_note(
        &result_b.my.recv_npk,
        "ETH",
        60,
        &result_b.my.r_recv,
        &result_b.my.recv_commitment,
    );
    // The exchanged payout-note pairs crossed correctly: what A holds as
    // the counterparty pair is B's own (npk, r) and vice versa.
    assert_eq!(result_a.my.ctr_recv_npk, result_b.my.recv_npk);
    assert_eq!(result_a.my.ctr_r_recv, result_b.my.r_recv);
    assert_eq!(result_b.my.ctr_recv_npk, result_a.my.recv_npk);
    assert_eq!(result_b.my.ctr_r_recv, result_a.my.r_recv);

    // The witness WAL landed on disk for both parties, consistent with the
    // final result.
    for (dir, result) in [(&dir_a, &result_a), (&dir_b, &result_b)] {
        let witness: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(dir.join("witness.json")).unwrap()).unwrap();
        assert_eq!(witness["cmp"], 1);
        assert_eq!(
            witness["my"]["recv_commitment"].as_str().unwrap(),
            result.my.recv_commitment
        );
    }

    let _ = fs::remove_dir_all(&dir_a);
    let _ = fs::remove_dir_all(&dir_b);
}

/// Divergent chain reads (here: B holds a tampered order_a) must abort at
/// the fingerprint preamble on both sides, before any secret is shared.
#[tokio::test(flavor = "multi_thread")]
async fn session_aborts_on_divergent_statement() {
    let (input_a, mut input_b) = inputs();
    // B read a different (stale/tampered) order_a commitment.
    input_b.order_a = fr_to_hex(&commit(81, &[0xA1; 32]));
    let (pk, vk) = dev_keys(&cozk2p::default_cache_dir()).unwrap();
    let dir_a = out_dir("tamper-a");
    let dir_b = out_dir("tamper-b");

    let (err_a, err_b) = execute_mock_mpc(|fabric| {
        let (input_a, input_b, pk, vk) = (input_a.clone(), input_b.clone(), pk.clone(), vk.clone());
        let (dir_a, dir_b) = (dir_a.clone(), dir_b.clone());
        async move {
            let party = fabric.party_id();
            let (input, dir, sig) = if party == PARTY0 {
                (input_a, dir_a, SIG_A)
            } else {
                (input_b, dir_b, SIG_B)
            };
            let mut sig_io = TestSigIo { sig, seen: None };
            let result = run_session(
                fabric.clone(),
                party,
                &input,
                &mut sig_io,
                SessionConfig {
                    pk: &pk,
                    vk: &vk,
                    out_dir: &dir,
                },
                |_, _| {},
            )
            .await;
            (result.err().map(|e| e.to_string()), sig_io.seen)
        }
    })
    .await;

    for (err, seen) in [err_a, err_b] {
        let msg = err.expect("both parties must abort");
        assert!(
            msg.contains("different on-chain statements"),
            "unexpected error: {msg}"
        );
        assert!(seen.is_none(), "no signature must ever be requested");
    }
    let _ = fs::remove_dir_all(&dir_a);
    let _ = fs::remove_dir_all(&dir_b);
}

/// The reveal-consistency mechanism: a plaintext reveal that disagrees with
/// the MPC-shared value opens non-zero and is detected by both parties.
#[tokio::test(flavor = "multi_thread")]
async fn lying_reveal_opens_nonzero() {
    let (r0, r1) = execute_mock_mpc(|fabric| async move {
        let party = fabric.party_id();
        // A's MPC-verified amount is 60...
        let v = fabric.share_scalar(Scalar::from(60u64), PARTY0);
        // ...but A reveals 61 in plaintext.
        let lie = if party == PARTY0 {
            Scalar::from(61u64)
        } else {
            Scalar::from(0u64)
        };
        let revealed: Scalar<_> = fabric.share_plaintext(lie, PARTY0).await;
        let diff = &v - &revealed;
        diff.open_authenticated()
            .await
            .expect("MAC check itself passes; the VALUE is what lies")
    })
    .await;
    assert_ne!(r0, Scalar::from(0u64), "the lie must be visible to party 0");
    assert_ne!(r1, Scalar::from(0u64), "the lie must be visible to party 1");
}
