//! End-to-end test of the MERGED settlement session
//! (`session_pair::run_session_pair`): two traders over a mock MPC fabric
//! bind their witnesses, compare, compute the payout/residual commitments
//! under MPC, jointly prove the merged relation, "land" the settlement
//! (no-op ferry), and complete the post-finality fill reveal.

use std::{fs, path::PathBuf};

use anyhow::Result;
use ark_mpc::{PARTY0, test_helpers::execute_mock_mpc};
use ark_serialize::CanonicalDeserialize;
use cozk2p::{
    dev_keys_pair,
    poseidon::{commit, fr_to_hex},
    session::{MyPrivate, SessionConfig, SessionInput},
    session_pair::{NeedSigPair, PairReady, PairSigIo, run_session_pair},
    verify_settle_pair,
};
use mpc_plonk::proof_system::structs::Proof;

const SIG_A: &str = "aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11\
                     aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11";
const SIG_B: &str = "bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22\
                     bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22";

/// Test ferry: fixed signature, records the signed payload, confirms the
/// settlement without a chain.
struct TestPairSigIo {
    sig: &'static str,
    seen: Option<NeedSigPair>,
    confirmed: Option<PairReady>,
}

impl PairSigIo for TestPairSigIo {
    fn request_sig(&mut self, need: &NeedSigPair) -> Result<String> {
        self.seen = Some(need.clone());
        Ok(self.sig.to_string())
    }

    fn confirm_settle_onchain(&mut self, ready: &PairReady) -> Result<()> {
        self.confirmed = Some(ready.clone());
        Ok(())
    }
}

/// The sample trade: A (maker) sells 80 token1 at price 3 (locks 80), B
/// buys 60 (locks 180). cmp = 1, fill = 60; A receives 180 USDT and keeps
/// 20 on the book; B receives 60 ETH and closes. Locked-only model: each
/// order's collateral commitment is its ONLY on-chain commitment.
fn inputs() -> (SessionInput, SessionInput) {
    let price = 3u64;
    let locked_a = fr_to_hex(&commit(80, &[0xA3; 32]));
    let locked_b = fr_to_hex(&commit(180, &[0xB3; 32]));

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
        my_lock_token: if role == "trader-a" { "ETH" } else { "USDT" }.into(),
        my_recv_token: if role == "trader-a" { "USDT" } else { "ETH" }.into(),
        price,
        a_is_seller: true,
        locked_a: locked_a.clone(),
        locked_b: locked_b.clone(),
        my_recv_npk: npk_hex(if role == "trader-a" { 0x51 } else { 0x52 }),
        my,
    };
    let a = base(
        "trader-a",
        MyPrivate {
            order_amount: 80,
            r_locked: hex::encode([0xA3u8; 32]),
        },
    );
    let b = base(
        "trader-b",
        MyPrivate {
            order_amount: 60,
            r_locked: hex::encode([0xB3u8; 32]),
        },
    );
    (a, b)
}

fn out_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "cozk2p-session-pair-test-{}-{tag}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    dir
}

#[tokio::test(flavor = "multi_thread")]
async fn merged_session_happy_path() {
    let (input_a, input_b) = inputs();
    let (pk, vk) = dev_keys_pair(&cozk2p::default_cache_dir()).unwrap();
    let dir_a = out_dir("a");
    let dir_b = out_dir("b");

    let (res_a, res_b) = execute_mock_mpc(|fabric| {
        let (input_a, input_b, pk, vk) = (input_a.clone(), input_b.clone(), pk.clone(), vk.clone());
        let (dir_a, dir_b) = (dir_a.clone(), dir_b.clone());
        async move {
            let party = fabric.party_id();
            let i_am_a = party == PARTY0;
            let (input, dir, sig) = if i_am_a {
                (input_a, dir_a, SIG_A)
            } else {
                (input_b, dir_b, SIG_B)
            };
            let mut sig_io = TestPairSigIo {
                sig,
                seen: None,
                confirmed: None,
            };
            let result = run_session_pair(
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
            .expect("merged session must succeed on the honest sample trade");
            (result, sig_io.seen, sig_io.confirmed)
        }
    })
    .await;
    let (result_a, need_a, confirmed_a) = res_a;
    let (result_b, need_b, confirmed_b) = res_b;

    // Identical statement, proof, and signatures on both sides.
    assert_eq!(result_a.cmp, 1);
    assert_eq!(result_b.cmp, 1);
    assert_eq!(
        serde_json::to_string(&result_a.public).unwrap(),
        serde_json::to_string(&result_b.public).unwrap()
    );
    assert_eq!(result_a.proof_hex, result_b.proof_hex);
    assert_eq!(result_a.sig_a, SIG_A);
    assert_eq!(result_b.sig_b, SIG_B);

    // The signed payload covered the full statement, and the confirmed
    // payload carried the same proof.
    assert_eq!(need_a.expect("A must sign").public.cmp, 1);
    assert_eq!(need_b.expect("B must sign").public.cmp, 1);
    assert_eq!(
        confirmed_a.expect("A must confirm").proof_hex,
        result_a.proof_hex
    );
    assert_eq!(
        confirmed_b.expect("B must confirm").proof_hex,
        result_b.proof_hex
    );

    // The revealed proof verifies as a standard single-prover PLONK proof.
    let proof_bytes = hex::decode(&result_a.proof_hex).unwrap();
    let proof = Proof::deserialize_compressed(proof_bytes.as_slice()).unwrap();
    verify_settle_pair(&vk, &result_a.public, &proof).expect("merged proof must verify");

    // Post-reveal outcomes: A (larger, seller) learned the fill and its
    // payout; B (smaller, buyer) knew everything all along.
    assert!(!result_a.my.i_am_smaller);
    assert_eq!(result_a.my.fill, 60);
    assert_eq!(result_a.my.recv_amount, 180); // 60 * price 3, USDT leg
    assert_eq!(result_a.my.new_order_amount, 20);
    assert_eq!(result_a.my.new_locked_amount, 20); // seller residual, token1
    assert!(result_b.my.i_am_smaller);
    assert_eq!(result_b.my.fill, 60);
    assert_eq!(result_b.my.recv_amount, 60); // ETH leg
    assert_eq!(result_b.my.new_locked_amount, 0);
    assert_eq!(result_b.my.new_locked_commitment, "");

    // The merged flow never exchanges note secrets and never reveals the
    // counterparty's opening.
    assert_eq!(result_a.my.ctr_recv_npk, "");
    assert_eq!(result_b.my.ctr_recv_npk, "");
    assert_eq!(result_a.my.ctr_order_amount, 0);
    assert_eq!(result_a.my.ctr_r_locked, "");

    // A's residual COLLATERAL opening matches the opened public commitment
    // (the only re-commitment in the locked-only model).
    let hex32 = |s: &str| -> [u8; 32] {
        let raw = hex::decode(s).unwrap();
        let mut out = [0u8; 32];
        out.copy_from_slice(&raw);
        out
    };
    assert_eq!(
        result_a.my.new_locked_commitment,
        fr_to_hex(&commit(20, &hex32(&result_a.my.r_locked_new)))
    );
    assert_eq!(
        result_a.my.new_locked_commitment,
        fr_to_hex(&result_a.public.cm_locked_res_a)
    );

    // Both WALs exist and are complete (v2: amounts filled in), and carry
    // NO residual-quantity commitment fields.
    for (dir, expect_recv) in [(&dir_a, 180u64), (&dir_b, 60u64)] {
        let raw = fs::read_to_string(dir.join("witness.json")).expect("witness.json must exist");
        let w: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(w["my"]["recv_amount"].as_u64().unwrap(), expect_recv);
        let my = w["my"].as_object().unwrap();
        assert!(
            !my.contains_key("new_order_commitment") && !my.contains_key("r_order_new"),
            "no residual quantity commitment may exist in the WAL"
        );
    }
}
