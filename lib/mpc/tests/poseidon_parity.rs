//! Assert that the MPC Poseidon hasher matches light-poseidon's `new_circom(1)`
//! plaintext output for a range of inputs. This is the hard gate for
//! hash-compatibility with `lib/zk`.

use ark_bn254::Fr;
use light_poseidon::{Poseidon, PoseidonHasher};
use mpc::{CompareStrategy, Fr as MpcFr, PoseidonCfg, run_inprocess};
use rand::{Rng, thread_rng};

/// Plaintext oracle — what lib/zk's Poseidon produces.
fn oracle(x: u64) -> Fr {
    let mut hasher = Poseidon::<Fr>::new_circom(1).unwrap();
    hasher.hash(&[Fr::from(x)]).unwrap()
}

#[test]
fn poseidon_cfg_matches_light_poseidon_plaintext() {
    let cfg = PoseidonCfg::circom_single();
    let cases = [0u64, 1, 2, 100, 1_000_000, u64::MAX / 3, u64::MAX];
    for x in cases {
        let ours = cfg.hash_plain(Fr::from(x));
        let theirs = oracle(x);
        assert_eq!(ours, theirs, "plaintext poseidon mismatch for x={x}");
    }

    let mut rng = thread_rng();
    for _ in 0..16 {
        let x: u64 = rng.gen();
        let ours = cfg.hash_plain(MpcFr::from(x));
        let theirs = oracle(x);
        assert_eq!(ours, theirs, "plaintext poseidon mismatch for random x={x}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn poseidon_in_circuit_matches_plaintext() {
    // End-to-end: run the full circuit with correct hashes and verify both
    // parties see the expected LT result. If Poseidon in-circuit were wrong,
    // the hash check inside the circuit would abort with `HashMismatch`.
    let a: u64 = 42;
    let b: u64 = 100;
    let hash_a = oracle(a);
    let hash_b = oracle(b);

    let out = run_inprocess(a, b, hash_a, hash_b, CompareStrategy::SignBit)
        .await
        .unwrap();
    assert!(out, "42 < 100 should be true");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn poseidon_circuit_rejects_wrong_hash() {
    let a: u64 = 7;
    let b: u64 = 8;
    // Swap the hashes so neither side's hash matches its amount.
    let hash_a = oracle(b);
    let hash_b = oracle(a);
    let err = run_inprocess(a, b, hash_a, hash_b, CompareStrategy::SignBit).await;
    assert!(
        err.is_err(),
        "circuit must reject mismatched hashes, got {err:?}"
    );
}
