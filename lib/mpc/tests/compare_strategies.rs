//! Correctness tests for each of the three comparison strategies across a
//! matrix of edge-case `(a, b)` pairs.

use ark_bn254::Fr;
use light_poseidon::{Poseidon, PoseidonHasher};
use mpc::{CompareStrategy, run_inprocess};

fn oracle(x: u64) -> Fr {
    Poseidon::<Fr>::new_circom(1)
        .unwrap()
        .hash(&[Fr::from(x)])
        .unwrap()
}

async fn check(strategy: CompareStrategy, a: u64, b: u64) {
    let got = run_inprocess(a, b, oracle(a), oracle(b), strategy)
        .await
        .unwrap();
    let want = a < b;
    assert_eq!(
        got, want,
        "strategy={strategy:?} a={a} b={b}: want {want}, got {got}"
    );
}

async fn run_matrix(strategy: CompareStrategy) {
    // Edge cases spanning both endpoints of u64 plus typical values.
    let cases: &[(u64, u64)] = &[
        (0, 0),
        (0, 1),
        (1, 0),
        (1, 1),
        (5, 10),
        (10, 5),
        (u64::MAX, 0),
        (0, u64::MAX),
        ((1u64 << 63) - 1, 1u64 << 63),
        (1u64 << 63, (1u64 << 63) - 1),
        (u64::MAX, u64::MAX),
    ];
    for (a, b) in cases.iter().copied() {
        check(strategy, a, b).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bit_direct_matrix() {
    run_matrix(CompareStrategy::BitDirect).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sign_bit_matrix() {
    run_matrix(CompareStrategy::SignBit).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn prefix_or_matrix() {
    run_matrix(CompareStrategy::PrefixOr).await;
}
