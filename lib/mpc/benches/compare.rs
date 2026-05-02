//! Compare wall-clock latency of the three SPDZ comparison strategies.
//!
//! This is a relative benchmark: all three strategies run on the same
//! in-process tokio duplex fabric, so the numbers reflect gate count +
//! round complexity rather than real network cost.

use ark_bn254::Fr;
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use light_poseidon::{Poseidon, PoseidonHasher};
use mpc::{CompareStrategy, run_inprocess};

fn oracle(x: u64) -> Fr {
    Poseidon::<Fr>::new_circom(1)
        .unwrap()
        .hash(&[Fr::from(x)])
        .unwrap()
}

fn bench_strategies(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let a = 1_234_567u64;
    let b = 7_654_321u64;
    let hash_a = oracle(a);
    let hash_b = oracle(b);

    let mut g = c.benchmark_group("compare");
    g.sample_size(20); // MPC runs take ~tens of ms; keep the loop short.

    for &s in &[
        CompareStrategy::BitDirect,
        CompareStrategy::SignBit,
        CompareStrategy::PrefixOr,
    ] {
        g.bench_with_input(
            BenchmarkId::from_parameter(format!("{s:?}")),
            &s,
            |bencher, &s| {
                bencher
                    .to_async(&rt)
                    .iter(|| async move { run_inprocess(a, b, hash_a, hash_b, s).await.unwrap() });
            },
        );
    }
    g.finish();
}

criterion_group!(benches, bench_strategies);
criterion_main!(benches);
