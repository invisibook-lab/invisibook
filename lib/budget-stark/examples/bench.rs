//! Measures proving, host-side verification and proof size per table size.
//!
//! cargo run --release -p budget-stark --features prover --example bench

use std::time::Instant;

use budget_stark::{
    air::BudgetAir,
    config::{Challenge, LOG_BLOWUP, NUM_QUERIES, QUERY_POW_BITS, Val},
    hash::Random,
    prove, rows_for, verify,
};
use p3_field::{PrimeCharacteristicRing, coset::TwoAdicMultiplicativeCoset};
use p3_fri::FriParameters;
use p3_koala_bear::KoalaBear;
use p3_uni_stark::{
    AirLayout, ConjecturedSecurity, OpeningShape, ProvenSecurity, StarkSecurityParams,
};

/// Security of a proof over `rows` trace rows under the budget config.
fn security(rows: usize) -> (usize, usize) {
    let fri = FriParameters {
        log_blowup: LOG_BLOWUP,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: NUM_QUERIES,
        batch_proof_of_work_bits: 0,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: QUERY_POW_BITS,
        mmcs: (),
    };
    let air = BudgetAir::new();
    let log_rows = rows.trailing_zeros() as usize;
    let params = StarkSecurityParams::from_air::<Val, Challenge, _>(
        fri.security_regime(),
        &air,
        AirLayout::from_air::<Val>(&air),
        TwoAdicMultiplicativeCoset::new(Val::ONE, log_rows).unwrap(),
        // KoalaBear^4.
        124,
        // Keccak digests truncated to 256 bits.
        128,
        2,
        OpeningShape::hiding(4),
        fri.grinding_sites(),
    );
    (
        ConjecturedSecurity::compute_from_params(&params, log_rows).security_bits,
        ProvenSecurity::compute(&params, rows).security_bits(),
    )
}

fn main() {
    println!(
        "{:>6} {:>6} {:>10} {:>10} {:>10} {:>12} {:>9}",
        "n", "rows", "prove", "verify", "proof B", "conjectured", "proven"
    );
    for n in [1usize, 8, 50, 128, 512, 1024] {
        let amounts: Vec<u64> = (0..n as u64).map(|i| 10_000_000_000 + i).collect();
        let randoms: Vec<Random> = (0..n)
            .map(|i| core::array::from_fn(|k| KoalaBear::from_u32((i * 8 + k) as u32 + 1)))
            .collect();

        let t = Instant::now();
        let (prepaid, commitments, proof) = prove(&amounts, &randoms).unwrap();
        let prove_time = t.elapsed();

        let t = Instant::now();
        verify(prepaid, &commitments, &proof).unwrap();
        let verify_time = t.elapsed();

        let (conjectured, proven) = security(rows_for(n));
        println!(
            "{:>6} {:>6} {:>10.2?} {:>10.2?} {:>10} {:>12} {:>9}",
            n,
            rows_for(n),
            prove_time,
            verify_time,
            proof.len(),
            conjectured,
            proven
        );
    }
}
