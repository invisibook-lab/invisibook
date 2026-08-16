pragma circom 2.2.3;

include "utils/poseidon.circom";
include "utils/bitify.circom";
include "utils/comparators.circom";

// SettleCmp — the paper's π_cmp as a single-prover Groth16 circuit (the
// collaborative twin is cozk2p's PLONK relation; both prove the IDENTICAL
// 3-public statement, so the chain accepts either):
//
//   the values opening the two on-chain order commitments compare as the
//   public `cmp = sign(a − b)` claims.
//
// Public: [cmp, order_a_commitment, order_b_commitment]
// Private: a, r_a, b, r_b (each side's quantity and blinding).
//
// Everything AFTER the comparison — payouts, residual re-commitments — is
// single-party work (settle_small.circom / settle_large.circom): once cmp
// is public and the smaller side reveals its opening over the settlement
// channel, each party holds its complete witness alone.
template SettleCmp() {
    signal input cmp;
    signal input order_a_commitment;
    signal input order_b_commitment;

    signal input a;
    signal input r_a;
    signal input b;
    signal input r_b;

    // 64-bit ranges make the comparison an integer comparison.
    component a_range = Num2Bits(64);
    a_range.in <== a;
    component b_range = Num2Bits(64);
    b_range.in <== b;

    // The compared values are exactly the committed quantities
    // (paper Property 1(i): input legitimacy).
    signal ha <== Poseidon(2)([a, r_a]);
    ha === order_a_commitment;
    signal hb <== Poseidon(2)([b, r_b]);
    hb === order_b_commitment;

    // cmp = (a > b) − (a < b) ∈ {−1, 0, 1}.
    component lt = LessThan(64);
    lt.in[0] <== a;
    lt.in[1] <== b;
    component gt = LessThan(64);
    gt.in[0] <== b;
    gt.in[1] <== a;
    cmp === gt.out - lt.out;
}

component main {public [cmp, order_a_commitment, order_b_commitment]} = SettleCmp();
