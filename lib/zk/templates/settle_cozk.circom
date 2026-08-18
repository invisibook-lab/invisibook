pragma circom 2.2.3;

include "utils/poseidon.circom";
include "utils/bitify.circom";
include "utils/comparators.circom";

// SettleCmp — the paper's π_cmp as a single-prover Groth16 circuit (the
// collaborative twin is cozk2p's PLONK relation; both prove the IDENTICAL
// 5-public statement, so the chain accepts either):
//
//   the quantities that back the two on-chain COLLATERAL commitments
//   compare as the public `cmp = sign(q_a − q_b)` claims.
//
// LOCKED-ONLY MODEL: orders commit only their collateral
// `locked = P2(needed, r)` with the side-dependent equation
//   needed(q, p, s) = q·p + s·(q − q·p)   (sell locks q, buy q·p).
// The equation is injective in q for price > 0, so opening each
// collateral against its in-circuit `needed` pins the compared
// quantities (input legitimacy). price and a_is_seller therefore enter
// the statement.
//
// Crossing orders use their own public collateral prices; execution price
// is irrelevant to quantity comparison.
// Public: [cmp, locked_a, locked_b, price_a, price_b, a_is_seller]
// Private: q_a, r_a, q_b, r_b (each side's quantity and collateral
// blinding).
template SettleCmp() {
    signal input cmp;
    signal input locked_a;
    signal input locked_b;
    signal input price_a;
    signal input price_b;
    signal input a_is_seller;

    signal input q_a;
    signal input r_a;
    signal input q_b;
    signal input r_b;

    // `price` and `a_is_seller` are PUBLIC inputs the chain builds itself
    // (a u64 execution price and a 0/1 side flag read off the order rows),
    // so they are not re-checked in-circuit: a prover cannot lie about a
    // public input and a verifier cannot supply an out-of-range one. Same
    // policy the statement already applies to cmp's encoding.
    //
    // The quantities ARE witnesses: their 64-bit ranges make the comparison
    // an integer comparison and the collateral products integer-exact.
    component a_range = Num2Bits(64);
    a_range.in <== q_a;
    component b_range = Num2Bits(64);
    b_range.in <== q_b;

    // The compared quantities back the on-chain collateral commitments;
    // A and B are on opposite sides.
    signal qa_price <== q_a * price_a;
    signal needed_a <== qa_price + a_is_seller * (q_a - qa_price);
    signal ha <== Poseidon(2)([needed_a, r_a]);
    ha === locked_a;

    signal b_is_seller <== 1 - a_is_seller;
    signal qb_price <== q_b * price_b;
    signal needed_b <== qb_price + b_is_seller * (q_b - qb_price);
    signal hb <== Poseidon(2)([needed_b, r_b]);
    hb === locked_b;

    // cmp = (q_a > q_b) − (q_a < q_b) ∈ {−1, 0, 1}.
    component lt = LessThan(64);
    lt.in[0] <== q_a;
    lt.in[1] <== q_b;
    component gt = LessThan(64);
    gt.in[0] <== q_b;
    gt.in[1] <== q_a;
    cmp === gt.out - lt.out;
}

component main {public [cmp, locked_a, locked_b, price_a, price_b, a_is_seller]} = SettleCmp();
