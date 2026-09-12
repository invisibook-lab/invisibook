pragma circom 2.2.3;

include "utils/bitify.circom";
include "utils/comparators.circom";
include "utils/poseidon.circom";
include "commitments.circom";

// SettleCoZk is the joint settlement circuit for a matched order pair, proven
// COLLABORATIVELY by both traders via MPC (co-snarks REP3): trader A supplies
// the a-side private signals, trader B the b-side, and neither learns the
// other's amounts. `a` and `b` are both denominated in token1 quantity
// (Order.Amount commits token1 qty for buy and sell alike), so they compare
// directly; all cross-token arithmetic goes through the public `price`.
//
// The updated commitments depend on both parties' secrets (e.g. the remainder
// a' = a - min(a, b)), so they are public OUTPUTS computed in-circuit rather
// than inputs: only the blinding factors are (per-party) private inputs.
//
// Witness/public-signal order (outputs first, then public inputs — this is the
// exact vector the chain rebuilds for Groth16 verification):
//   [cmp, new_order_a, new_order_b, new_locked_a, new_locked_b,
//    recv_a, recv_b,
//    order_a_commitment, order_b_commitment, price, a_is_seller,
//    locked_a_hashes[N], locked_b_hashes[N]]
template SettleCoZk(N) {
    // ── Public outputs (computed under MPC, opened with the proof) ──
    signal output cmp;                       // sign(a - b): -1 / 0 / 1 as field element
    signal output new_order_a_commitment;    // Poseidon(a', r_a_new); ignored by chain when A fully fills
    signal output new_order_b_commitment;    // Poseidon(b', r_b_new); ignored when B fully fills
    signal output new_locked_a_commitment;   // A's remainder collateral commitment
    signal output new_locked_b_commitment;   // B's remainder collateral commitment
    signal output recv_a_commitment;         // A's received cash commitment
    signal output recv_b_commitment;         // B's received cash commitment

    // ── Public inputs (known from on-chain state before the MPC) ──
    signal input order_a_commitment;         // on-chain orderA.Amount = Poseidon(a, r_a)
    signal input order_b_commitment;         // on-chain orderB.Amount = Poseidon(b, r_b)
    signal input price;                      // execution price (maker's), plaintext u64
    signal input a_is_seller;                // 1 if A sells token1 (locks token1); B is the opposite side
    signal input locked_a_hashes[N];         // A's locked cash commitments (zero-commit padded)
    signal input locked_b_hashes[N];         // B's locked cash commitments (zero-commit padded)

    // ── Private inputs, a-side (trader A only) ──
    signal input a;                          // A's order token1 quantity
    signal input r_a;                        // blinding of order_a_commitment
    signal input r_a_new;                    // fresh blinding for the remainder order commitment
    signal input locked_a_amounts[N];
    signal input locked_a_randomness[N];
    signal input r_locked_a_new;             // fresh blinding for the remainder collateral cash
    signal input r_recv_a;                   // fresh blinding for A's received cash

    // ── Private inputs, b-side (trader B only) ──
    signal input b;
    signal input r_b;
    signal input r_b_new;
    signal input locked_b_amounts[N];
    signal input locked_b_randomness[N];
    signal input r_locked_b_new;
    signal input r_recv_b;

    // 1) a_is_seller must be a boolean; price must fit u64 (defends the
    //    products below against field wrap)
    a_is_seller * (a_is_seller - 1) === 0;
    component price_bits = Num2Bits(64);
    price_bits.in <== price;

    // 2) Open both order-amount commitments and range check the amounts
    component a_bits = Num2Bits(64);
    a_bits.in <== a;
    component b_bits = Num2Bits(64);
    b_bits.in <== b;
    signal expected_order_a <== Poseidon(2)([a, r_a]);
    expected_order_a === order_a_commitment;
    signal expected_order_b <== Poseidon(2)([b, r_b]);
    expected_order_b === order_b_commitment;

    // 3) Three-way comparison cmp = sign(a - b) ∈ {-1, 0, 1}
    //    (safe: a and b are 64-bit range-checked above)
    signal lt <== LessThan(64)([a, b]);
    signal eq <== IsEqual()([a, b]);
    signal gt <== 1 - lt - eq;
    cmp <== gt - lt;

    // 4) Fill and remainders: fill_t1 = min(a, b), a' = a - fill_t1,
    //    b' = b - fill_t1 — equivalent to the protocol rules
    //    a' = (a < b) ? 0 : a - b and b' = (b < a) ? 0 : b - a.
    signal fill_t1 <== b + lt * (a - b);
    signal a_prime <== a - fill_t1;
    signal b_prime <== b - fill_t1;

    // 5) Bind the remainder order amounts to fresh commitments
    new_order_a_commitment <== Poseidon(2)([a_prime, r_a_new]);
    new_order_b_commitment <== Poseidon(2)([b_prime, r_b_new]);

    // 6) Open both parties' locked collateral (Poseidon open + 64-bit range
    //    per slot) and require it to exactly back the order:
    //    token1 qty for the seller, token1 qty * price (token2) for the buyer.
    component ins_a = VerifyAmounts(N);
    component ins_b = VerifyAmounts(N);
    for (var i = 0; i < N; i++) {
        ins_a.amounts[i] <== locked_a_amounts[i];
        ins_a.randomness[i] <== locked_a_randomness[i];
        ins_a.hashes[i] <== locked_a_hashes[i];
        ins_b.amounts[i] <== locked_b_amounts[i];
        ins_b.randomness[i] <== locked_b_randomness[i];
        ins_b.hashes[i] <== locked_b_hashes[i];
    }
    signal a_times_price <== a * price;
    signal locked_a_needed <== a_times_price + a_is_seller * (a - a_times_price);
    ins_a.sum === locked_a_needed;
    signal b_times_price <== b * price;
    signal locked_b_needed <== b_times_price + (1 - a_is_seller) * (b - b_times_price);
    ins_b.sum === locked_b_needed;

    // 7) UTXO updates. fill_t2 is the token2 leg; it and both remainder
    //    collateral amounts are range-checked to u64 so every minted cash is
    //    spendable by the 64-bit wallet circuits later.
    signal fill_t2 <== fill_t1 * price;
    component fill_t2_bits = Num2Bits(64);
    fill_t2_bits.in <== fill_t2;

    signal a_prime_times_price <== a_prime * price;
    signal a_new_locked <== a_prime_times_price + a_is_seller * (a_prime - a_prime_times_price);
    component a_new_locked_bits = Num2Bits(64);
    a_new_locked_bits.in <== a_new_locked;
    new_locked_a_commitment <== Poseidon(2)([a_new_locked, r_locked_a_new]);

    signal b_prime_times_price <== b_prime * price;
    signal b_new_locked <== b_prime_times_price + (1 - a_is_seller) * (b_prime - b_prime_times_price);
    component b_new_locked_bits = Num2Bits(64);
    b_new_locked_bits.in <== b_new_locked;
    new_locked_b_commitment <== Poseidon(2)([b_new_locked, r_locked_b_new]);

    // The seller receives the token2 leg, the buyer the token1 leg.
    signal a_recv <== fill_t1 + a_is_seller * (fill_t2 - fill_t1);
    recv_a_commitment <== Poseidon(2)([a_recv, r_recv_a]);
    signal b_recv <== fill_t1 + (1 - a_is_seller) * (fill_t2 - fill_t1);
    recv_b_commitment <== Poseidon(2)([b_recv, r_recv_b]);
}

component main { public [order_a_commitment, order_b_commitment, price, a_is_seller, locked_a_hashes, locked_b_hashes] } = SettleCoZk(2);
