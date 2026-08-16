pragma circom 2.2.3;

include "utils/poseidon.circom";
include "utils/bitify.circom";
include "note.circom";

// SettleSmall is the paper's π_A: the FULLY FILLED side's settlement
// update, proven alone after the comparison result is public. The prover's
// entire locked collateral transfers to the counterparty as one pool note.
//
// Public: [cm_q, locked_0, locked_1, price, side, pay_asset, cm_note_out, bind]
//   cm_q        — this order's on-chain quantity commitment P2(q, r_q);
//   locked_0/1  — this order's locked collateral commitments (2-slot shape,
//                 unused slot = P2(0, 0));
//   price       — the pair's execution price (plaintext, from the book);
//   side        — 1 when this order SELLS token1 (collateral = q),
//                 0 when it buys (collateral = q·price);
//   pay_asset   — assetID of the token this order pays out;
//   cm_note_out — the payout note minted to the counterparty (their fresh
//                 npk and blinding travel over the settlement channel);
//   bind        — hash of the full request (weld).
//
// The collateral equation `locked_sum = q·price + side·(q − q·price)` is
// what makes the payout exactly the executed value: the admission-time
// collateralization (Phase 4's send_order circuit) locks precisely this
// amount, and here it moves in full.
template SettleSmall() {
    signal input cm_q;
    signal input locked_0;
    signal input locked_1;
    signal input price;
    signal input side;
    signal input pay_asset;
    signal input cm_note_out;
    signal input bind;

    signal input q;
    signal input r_q;
    signal input locked_v[2];
    signal input locked_r[2];
    signal input npk_ctr;
    signal input r_note;

    side * (1 - side) === 0;

    // Open the order quantity commitment (64-bit q).
    component q_range = Num2Bits(64);
    q_range.in <== q;
    signal cm_q_check <== Poseidon(2)([q, r_q]);
    cm_q_check === cm_q;

    // Open both collateral slots (64-bit each; the pad slot commits 0).
    component v_range[2];
    signal locked_check[2];
    for (var i = 0; i < 2; i++) {
        v_range[i] = Num2Bits(64);
        v_range[i].in <== locked_v[i];
    }
    locked_check[0] <== Poseidon(2)([locked_v[0], locked_r[0]]);
    locked_check[0] === locked_0;
    locked_check[1] <== Poseidon(2)([locked_v[1], locked_r[1]]);
    locked_check[1] === locked_1;
    signal locked_sum <== locked_v[0] + locked_v[1];

    // Collateral equation: exact in the field (q, price 64-bit → product
    // < 2^128 ≪ p), then bounded back to 64 bits via locked_sum's parts.
    component price_range = Num2Bits(64);
    price_range.in <== price;
    signal q_price <== q * price;
    locked_sum === q_price + side * (q - q_price);

    // The payout note carries the full collateral to the counterparty.
    component note = NoteCommit();
    note.npk <== npk_ctr;
    note.asset <== pay_asset;
    note.v <== locked_sum;
    note.r <== r_note;
    note.cm === cm_note_out;

    signal bind_sq <== bind * bind;
}

component main {public [cm_q, locked_0, locked_1, price, side, pay_asset, cm_note_out, bind]} = SettleSmall();
