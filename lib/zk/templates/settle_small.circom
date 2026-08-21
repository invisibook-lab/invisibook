pragma circom 2.2.3;

include "utils/poseidon.circom";
include "utils/bitify.circom";
include "note.circom";

// SettleSmall is the paper's π_A: the FULLY FILLED side's settlement
// update, proven alone after the comparison result is public. The prover's
// entire locked collateral transfers to the counterparty as one pool note.
//
// LOCKED-ONLY MODEL: the order carries a single collateral commitment
// `locked = P2(needed, r_locked)` and NO quantity commitment. The hidden
// quantity q is a pure witness; the public (price, side) pin it through
// the side-dependent collateral equation
//   needed = q·price + side·(q − q·price)   (sell locks q, buy locks q·price),
// which is injective in q for price > 0, so opening `locked` against the
// in-circuit `needed` also fixes the quantity.
//
// Public: [locked, price, side, pay_asset, cm_note_out, bind]
//   locked      — this order's on-chain collateral commitment;
//   price       — the pair's execution price (plaintext, from the book);
//   side        — 1 when this order SELLS token1, 0 when it buys;
//   pay_asset   — assetID of the token this order pays out;
//   cm_note_out — the payout note minted to the counterparty (their fresh
//                 npk and blinding travel over the settlement channel);
//   bind        — hash of the full request (weld).
template SettleSmall() {
    signal input locked;
    signal input price;
    signal input side;
    signal input pay_asset;
    signal input cm_note_out;
    signal input bind;

    signal input q;
    signal input r_locked;
    signal input npk_ctr;
    signal input r_note;

    side * (1 - side) === 0;

    // 64-bit q and price keep the product integer-exact in the field.
    component q_range = Num2Bits(64);
    q_range.in <== q;
    component price_range = Num2Bits(64);
    price_range.in <== price;

    // Open the collateral against the side-dependent equation.
    signal q_price <== q * price;
    signal needed <== q_price + side * (q - q_price);
    signal locked_check <== Poseidon(2)([needed, r_locked]);
    locked_check === locked;

    // The payout note carries the full collateral to the counterparty.
    component note = NoteCommit();
    note.npk <== npk_ctr;
    note.asset <== pay_asset;
    note.v <== needed;
    note.r <== r_note;
    note.cm === cm_note_out;

    signal bind_sq <== bind * bind;
}

component main {public [locked, price, side, pay_asset, cm_note_out, bind]} = SettleSmall();
