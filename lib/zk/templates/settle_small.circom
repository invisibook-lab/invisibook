pragma circom 2.2.3;

include "utils/poseidon.circom";
include "utils/bitify.circom";
include "note.circom";

// SettleSmall is the paper's π_A: the FULLY FILLED side's settlement
// update, proven alone after the comparison result is public. Crossing
// prices split the locked collateral into the execution-price payment and a
// price-improvement refund back to the order owner.
//
// LOCKED-ONLY MODEL: the order carries a single collateral commitment
// `locked = P2(needed, r_locked)` and NO quantity commitment. The hidden
// quantity q is a pure witness; the public (price, side) pin it through
// the side-dependent collateral equation
//   needed = q·price + side·(q − q·price)   (sell locks q, buy locks q·price),
// which is injective in q for price > 0, so opening `locked` against the
// in-circuit `needed` also fixes the quantity.
//
// Public: [locked, collateral_price, execution_price, side, pay_asset,
//          cm_note_out, cm_refund_out, bind]
//   locked      — this order's on-chain collateral commitment;
//   collateral_price — this order's limit/protection price;
//   execution_price  — immutable price selected by the matcher;
//   side        — 1 when this order SELLS token1, 0 when it buys;
//   pay_asset   — assetID of the token this order pays out;
//   cm_note_out — the payout note minted to the counterparty (their fresh
//                 npk and blinding travel over the settlement channel);
//   bind        — hash of the full request (weld).
template SettleSmall() {
    signal input locked;
    signal input collateral_price;
    signal input execution_price;
    signal input side;
    signal input pay_asset;
    signal input cm_note_out;
    signal input cm_refund_out;
    signal input bind;

    signal input q;
    signal input r_locked;
    signal input npk_ctr;
    signal input r_note;
    signal input npk_refund;
    signal input r_refund;

    side * (1 - side) === 0;

    // 64-bit q and price keep the product integer-exact in the field.
    component q_range = Num2Bits(64);
    q_range.in <== q;
    component collateral_price_range = Num2Bits(64);
    collateral_price_range.in <== collateral_price;
    component execution_price_range = Num2Bits(64);
    execution_price_range.in <== execution_price;

    // Open the collateral against the side-dependent equation.
    signal q_price <== q * collateral_price;
    signal needed <== q_price + side * (q - q_price);
    signal locked_check <== Poseidon(2)([needed, r_locked]);
    locked_check === locked;

    // Pay at execution price, returning any buy-side price improvement.
    signal q_execution <== q * execution_price;
    signal payment <== q_execution + side * (q - q_execution);
    component payment_range = Num2Bits(64);
    payment_range.in <== payment;
    signal refund <== needed - payment;
    component refund_range = Num2Bits(64);
    refund_range.in <== refund;

    component note = NoteCommit();
    note.npk <== npk_ctr;
    note.asset <== pay_asset;
    note.v <== payment;
    note.r <== r_note;
    note.cm === cm_note_out;

    component refund_note = NoteCommit();
    refund_note.npk <== npk_refund;
    refund_note.asset <== pay_asset;
    refund_note.v <== refund;
    refund_note.r <== r_refund;
    refund_note.cm === cm_refund_out;

    signal bind_sq <== bind * bind;
}

component main {public [locked, collateral_price, execution_price, side, pay_asset, cm_note_out, cm_refund_out, bind]} = SettleSmall();
