pragma circom 2.2.3;

include "utils/poseidon.circom";
include "utils/bitify.circom";
include "note.circom";

// SettleLarge is the paper's π_B: the PARTIALLY FILLED side's settlement
// update, proven alone after the smaller party revealed its collateral
// opening (q_ctr, r_locked_ctr) over the settlement channel. It pays the
// fill to the counterparty as a pool note and re-commits its residual
// collateral under fresh randomness.
//
// LOCKED-ONLY MODEL: both orders carry only a collateral commitment; each
// hidden quantity is a witness pinned by the side-dependent equation
//   needed(q, s) = q·price + s·(q − q·price).
// This order uses its own `side`; the counterparty is on the OPPOSITE
// side, so its collateral opens against needed(q_ctr, 1 − side).
//
// Public: [locked, locked_ctr, collateral_price, ctr_collateral_price,
//          execution_price, side, cm_locked_residual, pay_asset,
//          cm_note_out, cm_refund_out, bind]
//   locked             — this (larger) order's collateral commitment;
//   locked_ctr         — the COUNTERPARTY's on-chain collateral
//                        commitment; opening it in-circuit is the paper's
//                        clause (ii): the fill cannot be understated by
//                        substituting a fabricated counterparty quantity;
//   price, side        — as in SettleSmall (side = 1 when this order sells);
//   cm_locked_residual — fresh commitment to the residual collateral
//                        (relists on the book);
//   pay_asset          — assetID of the token this order pays out;
//   cm_note_out        — the fill, minted to the counterparty as a note;
//   bind               — hash of the full request.
template SettleLarge() {
    signal input locked;
    signal input locked_ctr;
    signal input collateral_price;
    signal input ctr_collateral_price;
    signal input execution_price;
    signal input side;
    signal input cm_locked_residual;
    signal input pay_asset;
    signal input cm_note_out;
    signal input cm_refund_out;
    signal input bind;

    signal input q;
    signal input r_locked;
    signal input q_ctr;
    signal input r_locked_ctr;
    signal input r_locked_res;
    signal input npk_ctr;
    signal input r_note;
    signal input npk_refund;
    signal input r_refund;

    side * (1 - side) === 0;

    component q_range = Num2Bits(64);
    q_range.in <== q;
    component q_ctr_range = Num2Bits(64);
    q_ctr_range.in <== q_ctr;
    component collateral_price_range = Num2Bits(64);
    collateral_price_range.in <== collateral_price;
    component ctr_collateral_price_range = Num2Bits(64);
    ctr_collateral_price_range.in <== ctr_collateral_price;
    component execution_price_range = Num2Bits(64);
    execution_price_range.in <== execution_price;

    // Open my collateral: needed(q, side).
    signal q_price <== q * collateral_price;
    signal needed <== q_price + side * (q - q_price);
    signal locked_check <== Poseidon(2)([needed, r_locked]);
    locked_check === locked;

    // Open the counterparty's collateral with the REVEALED opening, on the
    // OPPOSITE side: needed(q_ctr, 1 − side).
    signal ctr_side <== 1 - side;
    signal q_ctr_price <== q_ctr * ctr_collateral_price;
    signal needed_ctr <== q_ctr_price + ctr_side * (q_ctr - q_ctr_price);
    signal ctr_check <== Poseidon(2)([needed_ctr, r_locked_ctr]);
    ctr_check === locked_ctr;

    // Residual quantity: q − q_ctr, non-negative by its 64-bit range
    // (both operands are 64-bit, so wrap-around would exceed 64 bits).
    signal q_res <== q - q_ctr;
    component res_range = Num2Bits(64);
    res_range.in <== q_res;

    // Residual collateral, re-committed under a fresh blinding.
    signal res_price <== q_res * collateral_price;
    signal locked_res <== res_price + side * (q_res - res_price);
    signal res_check <== Poseidon(2)([locked_res, r_locked_res]);
    res_check === cm_locked_residual;

    // The fill pays at execution price. Any excess buy-side collateral is
    // returned to the owner rather than transferred to the counterparty.
    signal fill_execution <== q_ctr * execution_price;
    signal payment <== fill_execution + side * (q_ctr - fill_execution);
    component payment_range = Num2Bits(64);
    payment_range.in <== payment;
    signal refund <== needed - locked_res - payment;
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

component main {public [locked, locked_ctr, collateral_price, ctr_collateral_price, execution_price, side, cm_locked_residual, pay_asset, cm_note_out, cm_refund_out, bind]} = SettleLarge();
