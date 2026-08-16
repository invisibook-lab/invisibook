pragma circom 2.2.3;

include "utils/poseidon.circom";
include "utils/bitify.circom";
include "note.circom";

// SettleLarge is the paper's π_B: the PARTIALLY FILLED side's settlement
// update, proven alone after the smaller party revealed its opening
// (q_ctr, r_ctr) over the settlement channel. It pays the fill to the
// counterparty as a pool note and re-commits its residual order and
// residual collateral under fresh randomness.
//
// Public: [cm_q, cm_q_ctr, locked_0, locked_1, price, side,
//          cm_q_residual, cm_locked_residual, pay_asset, cm_note_out, bind]
//   cm_q               — this (larger) order's quantity commitment;
//   cm_q_ctr           — the COUNTERPARTY's on-chain quantity commitment;
//                        opening it in-circuit is the paper's clause (ii):
//                        the fill cannot be understated by substituting a
//                        fabricated counterparty quantity;
//   locked_0/1         — this order's locked collateral (2-slot shape);
//   price, side        — as in SettleSmall (side = 1 when this order sells);
//   cm_q_residual      — fresh commitment to q − q_ctr (relists on the book);
//   cm_locked_residual — fresh commitment to the residual collateral;
//   pay_asset          — assetID of the token this order pays out;
//   cm_note_out        — the fill, minted to the counterparty as a note;
//   bind               — hash of the full request.
template SettleLarge() {
    signal input cm_q;
    signal input cm_q_ctr;
    signal input locked_0;
    signal input locked_1;
    signal input price;
    signal input side;
    signal input cm_q_residual;
    signal input cm_locked_residual;
    signal input pay_asset;
    signal input cm_note_out;
    signal input bind;

    signal input q;
    signal input r_q;
    signal input q_ctr;
    signal input r_q_ctr;
    signal input locked_v[2];
    signal input locked_r[2];
    signal input r_q_residual;
    signal input r_locked_residual;
    signal input npk_ctr;
    signal input r_note;

    side * (1 - side) === 0;

    // Open both quantity commitments (mine, and the counterparty's — the
    // revealed opening must match what THEY committed on chain).
    component q_range = Num2Bits(64);
    q_range.in <== q;
    component q_ctr_range = Num2Bits(64);
    q_ctr_range.in <== q_ctr;
    signal cm_q_check <== Poseidon(2)([q, r_q]);
    cm_q_check === cm_q;
    signal cm_ctr_check <== Poseidon(2)([q_ctr, r_q_ctr]);
    cm_ctr_check === cm_q_ctr;

    // Residual quantity: q − q_ctr, non-negative by its 64-bit range
    // (both operands are 64-bit, so wrap-around would exceed 64 bits).
    signal q_res <== q - q_ctr;
    component res_range = Num2Bits(64);
    res_range.in <== q_res;
    signal cm_res_check <== Poseidon(2)([q_res, r_q_residual]);
    cm_res_check === cm_q_residual;

    // Open the collateral slots.
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

    // Collateral equations for the full and residual quantities.
    component price_range = Num2Bits(64);
    price_range.in <== price;
    signal q_price <== q * price;
    locked_sum === q_price + side * (q - q_price);

    signal res_price <== q_res * price;
    signal locked_res <== res_price + side * (q_res - res_price);
    signal cm_locked_res_check <== Poseidon(2)([locked_res, r_locked_residual]);
    cm_locked_res_check === cm_locked_residual;

    // The fill — what actually moves — is collateral minus residual.
    signal fill <== locked_sum - locked_res;
    component note = NoteCommit();
    note.npk <== npk_ctr;
    note.asset <== pay_asset;
    note.v <== fill;
    note.r <== r_note;
    note.cm === cm_note_out;

    signal bind_sq <== bind * bind;
}

component main {public [cm_q, cm_q_ctr, locked_0, locked_1, price, side, cm_q_residual, cm_locked_residual, pay_asset, cm_note_out, bind]} = SettleLarge();
