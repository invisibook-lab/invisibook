pragma circom 2.2.3;

include "utils/poseidon.circom";
include "utils/bitify.circom";
include "note.circom";

// SendOrder proves admission-time full collateralization (paper §V-B):
// placing an order destroys pool notes worth exactly the collateral plus
// the plaintext fee, with the collateral amount computed IN-CIRCUIT from
// the hidden quantity and the public price.
//
// Public: [anchor, nf_0, nf_1, lock_asset_id, cm_q, locked_commitment,
//          fee, cm_change, price, side, bind]
//   anchor            — historical tree root the spends reference;
//   nf_0, nf_1        — the two input slots' nullifiers (dummies allowed);
//   lock_asset_id     — the collateral token (buy → token2, sell → token1);
//   cm_q              — the order's quantity commitment P2(q, r_q), the
//                       value the settlement comparison later opens;
//   locked_commitment — P2(locked_value, r_locked), the order-bound
//                       collateral (lives on the order row, outside the
//                       pool); locked_value = q·price (buy) or q (sell);
//   fee               — plaintext fee, really destroyed from the pool and
//                       claimable by the block producer;
//   cm_change         — change note back to the spender (always minted);
//   price, side       — plaintext order terms (side = 1 for sell);
//   bind              — hash of the full signed request (weld).
//
// Everything is tied through the shared witness q and one conservation
// equation: v_0 + v_1 = locked_value + fee + v_change.
template SendOrder(DEPTH) {
    signal input anchor;
    signal input nf_0;
    signal input nf_1;
    signal input lock_asset_id;
    signal input cm_q;
    signal input locked_commitment;
    signal input fee;
    signal input cm_change;
    signal input price;
    signal input side;
    signal input bind;

    // Per-slot spend witnesses (slot may be a dummy).
    signal input enabled[2];
    signal input sk[2];
    signal input v[2];
    signal input r[2];
    signal input rho_rand[2];
    signal input path[2][DEPTH];
    signal input path_bits[2][DEPTH];

    // Order + change openings.
    signal input q;
    signal input r_q;
    signal input r_locked;
    signal input npk_change;
    signal input v_change;
    signal input r_change;

    side * (1 - side) === 0;

    component spend[2];
    for (var s = 0; s < 2; s++) {
        spend[s] = SpendNote(DEPTH);
        spend[s].anchor <== anchor;
        spend[s].asset <== lock_asset_id;
        spend[s].enabled <== enabled[s];
        spend[s].sk <== sk[s];
        spend[s].v <== v[s];
        spend[s].r <== r[s];
        spend[s].rho_rand <== rho_rand[s];
        for (var i = 0; i < DEPTH; i++) {
            spend[s].path[i] <== path[s][i];
            spend[s].path_bits[i] <== path_bits[s][i];
        }
    }
    spend[0].nf === nf_0;
    spend[1].nf === nf_1;

    // Open the quantity commitment; 64-bit q and price keep the product
    // integer-exact in the field.
    component q_range = Num2Bits(64);
    q_range.in <== q;
    component price_range = Num2Bits(64);
    price_range.in <== price;
    signal cm_q_check <== Poseidon(2)([q, r_q]);
    cm_q_check === cm_q;

    // Collateral: q·price for a buy, q for a sell — the paper's
    // admission-time full backing. Bounded to 64 bits so conservation is
    // integer arithmetic.
    signal q_price <== q * price;
    signal locked_value <== q_price + side * (q - q_price);
    component locked_range = Num2Bits(64);
    locked_range.in <== locked_value;
    signal locked_check <== Poseidon(2)([locked_value, r_locked]);
    locked_check === locked_commitment;

    // Fee range; conservation over integers (sums of 64-bit terms).
    component fee_range = Num2Bits(64);
    fee_range.in <== fee;
    component change = NoteCommit();
    change.npk <== npk_change;
    change.asset <== lock_asset_id;
    change.v <== v_change;
    change.r <== r_change;
    change.cm === cm_change;
    spend[0].value + spend[1].value === locked_value + fee + v_change;

    signal bind_sq <== bind * bind;
}

component main {public [anchor, nf_0, nf_1, lock_asset_id, cm_q, locked_commitment, fee, cm_change, price, side, bind]} = SendOrder(20);
