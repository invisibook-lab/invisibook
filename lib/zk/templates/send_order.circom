pragma circom 2.2.3;

include "utils/poseidon.circom";
include "utils/bitify.circom";
include "utils/comparators.circom";
include "note.circom";

// SendOrder proves admission-time full collateralization (paper §V-B):
// placing an order destroys collateral-asset notes for the lock and native
// `invis` notes for the plaintext fee. Each asset conserves independently;
// when the collateral itself is `invis`, one combined conservation equation
// permits either input bank to fund both outputs.
//
// Public: [anchor, coll_nf_0, coll_nf_1, fee_nf_0, fee_nf_1,
//          lock_asset_id, native_asset_id, locked_commitment, fee,
//          cm_coll_change, cm_fee_change, collateral_price, side, bind]
//   anchor            — historical tree root the spends reference;
//   nf_0, nf_1        — the two input slots' nullifiers (dummies allowed);
//   lock_asset_id     — the collateral token (buy → token2, sell → token1);
//   locked_commitment — P2(locked_value, r_locked), the order's ONLY
//                       commitment (locked-only model); locked_value =
//                       q·price (buy) or q (sell) pins the hidden
//                       quantity q through the side-dependent equation;
//   fee               — plaintext fee, really destroyed from the pool and
//                       claimable by the block producer;
//   cm_change         — change note back to the spender (always minted);
//   price, side       — plaintext order terms (side = 1 for sell);
//   bind              — hash of the full signed request (weld).
//
template SendOrder(DEPTH) {
    signal input anchor;
    signal input coll_nf_0;
    signal input coll_nf_1;
    signal input fee_nf_0;
    signal input fee_nf_1;
    signal input lock_asset_id;
    signal input native_asset_id;
    signal input locked_commitment;
    signal input fee;
    signal input cm_coll_change;
    signal input cm_fee_change;
    signal input collateral_price;
    signal input side;
    signal input bind;

    signal input coll_enabled[2];
    signal input coll_sk[2];
    signal input coll_v[2];
    signal input coll_r[2];
    signal input coll_rho_rand[2];
    signal input coll_path[2][DEPTH];
    signal input coll_path_bits[2][DEPTH];

    signal input fee_enabled[2];
    signal input fee_sk[2];
    signal input fee_v[2];
    signal input fee_r[2];
    signal input fee_rho_rand[2];
    signal input fee_path[2][DEPTH];
    signal input fee_path_bits[2][DEPTH];

    // Order + change openings.
    signal input q;
    signal input r_locked;
    signal input npk_coll_change;
    signal input v_coll_change;
    signal input r_coll_change;
    signal input npk_fee_change;
    signal input v_fee_change;
    signal input r_fee_change;

    side * (1 - side) === 0;

    component coll_spend[2];
    component fee_spend[2];
    for (var s = 0; s < 2; s++) {
        coll_spend[s] = SpendNote(DEPTH);
        coll_spend[s].anchor <== anchor;
        coll_spend[s].asset <== lock_asset_id;
        coll_spend[s].enabled <== coll_enabled[s];
        coll_spend[s].sk <== coll_sk[s];
        coll_spend[s].v <== coll_v[s];
        coll_spend[s].r <== coll_r[s];
        coll_spend[s].rho_rand <== coll_rho_rand[s];
        fee_spend[s] = SpendNote(DEPTH);
        fee_spend[s].anchor <== anchor;
        fee_spend[s].asset <== native_asset_id;
        fee_spend[s].enabled <== fee_enabled[s];
        fee_spend[s].sk <== fee_sk[s];
        fee_spend[s].v <== fee_v[s];
        fee_spend[s].r <== fee_r[s];
        fee_spend[s].rho_rand <== fee_rho_rand[s];
        for (var i = 0; i < DEPTH; i++) {
            coll_spend[s].path[i] <== coll_path[s][i];
            coll_spend[s].path_bits[i] <== coll_path_bits[s][i];
            fee_spend[s].path[i] <== fee_path[s][i];
            fee_spend[s].path_bits[i] <== fee_path_bits[s][i];
        }
    }
    coll_spend[0].nf === coll_nf_0;
    coll_spend[1].nf === coll_nf_1;
    fee_spend[0].nf === fee_nf_0;
    fee_spend[1].nf === fee_nf_1;

    // 64-bit q and price keep the collateral product integer-exact.
    component q_range = Num2Bits(64);
    q_range.in <== q;
    component price_range = Num2Bits(64);
    price_range.in <== collateral_price;

    // Collateral: q·price for a buy, q for a sell — the paper's
    // admission-time full backing. Bounded to 64 bits so conservation is
    // integer arithmetic.
    signal q_price <== q * collateral_price;
    signal locked_value <== q_price + side * (q - q_price);
    component locked_range = Num2Bits(64);
    locked_range.in <== locked_value;
    signal locked_check <== Poseidon(2)([locked_value, r_locked]);
    locked_check === locked_commitment;

    // Fee range; conservation over integers (sums of 64-bit terms).
    component fee_range = Num2Bits(64);
    fee_range.in <== fee;
    component coll_change = NoteCommit();
    coll_change.npk <== npk_coll_change;
    coll_change.asset <== lock_asset_id;
    coll_change.v <== v_coll_change;
    coll_change.r <== r_coll_change;
    coll_change.cm === cm_coll_change;
    component fee_change = NoteCommit();
    fee_change.npk <== npk_fee_change;
    fee_change.asset <== native_asset_id;
    fee_change.v <== v_fee_change;
    fee_change.r <== r_fee_change;
    fee_change.cm === cm_fee_change;

    signal coll_in <== coll_spend[0].value + coll_spend[1].value;
    signal fee_in <== fee_spend[0].value + fee_spend[1].value;
    component same_asset = IsEqual();
    same_asset.in[0] <== lock_asset_id;
    same_asset.in[1] <== native_asset_id;
    (1 - same_asset.out) * (coll_in - locked_value - v_coll_change) === 0;
    (1 - same_asset.out) * (fee_in - fee - v_fee_change) === 0;
    same_asset.out * (coll_in + fee_in - locked_value - fee - v_coll_change - v_fee_change) === 0;

    signal bind_sq <== bind * bind;
}

component main {public [anchor, coll_nf_0, coll_nf_1, fee_nf_0, fee_nf_1,
                        lock_asset_id, native_asset_id, locked_commitment, fee,
                        cm_coll_change, cm_fee_change, collateral_price, side,
                        bind]} = SendOrder(20);
