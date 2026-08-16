pragma circom 2.2.3;

include "utils/poseidon.circom";
include "utils/bitify.circom";
include "note.circom";

// SpendWithdraw spends up to two pool notes and withdraws value out through
// the bridge, minting a change note back to the spender.
//
// Public: [anchor, nf_0, nf_1, asset_id, bridge_out_commitment, cm_change, bind]
//   anchor                — a historical tree root the spends reference;
//   nf_0, nf_1            — the two input slots' nullifiers (a dummy slot
//                           still emits one: a fresh-secret PRF image);
//   asset_id              — the withdrawn token; every enabled input and
//                           the change note are bound to it (asset
//                           conservation);
//   bridge_out_commitment — P2(v_out, r_bridge_out), attested (eventually)
//                           by the destination-chain release proof;
//   cm_change             — the change note, ALWAYS minted (v_change may be
//                           0) so every withdrawal has the same shape;
//   bind                  — hash of the full request (anti-replay weld).
//
// Conservation: v_0 + v_1 === v_out + v_change over 64-bit-checked values
// (sums of two such terms cannot wrap the field).
template SpendWithdraw(DEPTH) {
    signal input anchor;
    signal input nf_0;
    signal input nf_1;
    signal input asset_id;
    signal input bridge_out_commitment;
    signal input cm_change;
    signal input bind;

    // Per-slot witnesses (slot 1 may be a dummy: enabled=0, v=0, fresh
    // random sk/rho_rand).
    signal input enabled[2];
    signal input sk[2];
    signal input v[2];
    signal input r[2];
    signal input rho_rand[2];
    signal input path[2][DEPTH];
    signal input path_bits[2][DEPTH];

    // Withdrawal + change openings.
    signal input v_out;
    signal input r_bridge_out;
    signal input npk_change;
    signal input v_change;
    signal input r_change;

    component spend[2];
    for (var s = 0; s < 2; s++) {
        spend[s] = SpendNote(DEPTH);
        spend[s].anchor <== anchor;
        spend[s].asset <== asset_id;
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

    // Bridge-out binding; v_out range-checked so conservation is integer
    // arithmetic, not field arithmetic.
    component out_range = Num2Bits(64);
    out_range.in <== v_out;
    signal bridge_out <== Poseidon(2)([v_out, r_bridge_out]);
    bridge_out === bridge_out_commitment;

    // Change note: same asset, always emitted (its NoteCommit range-checks
    // v_change).
    component change = NoteCommit();
    change.npk <== npk_change;
    change.asset <== asset_id;
    change.v <== v_change;
    change.r <== r_change;
    change.cm === cm_change;

    // Conservation over integers.
    spend[0].value + spend[1].value === v_out + v_change;

    signal bind_sq <== bind * bind;
}

component main {public [anchor, nf_0, nf_1, asset_id, bridge_out_commitment, cm_change, bind]} = SpendWithdraw(20);
