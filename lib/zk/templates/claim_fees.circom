pragma circom 2.2.3;

include "utils/poseidon.circom";
include "utils/bitify.circom";
include "note.circom";

// ClaimFees lets the block producer mint one note for exactly the fees it
// has accrued. The chain checks `amount` against its per-producer counter;
// this circuit only proves the minted note commits that public amount under
// the producer's own key.
//
// Public: [asset_id, amount, cm_out, bind]
template ClaimFees() {
    signal input asset_id;
    signal input amount;
    signal input cm_out;
    signal input bind;

    signal input npk;
    signal input r_note;

    component amount_range = Num2Bits(64);
    amount_range.in <== amount;

    component note = NoteCommit();
    note.npk <== npk;
    note.asset <== asset_id;
    note.v <== amount;
    note.r <== r_note;
    note.cm === cm_out;

    signal bind_sq <== bind * bind;
}

component main {public [asset_id, amount, cm_out, bind]} = ClaimFees();
