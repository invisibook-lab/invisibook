pragma circom 2.2.3;

include "utils/poseidon.circom";
include "note.circom";

// NoteDeposit mints one shielded note from a bridged deposit.
//
// Public: [bridge_commitment, asset_id, cm_out, bind]
//   bridge_commitment = P2(v, r_bridge) — attested (eventually) by the
//                       source-chain bridge inclusion proof;
//   asset_id          — the deposited token, bound into the note so a
//                       deposit of one asset can never mint another;
//   cm_out            — the new note's commitment (appended to the tree);
//   bind              — hash of the full request (anti-replay weld).
//
// Private: v, r_bridge, npk, r_note. The depositor mints to their own npk,
// so the wallet knows the opening before the transaction exists.
template NoteDeposit() {
    signal input bridge_commitment;
    signal input asset_id;
    signal input cm_out;
    signal input bind;

    signal input v;
    signal input r_bridge;
    signal input npk;
    signal input r_note;

    // The prover knows an opening of the bridge commitment.
    // (v's 64-bit range check happens inside NoteCommit.)
    signal bridge <== Poseidon(2)([v, r_bridge]);
    bridge === bridge_commitment;

    // The minted note commits exactly the bridged value under the public
    // asset.
    component note = NoteCommit();
    note.npk <== npk;
    note.asset <== asset_id;
    note.v <== v;
    note.r <== r_note;
    note.cm === cm_out;

    // Anti-pruning square so `bind` survives circom optimization; the
    // Groth16 verification equation binds its value regardless.
    signal bind_sq <== bind * bind;
}

component main {public [bridge_commitment, asset_id, cm_out, bind]} = NoteDeposit();
