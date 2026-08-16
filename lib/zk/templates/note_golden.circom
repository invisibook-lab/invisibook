pragma circom 2.2.3;

include "note.circom";

// Test-only main: pins every note gadget against spec/golden.json.
// Witness generation SUCCEEDS iff all derivations equal the expected
// golden values — the circom leg of the three-language golden-vector gate.
// Never deployed; no verification key is ever generated for it.
template NoteGolden(DEPTH) {
    // Golden inputs.
    signal input sk1;
    signal input sk2;
    signal input asset_usdt;
    signal input r1;
    signal input path[DEPTH];
    signal input path_bits[DEPTH];
    signal input sk_dummy;
    signal input rho_dummy;
    // Golden expectations.
    signal input want_nk1;
    signal input want_npk1;
    signal input want_leaf1;
    signal input want_root;
    signal input want_nf1;
    signal input want_nf_dummy;

    // Key derivation of sk1.
    component k1 = KeyDerive();
    k1.sk <== sk1;
    k1.nk === want_nk1;
    k1.npk === want_npk1;

    // Note commitment of leaf1 (sk2's USDT note, v = 1_000_000).
    component k2 = KeyDerive();
    k2.sk <== sk2;
    component note1 = NoteCommit();
    note1.npk <== k2.npk;
    note1.asset <== asset_usdt;
    note1.v <== 1000000;
    note1.r <== r1;
    note1.cm === want_leaf1;

    // Real spend slot over leaf1 at index 1: membership + position-bound nf.
    component spend = SpendNote(DEPTH);
    spend.anchor <== want_root;
    spend.asset <== asset_usdt;
    spend.enabled <== 1;
    spend.sk <== sk2;
    spend.v <== 1000000;
    spend.r <== r1;
    spend.rho_rand <== 0;
    for (var i = 0; i < DEPTH; i++) {
        spend.path[i] <== path[i];
        spend.path_bits[i] <== path_bits[i];
    }
    spend.nf === want_nf1;

    // Dummy slot: zero value, membership off, nf from fresh secrets.
    component dummy = SpendNote(DEPTH);
    dummy.anchor <== want_root;
    dummy.asset <== asset_usdt;
    dummy.enabled <== 0;
    dummy.sk <== sk_dummy;
    dummy.v <== 0;
    dummy.r <== 0;
    dummy.rho_rand <== rho_dummy;
    for (var i = 0; i < DEPTH; i++) {
        dummy.path[i] <== 0;
        dummy.path_bits[i] <== 0;
    }
    dummy.nf === want_nf_dummy;
}

component main = NoteGolden(20);
