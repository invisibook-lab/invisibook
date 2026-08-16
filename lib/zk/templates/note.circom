pragma circom 2.2.3;

include "utils/poseidon.circom";
include "utils/bitify.circom";
include "utils/merkle.circom";

// Shielded-pool note gadgets — the circom half of the frozen protocol spec
// (plan rev. 3, "Protocol equations"). The Rust twin is
// `lib/chain/src/note.rs`, the Go twin `chain/core/pool.go`; all three are
// pinned byte-for-byte by `spec/golden.json`.
//
// Domain tags: TAG_NK=1, TAG_NPK=2, TAG_CM=3, TAG_RHO=4, TAG_NF=5.
//
//   nk  = P2(TAG_NK,  sk)          npk = P2(TAG_NPK, sk)
//   cm  = P2( P2( P2( P2(TAG_CM, npk), assetID ), v ), r )
//   rho = P2( P2(TAG_RHO, cm), leafIndex )
//   nf  = P2( P2(TAG_NF,  nk), rho )

// KeyDerive binds both keys to ONE spending secret — the ownership
// relation: whoever can derive this nf also owns this npk's notes.
template KeyDerive() {
    signal input sk;
    signal output nk;
    signal output npk;

    nk <== Poseidon(2)([1, sk]);
    npk <== Poseidon(2)([2, sk]);
}

// NoteCommit computes the tagged nested commitment chain and range-checks
// the amount to the protocol's 64-bit monetary range (field arithmetic is
// mod p; without the range check, modular wrap-around could mint value).
template NoteCommit() {
    signal input npk;
    signal input asset;
    signal input v;
    signal input r;
    signal output cm;

    component range = Num2Bits(64);
    range.in <== v;

    signal c1 <== Poseidon(2)([3, npk]);
    signal c2 <== Poseidon(2)([c1, asset]);
    signal c3 <== Poseidon(2)([c2, v]);
    cm <== Poseidon(2)([c3, r]);
}

// SpendNote is one input slot of a spend circuit: proves ownership,
// membership, and nullifier correctness for a real note — or a harmless
// zero-value dummy when `enabled` = 0 (fixed-shape circuits pad unused
// slots with dummies instead of a fixed constant, which would collide in
// the nullifier set).
//
// Dummy construction (Orchard's): the caller supplies FRESH RANDOM
// `sk` and `rho_rand`; the nf is then the PRF image of unknown secrets —
// unsteerable to any target (no nullifier squatting) and collision-free.
// The membership check is the ONLY constraint that switches off.
//
// Inputs the enclosing circuit must feed from its own publics:
//   `anchor` — the historical root the spend references;
//   `asset`  — the leg's public assetID (asset conservation: a note of a
//              different asset cannot open this slot's commitment).
template SpendNote(DEPTH) {
    signal input anchor;
    signal input asset;
    signal input enabled;
    signal input sk;
    signal input v;
    signal input r;
    signal input rho_rand;
    signal input path[DEPTH];
    signal input path_bits[DEPTH];
    signal output nf;
    signal output value;

    enabled * (enabled - 1) === 0;
    // A dummy slot carries no value.
    (1 - enabled) * v === 0;

    component keys = KeyDerive();
    keys.sk <== sk;

    component note = NoteCommit();
    note.npk <== keys.npk;
    note.asset <== asset;
    note.v <== v;
    note.r <== r;

    component inc = MerkleInclusion(DEPTH);
    inc.leaf <== note.cm;
    for (var i = 0; i < DEPTH; i++) {
        inc.path[i] <== path[i];
        inc.path_bits[i] <== path_bits[i];
    }
    // Membership relaxes ONLY for dummies.
    enabled * (inc.root - anchor) === 0;

    // rho: position-bound for real notes, fresh random for dummies.
    // inc.index is derived from the path bits — never a free input.
    signal rho_tag <== Poseidon(2)([4, note.cm]);
    signal rho_real <== Poseidon(2)([rho_tag, inc.index]);
    signal rho <== rho_rand + enabled * (rho_real - rho_rand);

    signal nf_tag <== Poseidon(2)([5, keys.nk]);
    nf <== Poseidon(2)([nf_tag, rho]);
    value <== v;
}
