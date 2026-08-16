pragma circom 2.2.3;

include "poseidon.circom";

// DualMux orders (in[0], in[1]) by the boolean selector `s`:
// s = 0 keeps the order, s = 1 swaps. Constrains s to a boolean.
// Convention (pinned by spec/golden.json): path bit 0 means the current
// node is the LEFT child, so the sibling goes on the right.
template DualMux() {
    signal input in[2];
    signal input s;
    signal output out[2];

    s * (1 - s) === 0;
    out[0] <== (in[1] - in[0]) * s + in[0];
    out[1] <== (in[0] - in[1]) * s + in[1];
}

// MerkleInclusion computes the root of a depth-DEPTH Poseidon tree from a
// leaf and its authentication path, and re-derives the leaf index from the
// path bits (little-endian: bit 0 nearest the leaf).
//
// The exported `index` is what makes one note yield exactly one nullifier:
// rho must consume THIS value, never a free input, or the same note could
// produce a second nullifier at a fabricated position (double spend).
template MerkleInclusion(DEPTH) {
    signal input leaf;
    signal input path[DEPTH];
    signal input path_bits[DEPTH];
    signal output root;
    signal output index;

    component mux[DEPTH];
    signal cur[DEPTH + 1];
    cur[0] <== leaf;
    var idx = 0;
    for (var i = 0; i < DEPTH; i++) {
        mux[i] = DualMux();
        mux[i].in[0] <== cur[i];
        mux[i].in[1] <== path[i];
        mux[i].s <== path_bits[i];
        cur[i + 1] <== Poseidon(2)([mux[i].out[0], mux[i].out[1]]);
        idx += path_bits[i] * 2 ** i;
    }
    root <== cur[DEPTH];
    index <== idx;
}
