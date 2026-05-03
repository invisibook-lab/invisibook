pragma circom 2.2.3;

include "poseidon.circom";
include "bitify.circom";

// VerifyAmounts opens N Poseidon commitments and exposes the sum of the
// committed plaintext amounts so callers can constrain balance conservation.
// Each `amounts[i]` is range-checked to 64 bits to prevent attacks that exploit
// field wrap-around when comparing sums. The output `sum` is a linear
// combination of the input amounts (no extra constraint on its own).
// `amounts` and `hashes` must both have length N.
template VerifyAmounts(N) {
    signal input amounts[N];
    signal input hashes[N];
    signal output sum;

    component n2b[N];
    component pose[N];
    var s = 0;
    for (var i = 0; i < N; i++) {
        // Range check: amount fits in 64 bits
        n2b[i] = Num2Bits(64);
        n2b[i].in <== amounts[i];
        // Poseidon commitment opens to the claimed amount
        pose[i] = Poseidon(1);
        pose[i].inputs[0] <== amounts[i];
        pose[i].out === hashes[i];
        s += amounts[i];
    }
    sum <== s;
}
