pragma circom 2.2.3;

include "utils/poseidon.circom";
include "utils/bitify.circom";

// VerifyAmounts opens N Poseidon commitments and exposes the sum of the
// committed plaintext amounts so callers can constrain balance conservation.
// Each commitment hides an `amount` under a 256-bit blinding factor `r`, so
// commitments are computed as `Poseidon(2)([amount, r])`. Without `r`, an
// observer could brute-force the small space of plausible amounts.
//
// Each `amounts[i]` is range-checked to 64 bits to prevent attacks that exploit
// field wrap-around when comparing sums. The output `sum` is a linear
// combination of the input amounts (no extra constraint on its own).
// `amounts`, `randomness`, and `hashes` must all have length N.
template VerifyAmounts(N) {
    signal input amounts[N];
    signal input randomness[N];
    signal input hashes[N];
    signal output sum;

    component n2b[N];
    component pose[N];
    var s = 0;
    for (var i = 0; i < N; i++) {
        // Range check: amount fits in 64 bits
        n2b[i] = Num2Bits(64);
        n2b[i].in <== amounts[i];
        // Poseidon commitment opens to the claimed (amount, r)
        pose[i] = Poseidon(2);
        pose[i].inputs[0] <== amounts[i];
        pose[i].inputs[1] <== randomness[i];
        pose[i].out === hashes[i];
        s += amounts[i];
    }
    sum <== s;
}
