pragma circom 2.2.3;

include "commitments.circom";

// SplitVerify proves value conservation when SendOrder splits its input Cash
// into one Locked output (the order's collateral) plus one Active change Cash:
// `sum(input_amounts) == sum(output_amounts)`. All Cash here belong to the
// same owner and the same token. Unused slots must commit to amount 0.
template SplitVerify(N, M) {
    // Public: Poseidon commitments for every input and output Cash
    signal input input_hashes[N];
    signal input output_hashes[M];

    // Private: plaintext amounts being spent and re-minted
    signal input input_amounts[N];
    signal input output_amounts[M];

    component ins = VerifyAmounts(N);
    for (var i = 0; i < N; i++) {
        ins.amounts[i] <== input_amounts[i];
        ins.hashes[i] <== input_hashes[i];
    }

    component outs = VerifyAmounts(M);
    for (var i = 0; i < M; i++) {
        outs.amounts[i] <== output_amounts[i];
        outs.hashes[i] <== output_hashes[i];
    }

    ins.sum === outs.sum;
}

component main { public [input_hashes, output_hashes] } = SplitVerify(2, 2);
