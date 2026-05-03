pragma circom 2.2.3;

include "commitments.circom";

// SettleVerify proves value conservation when SettleOrder spends the locked
// input Cash of a matched order pair and mints the corresponding output Cash:
// `sum(input_amounts) == sum(output_amounts)`. Settlement spans two tokens, so
// this circuit must be invoked once per token group (e.g. once for Token1 cash
// flowing seller→buyer and once for Token2 cash flowing buyer→seller). All
// Cash within a single proof must belong to the same token. Unused slots must
// commit to amount 0.
template SettleVerify(N, M) {
    // Public: Poseidon commitments for every input and output Cash in the token group
    signal input input_hashes[N];
    signal input output_hashes[M];

    // Private: plaintext amounts of inputs being spent and outputs being minted
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

component main { public [input_hashes, output_hashes] } = SettleVerify(2, 2);
