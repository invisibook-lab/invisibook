pragma circom 2.2.3;

include "bitify.circom";
include "commitments.circom";

// WithdrawVerify proves that the spent input Cash plus the (optional) change
// outputs satisfy `sum(inputs) == withdraw_amount + sum(outputs)`.
// `withdraw_amount` is the plaintext value the user is moving off-chain.
// Unused input/output slots must commit to amount 0
// (e.g. when there is no change, all `output_amounts[i] = 0`).
template WithdrawVerify(N, M) {
    // Public: plaintext withdraw amount, plus Poseidon commitments for every input/output
    signal input withdraw_amount;
    signal input input_hashes[N];
    signal input output_hashes[M];

    // Private: plaintext amounts of inputs being spent and outputs being minted
    signal input input_amounts[N];
    signal input output_amounts[M];

    // Range-check the public withdraw amount
    component wd_bits = Num2Bits(64);
    wd_bits.in <== withdraw_amount;

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

    // Conservation: spent input value covers the withdrawal plus the change output(s)
    ins.sum === withdraw_amount + outs.sum;
}

component main { public [withdraw_amount, input_hashes, output_hashes] } = WithdrawVerify(2, 2);
