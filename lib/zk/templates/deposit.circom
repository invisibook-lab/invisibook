pragma circom 2.2.3;

include "bitify.circom";
include "commitments.circom";

// DepositVerify proves that the M output Cash amounts collectively equal
// `deposit_amount`, the plaintext value bridged in from another chain.
// Slots not used by the deposit must commit to amount 0
// (i.e. `output_amounts[i] = 0` and `output_hashes[i] = Poseidon(0)`).
template DepositVerify(M) {
    // Public: bridged-in plaintext amount and Poseidon hashes of every output Cash
    signal input deposit_amount;
    signal input output_hashes[M];

    // Private: plaintext amounts of each output Cash
    signal input output_amounts[M];

    // Range-check the bridged amount so the conservation equality cannot wrap
    component dep_bits = Num2Bits(64);
    dep_bits.in <== deposit_amount;

    // Verify each output commitment and compute the total
    component outs = VerifyAmounts(M);
    for (var i = 0; i < M; i++) {
        outs.amounts[i] <== output_amounts[i];
        outs.hashes[i] <== output_hashes[i];
    }

    // Conservation: minted output value equals what was bridged in
    outs.sum === deposit_amount;
}

component main { public [deposit_amount, output_hashes] } = DepositVerify(2);
