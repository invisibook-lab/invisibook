pragma circom 2.2.3;

include "utils/bitify.circom";
include "utils/poseidon.circom";
include "commitments.circom";

// WithdrawVerify proves that the spent input Cash plus an optional change
// output cover a hidden `withdraw_amount` bound to a public
// `bridge_out_commitment`: `Poseidon(2)([withdraw_amount, r_bridge_out])`.
// Hiding `withdraw_amount` keeps the on-chain withdraw receipt from leaking
// the moved value; binding it to `bridge_out_commitment` lets the
// destination-chain bridge contract release exactly the attested amount once
// it verifies its inclusion proof for the same commitment.
//
// Slot conventions (mirrors deposit.circom):
//   * Unused input slots commit to amount 0 (`input_amounts[i] = 0`,
//     `input_hashes[i] = Poseidon(2)([0, input_randomness[i]])`).
//   * `output_amounts[0]` is the change cash sent back to the withdrawer
//     (set to 0 if the inputs cover withdraw_amount exactly).
//   * `output_amounts[1..M-1]` are zero-padded with `random = 0`, so their
//     hash is the constant `Poseidon(2)([0, 0])` — chain rebuilds this.
template WithdrawVerify(N, M) {
    // Public: bridge commitment + Poseidon hashes of every input and output Cash
    signal input bridge_out_commitment;
    signal input input_hashes[N];
    signal input output_hashes[M];

    // Private: hidden withdraw amount + its blinding factor, plus per-Cash openings
    signal input withdraw_amount;
    signal input r_bridge_out;
    signal input input_amounts[N];
    signal input input_randomness[N];
    signal input output_amounts[M];
    signal input output_randomness[M];

    // 1) Bridge binding: prover must know an opening (withdraw_amount, r_bridge_out)
    signal expected_bridge <== Poseidon(2)([withdraw_amount, r_bridge_out]);
    expected_bridge === bridge_out_commitment;

    // 2) Range-check the hidden withdraw_amount so the conservation equality cannot wrap
    component wd_bits = Num2Bits(64);
    wd_bits.in <== withdraw_amount;

    // 3) Verify each input commitment opens correctly and compute the total
    component ins = VerifyAmounts(N);
    for (var i = 0; i < N; i++) {
        ins.amounts[i] <== input_amounts[i];
        ins.randomness[i] <== input_randomness[i];
        ins.hashes[i] <== input_hashes[i];
    }

    // 4) Verify each output commitment opens correctly and compute the total
    component outs = VerifyAmounts(M);
    for (var j = 0; j < M; j++) {
        outs.amounts[j] <== output_amounts[j];
        outs.randomness[j] <== output_randomness[j];
        outs.hashes[j] <== output_hashes[j];
    }

    // 5) Conservation: spent input value covers the hidden withdrawal plus the change output(s)
    ins.sum === withdraw_amount + outs.sum;
}

component main { public [bridge_out_commitment, input_hashes, output_hashes] } = WithdrawVerify(2, 2);
