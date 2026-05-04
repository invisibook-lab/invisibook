pragma circom 2.2.3;

include "utils/bitify.circom";
include "utils/poseidon.circom";
include "commitments.circom";

// DepositVerify proves that the M output Cash amounts collectively equal a
// hidden `deposit_amount`, which is bound to a public `bridge_commitment`
// supplied (eventually) by the source-chain bridge proof:
// `bridge_commitment = Poseidon(2)([deposit_amount, r_bridge])`.
// Hiding `deposit_amount` keeps the on-chain receipt from leaking the bridged
// value; binding it to the bridge commitment prevents the prover from minting
// outputs that don't match what the bridge attests was deposited.
// Each output commitment hides an amount under a per-output blinding factor
// (`output_randomness[i]`). Slots not used by the deposit must commit to
// amount 0 (i.e. `output_amounts[i] = 0` and `output_hashes[i] =
// Poseidon(2)([0, output_randomness[i]])`).
template DepositVerify(M) {
    // Public: bridge commitment and Poseidon hashes of every output Cash
    signal input bridge_commitment;
    signal input output_hashes[M];

    // Private: hidden bridged amount + its blinding factor, plus per-output amounts and randomness
    signal input deposit_amount;
    signal input r_bridge;
    signal input output_amounts[M];
    signal input output_randomness[M];

    // 1) Bridge binding: prover must know an opening (deposit_amount, r_bridge) of bridge_commitment
    signal expected_bridge <== Poseidon(2)([deposit_amount, r_bridge]);
    expected_bridge === bridge_commitment;

    // 2) Range-check the hidden deposit_amount so the conservation equality cannot wrap
    component dep_bits = Num2Bits(64);
    dep_bits.in <== deposit_amount;

    // 3) Verify each output commitment opens correctly and compute the total
    component outs = VerifyAmounts(M);
    for (var i = 0; i < M; i++) {
        outs.amounts[i] <== output_amounts[i];
        outs.randomness[i] <== output_randomness[i];
        outs.hashes[i] <== output_hashes[i];
    }

    // 4) Conservation: minted output value equals the hidden bridged amount
    outs.sum === deposit_amount;
}

component main { public [bridge_commitment, output_hashes] } = DepositVerify(2);
