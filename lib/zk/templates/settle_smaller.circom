pragma circom 2.2.3;

include "utils/poseidon.circom";
include "commitments.circom";

// SettleSmallerVerify is run by the side of a matched pair whose locked input
// is fully consumed by the trade (no change cash). Because fill = inputs.sum
// in this case, there is no independent fill signal — the match commitment is
// computed directly over `inputs.sum`. Chain pairs this proof with the
// counterparty's settle_larger proof and asserts
// `larger.other_match_commitment == smaller.match_commitment` to enforce that
// both sides agreed on the same fill for the smaller side.
//
// counterparty_recv_commitment is bound into the public input vector but its
// (amount, random) opening is not verified — the counterparty opens it when
// they later spend the cash.
template SettleSmallerVerify(N) {
    // Public
    signal input match_commitment;               // = Poseidon(inputs.sum, r_match)
    signal input input_hashes[N];                // sender's locked cashes
    signal input counterparty_recv_commitment;   // counterparty's new cash, NOT opened here

    // Private
    signal input r_match;
    signal input input_amounts[N];
    signal input input_randomness[N];

    // 1) Open inputs (gives us inputs.sum)
    component ins = VerifyAmounts(N);
    for (var i = 0; i < N; i++) {
        ins.amounts[i] <== input_amounts[i];
        ins.randomness[i] <== input_randomness[i];
        ins.hashes[i] <== input_hashes[i];
    }

    // 2) Bind inputs.sum directly to match_commitment — no independent fill signal
    signal expected <== Poseidon(2)([ins.sum, r_match]);
    expected === match_commitment;
}

component main { public [match_commitment, input_hashes, counterparty_recv_commitment] } = SettleSmallerVerify(2);
