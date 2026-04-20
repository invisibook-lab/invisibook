pragma circom  2.2.3;

include "poseidon.circom";
include "comparators.circom";

// OrderVerify proves that:
// 1. larger_amount hashes to larger_amount_hash (Poseidon commitment)
// 2. smaller_amount hashes to smaller_amount_hash (Poseidon commitment)
// 3. smaller_amount <= larger_amount
template OrderVerify() {
    // Public inputs: Poseidon hash commitments (known to verifier)
    signal input larger_amount_hash;
    signal input smaller_amount_hash;

    // Private inputs: plaintext amounts (hidden from verifier)
    signal input larger_amount;
    signal input smaller_amount;

    signal expected_larger_amount_hash <== Poseidon(1)([larger_amount]);
    expected_larger_amount_hash === larger_amount_hash;
    signal expected_smaller_amount_hash <== Poseidon(1)([smaller_amount]);
    expected_smaller_amount_hash === smaller_amount_hash;

    signal expected_leq <== LessEqThan(64)([smaller_amount, larger_amount]);
    expected_leq === 1;

    // TODO: Update the state of the order and the balance.
}

component main { public [larger_amount_hash, smaller_amount_hash] } = OrderVerify();
