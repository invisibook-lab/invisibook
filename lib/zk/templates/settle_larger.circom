pragma circom 2.2.3;

include "utils/bitify.circom";
include "utils/poseidon.circom";
include "commitments.circom";

// SettleLargerVerify is run by the side of a matched pair whose locked input
// strictly exceeds the trade's fill (i.e. the order will produce a change cash).
// It binds BOTH sides' fill commitments so chain can later check the
// counterparty's separately-produced settle proof references the same fill on
// the smaller side. It also enforces the cross-leg ratio
// `fill_t2 == fill_t1 * price` that ties the two token groups together.
//
// counterparty_recv_commitment is included as a public input so the proof is
// bound to the specific counterparty cash being minted, but its (amount,
// random) opening is NOT verified here — the sender doesn't know the
// counterparty's random. The counterparty will open it themselves when they
// later spend the cash.
template SettleLargerVerify(N) {
    // Public
    signal input my_match_commitment;            // = Poseidon(inputs.sum - change_amount, r_my)
    signal input other_match_commitment;         // = Poseidon(other_fill, r_other) — counterparty's fill commitment
    signal input price;                          // plaintext, equals on-chain order.Price
    signal input is_token2_sender;               // 1 if I'm Token2 sender, 0 if Token1 sender
    signal input input_hashes[N];                // sender's locked cashes
    signal input change_commitment;              // sender's change cash (zero pad if change_amount == 0)
    signal input counterparty_recv_commitment;   // counterparty's new cash, NOT opened here

    // Private
    signal input r_my;
    signal input other_fill;
    signal input r_other;
    signal input input_amounts[N];
    signal input input_randomness[N];
    signal input change_amount;
    signal input change_random;

    // 1) is_token2_sender must be a boolean
    is_token2_sender * (is_token2_sender - 1) === 0;

    // 2) Open the sender's input commitments (they know their own randoms)
    component ins = VerifyAmounts(N);
    for (var i = 0; i < N; i++) {
        ins.amounts[i] <== input_amounts[i];
        ins.randomness[i] <== input_randomness[i];
        ins.hashes[i] <== input_hashes[i];
    }

    // 3) Open the change commitment
    signal expected_change <== Poseidon(2)([change_amount, change_random]);
    expected_change === change_commitment;

    // 4) my_fill = inputs.sum - change_amount — derived signal, not an independent input
    signal my_fill <== ins.sum - change_amount;

    // 5) Range checks defend against field wrap on the subtraction + multiplication below
    component my_fill_bits = Num2Bits(64);   my_fill_bits.in <== my_fill;
    component change_bits  = Num2Bits(64);   change_bits.in  <== change_amount;
    component other_bits   = Num2Bits(64);   other_bits.in   <== other_fill;

    // 6) Bind both fills to their respective public commitments
    signal expected_my    <== Poseidon(2)([my_fill, r_my]);
    expected_my    === my_match_commitment;
    signal expected_other <== Poseidon(2)([other_fill, r_other]);
    expected_other === other_match_commitment;

    // 7) Cross-leg ratio: fill_t2 === fill_t1 * price
    //    Mux: (fill_t1, fill_t2) = is_token2_sender ? (other_fill, my_fill) : (my_fill, other_fill)
    signal fill_t1 <== my_fill + is_token2_sender * (other_fill - my_fill);
    signal fill_t2 <== other_fill + is_token2_sender * (my_fill - other_fill);
    fill_t2 === fill_t1 * price;
}

component main { public [my_match_commitment, other_match_commitment, price, is_token2_sender, input_hashes, change_commitment, counterparty_recv_commitment] } = SettleLargerVerify(2);
