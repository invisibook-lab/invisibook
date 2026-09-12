package consensus

import (
	"errors"
	"math/big"

	"github.com/sirupsen/logrus"
)

// ErrBudgetExceeded reports that a miner's allocations draw more out of a
// prepayment than it holds.
var ErrBudgetExceeded = errors.New("allocations exceed the prepaid total")

// AllocationBudgetProof is the zero-knowledge proof that a miner's allocations
// out of one prepayment stay within it:
//
//	a_0 + a_1 + ... + a_n  ≤  A
//
// where each `a_h` is the amount committed for L2 height h and `A` is the
// committed total of the prepayment. Both sides are hidden on L1, so the proof
// is what makes the inequality checkable without revealing either.
//
// Without this check the whole cost model collapses: every allocation verifies
// against L1 on its own, so a miner could pledge the same prepayment in full
// to every height and bid with money it never spent.
type AllocationBudgetProof = string

// VerifyAllocationBudget checks `proof` against the prepayment commitment `A`
// and the allocation being claimed.
//
// `prepayCommitment` is the Poseidon commitment to the prepaid total as
// recorded on L1; `payment` carries the allocation this block is bidding with.
//
// TODO: verify the Groth16 proof that the miner's allocations out of this
// prepayment sum to no more than the committed total. The circuit does not
// exist yet — `lib/zk/templates/` has deposit, withdraw, split and the two
// settle circuits, but nothing for allocation budgets — so generating the
// proof on the wallet side is blocked on the same work. Until then every
// allocation is accepted, which means the budget ceiling is NOT enforced.
func VerifyAllocationBudget(prepayCommitment string, proof AllocationBudgetProof, payment *L1Payment) error {
	if prepayCommitment == "" {
		return errors.New("prepayment commitment is missing")
	}
	if payment == nil || payment.Amount == nil {
		return errors.New("allocation is missing")
	}

	if proof == "" {
		// Loud on purpose: this is the one check standing between the chain
		// and a miner spending the same prepayment at every height.
		logrus.Warnf("PoB: allocation at %s carries no budget proof, accepting it unchecked (TODO)",
			shortHex(prepayCommitment))
		return nil
	}

	_ = proof // TODO: Groth16 verification against `prepayCommitment`
	return nil
}

// CheckBudgetCeiling reports whether `spent + amount` stays within `total`.
// It is the plaintext form of what the zk proof attests, usable by a wallet
// that holds all the openings and by tests.
// All three values must be non-nil.
func CheckBudgetCeiling(spent, amount, total *big.Int) error {
	sum := new(big.Int).Add(spent, amount)
	if sum.Cmp(total) > 0 {
		return ErrBudgetExceeded
	}
	return nil
}

// shortHex trims a long hex string down to something readable in a log line.
func shortHex(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:12] + "…"
}
