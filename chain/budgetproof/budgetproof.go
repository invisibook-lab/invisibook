// Package budgetproof proves that a budget cell's allocation table adds up to
// its prepaid total (R3.2), for the budget cell's type script to verify on
// L1.
//
// The prover is Rust (lib/budget-stark, Plonky3), linked in as a static
// library over cgo when built with `-tags budgetstark` (see prove_cgo.go and
// `make build-pob-miner`). Only pob-miner imports this package; the node never
// proves. Built without the tag, Prove refuses (prove_stub.go).
package budgetproof

import (
	"encoding/hex"
	"errors"
	"fmt"
)

// ErrUnavailable is returned by Prove in a binary built without the prover.
var ErrUnavailable = errors.New(
	"this binary was built without the budget prover; rebuild with `make build-pob-miner` (go build -tags budgetstark)")

// Proof is a balance proof together with what it was made over.
type Proof struct {
	// Prepaid is the total the proof is for: the sum of the amounts.
	Prepaid uint64
	// Commitments are the table's commitments in order, 64 hex characters
	// each — identical to consensus.PaymentCommit on the same openings.
	Commitments []string
	// Bytes is the proof, for the budget cell's witness.
	Bytes []byte
}

// Prove proves that the table of `amounts[i]` under blinding factors
// `randoms[i]` balances. The two slices must have the same, non-zero length;
// every random must be 64 hex characters of canonical words (as
// consensus.NewPaymentRandomHex produces).
func Prove(amounts []uint64, randoms []string) (*Proof, error) {
	if len(amounts) == 0 {
		return nil, errors.New("the allocation table is empty")
	}
	if len(amounts) != len(randoms) {
		return nil, fmt.Errorf("%d amounts but %d blinding factors", len(amounts), len(randoms))
	}
	packed := make([]byte, 0, 32*len(randoms))
	for i, r := range randoms {
		raw, err := hex.DecodeString(r)
		if err != nil || len(raw) != 32 {
			return nil, fmt.Errorf("blinding factor %d is not 32 bytes of hex", i)
		}
		packed = append(packed, raw...)
	}
	return prove(amounts, packed)
}
