package consensus

import (
	"context"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/yu-org/yu/core/types"
)

// l1Ready builds a sealed block and seeds L1 so that every check passes: the
// header landed at `anchorHeight`, the budget cell is locked to the producer,
// and the allocation was written at `allocationHeight`.
func l1Ready(t *testing.T, anchorHeight, allocationHeight uint64) (
	*types.Block, *AnchoredHeader, *MockL1Reader, *MockL1PaymentVerifier,
) {
	t.Helper()

	verifier := &MockL1PaymentVerifier{}
	block, _, pub, _ := sealedRival(t, verifier)
	producer := hex.EncodeToString(pub.Bytes())

	// sealedRival recorded the allocation at L1 height 0; put it where this
	// test wants it instead.
	cdata, err := DecodeConsensusData(block.Extra)
	if err != nil {
		t.Fatalf("decoding the block's consensus data: %v", err)
	}
	if err := verifier.Allocate("0xprepay", producer, block.Height,
		cdata.L1Payment.Amount, cdata.L1Payment.Random, allocationHeight); err != nil {
		t.Fatalf("seeding the allocation: %v", err)
	}

	reader := &MockL1Reader{}
	reader.Anchor(block.Header, anchorHeight)
	args, err := Blake160(pub.Bytes())
	if err != nil {
		t.Fatalf("Blake160: %v", err)
	}
	reader.SetBudgetOwner("0xprepay", args)

	return block, &AnchoredHeader{Header: block.Header, L1Height: anchorHeight}, reader, verifier
}

func TestVerifyAnchoredHeaderAcceptsAFullyBackedHeader(t *testing.T) {
	// Anchored at 1000, allocation written at 976 — a lead of exactly 24.
	block, anchored, reader, verifier := l1Ready(t, 1000, 976)

	goal, err := VerifyAnchoredHeader(context.Background(), reader, verifier, anchored)
	if err != nil {
		t.Fatalf("a fully backed header must verify, got %v", err)
	}
	cdata, err := DecodeConsensusData(block.Extra)
	if err != nil {
		t.Fatalf("decoding consensus data: %v", err)
	}
	if want := CalcBlockScore(cdata.L1Payment.Amount, cdata.VRFResult.Output); goal.Cmp(want) != 0 {
		t.Fatalf("goal = %s, want %s", goal, want)
	}
}

// Anyone can write a submit cell. A header altered after sealing — here its
// timestamp — no longer hashes to its Hash field and must be refused.
func TestVerifyAnchoredHeaderRejectsAnAlteredHeader(t *testing.T) {
	_, anchored, reader, verifier := l1Ready(t, 1000, 976)

	forged := *anchored.Header
	forged.Timestamp++
	anchored.Header = &forged

	_, err := VerifyAnchoredHeader(context.Background(), reader, verifier, anchored)
	if !errors.Is(err, ErrBlockHashMismatch) {
		t.Fatalf("expected ErrBlockHashMismatch, got %v", err)
	}
}

// V7's first item: the budget cell has to be the producer's own. Without it
// the allocation read below is one the producer could have chosen.
func TestVerifyAnchoredHeaderRejectsABudgetCellOwnedByAnother(t *testing.T) {
	_, anchored, reader, verifier := l1Ready(t, 1000, 976)

	theirs, err := Blake160([]byte("somebody else"))
	if err != nil {
		t.Fatalf("Blake160: %v", err)
	}
	reader.SetBudgetOwner("0xprepay", theirs)

	_, err = VerifyAnchoredHeader(context.Background(), reader, verifier, anchored)
	if !errors.Is(err, ErrBudgetNotOwned) {
		t.Fatalf("expected ErrBudgetNotOwned, got %v", err)
	}
}

// V4: one block short of the required lead is short.
func TestVerifyAnchoredHeaderRejectsAnAllocationWrittenTooLate(t *testing.T) {
	// Anchored at 1000, allocation at 977 — a lead of 23.
	_, anchored, reader, verifier := l1Ready(t, 1000, 977)

	_, err := VerifyAnchoredHeader(context.Background(), reader, verifier, anchored)
	if !errors.Is(err, ErrPaymentTooLate) {
		t.Fatalf("expected ErrPaymentTooLate, got %v", err)
	}
}
