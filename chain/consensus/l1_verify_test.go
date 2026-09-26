package consensus

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/yu-org/yu/core/types"
)

// l1Ready builds a block with its opening, and seeds L1 so that all three
// checks pass: the commitment is anchored at `anchorHeight`, the budget cell
// is locked to the producer, and the allocation was written at
// `allocationHeight`.
func l1Ready(t *testing.T, anchorHeight, allocationHeight uint64) (
	*types.Block, *BlockReveal, *MockL1Reader, *MockL1PaymentVerifier,
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

	random := strings.Repeat("ab", 32)
	commitment, err := CommitBlockHash(block.Hash, random)
	if err != nil {
		t.Fatalf("committing to the block hash: %v", err)
	}
	reveal := &BlockReveal{
		L2BlockHeight: block.Height,
		L2BlockHash:   block.Hash.String(),
		Random:        random,
		L1BlockHash:   "0xanchor",
		TxIdx:         1,
		MinerPubkey:   producer,
	}

	reader := &MockL1Reader{}
	reader.Anchor(&L1Location{BlockHash: reveal.L1BlockHash, TxIdx: reveal.TxIdx},
		commitment, anchorHeight)
	args, err := Blake160(pub.Bytes())
	if err != nil {
		t.Fatalf("Blake160: %v", err)
	}
	reader.SetBudgetOwner("0xprepay", args)

	return block, reveal, reader, verifier
}

func TestVerifyAgainstL1AcceptsAFullyBackedBlock(t *testing.T) {
	// Anchored at 1000, allocation written at 976 — a lead of exactly 24.
	block, reveal, reader, verifier := l1Ready(t, 1000, 976)

	if err := VerifyAgainstL1(context.Background(), reader, verifier, block, reveal); err != nil {
		t.Fatalf("a fully backed block must verify, got %v", err)
	}
}

// V1: the opening has to open the commitment L1 actually holds.
func TestVerifyAgainstL1RejectsAnOpeningThatDoesNotMatch(t *testing.T) {
	block, reveal, reader, verifier := l1Ready(t, 1000, 976)

	reveal.Random = strings.Repeat("cd", 32)

	err := VerifyAgainstL1(context.Background(), reader, verifier, block, reveal)
	if !errors.Is(err, ErrCommitmentMismatch) {
		t.Fatalf("expected ErrCommitmentMismatch, got %v", err)
	}
}

// V7's first item: the budget cell has to be the producer's own. Without it
// the allocation read below is one the producer could have chosen.
func TestVerifyAgainstL1RejectsABudgetCellOwnedByAnother(t *testing.T) {
	block, reveal, reader, verifier := l1Ready(t, 1000, 976)

	theirs, err := Blake160([]byte("somebody else"))
	if err != nil {
		t.Fatalf("Blake160: %v", err)
	}
	reader.SetBudgetOwner("0xprepay", theirs)

	err = VerifyAgainstL1(context.Background(), reader, verifier, block, reveal)
	if !errors.Is(err, ErrBudgetNotOwned) {
		t.Fatalf("expected ErrBudgetNotOwned, got %v", err)
	}
}

// V4: one block short of the required lead is short.
func TestVerifyAgainstL1RejectsAnAllocationWrittenTooLate(t *testing.T) {
	// Anchored at 1000, allocation at 977 — a lead of 23.
	block, reveal, reader, verifier := l1Ready(t, 1000, 977)

	err := VerifyAgainstL1(context.Background(), reader, verifier, block, reveal)
	if !errors.Is(err, ErrPaymentTooLate) {
		t.Fatalf("expected ErrPaymentTooLate, got %v", err)
	}
}

// A commitment whose L1 block a reorg took away backs nothing, however well
// the rest lines up.
func TestVerifyAgainstL1RejectsAnAnchorLostToAReorg(t *testing.T) {
	block, reveal, reader, verifier := l1Ready(t, 1000, 976)

	reader.Orphan(reveal.L1BlockHash)

	err := VerifyAgainstL1(context.Background(), reader, verifier, block, reveal)
	if !errors.Is(err, ErrNotOnChain) {
		t.Fatalf("expected ErrNotOnChain, got %v", err)
	}
}

func TestVerifyAgainstL1RejectsAHeaderlessBlock(t *testing.T) {
	_, reveal, reader, verifier := l1Ready(t, 1000, 976)

	if err := VerifyAgainstL1(context.Background(), reader, verifier, &types.Block{}, reveal); err == nil {
		t.Fatal("a block with no header must be refused")
	}
	if err := VerifyAgainstL1(context.Background(), reader, verifier, nil, reveal); err == nil {
		t.Fatal("a nil block must be refused")
	}
}
