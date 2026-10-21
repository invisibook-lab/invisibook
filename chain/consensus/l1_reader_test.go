package consensus

import (
	"context"
	"errors"
	"testing"
)

// The lead is 24 L1 blocks — whitepaper §7.3 and §9.3.
//
// Written as a literal on purpose. A test that measured the boundary against
// PaymentLeadBlocks itself would follow the constant silently wherever it
// went, and this is a protocol parameter: the number was chosen to outlast
// L1 fork convergence, and changing it changes what the chain is safe
// against. It should take a deliberate edit here to move it.
func TestPaymentLeadIsTwentyFourL1Blocks(t *testing.T) {
	if PaymentLeadBlocks != 24 {
		t.Fatalf("PaymentLeadBlocks = %d, want 24 — see whitepaper §7.3", PaymentLeadBlocks)
	}
}

// V4's boundary is exact: a lead of precisely 24 passes, 23 does not.
func TestVerifyPaymentLeadAtTheBoundary(t *testing.T) {
	const anchor uint64 = 1000

	if err := VerifyPaymentLead(anchor-24, anchor); err != nil {
		t.Fatalf("a lead of exactly 24 must pass, got %v", err)
	}
	if err := VerifyPaymentLead(anchor-23, anchor); !errors.Is(err, ErrPaymentTooLate) {
		t.Fatalf("a lead of 23 must fail, got %v", err)
	}
}

// An allocation written after the block that spends it is the extreme case:
// the miner would be choosing what to pay once the round was already decided.
func TestVerifyPaymentLeadRejectsAnAllocationWrittenLater(t *testing.T) {
	if err := VerifyPaymentLead(1001, 1000); !errors.Is(err, ErrPaymentTooLate) {
		t.Fatalf("expected ErrPaymentTooLate, got %v", err)
	}
}

func TestVerifyBudgetOwnerAcceptsTheProducersOwnCell(t *testing.T) {
	pubkey := []byte{0x02, 0xaa, 0xbb}
	args, err := Blake160(pubkey)
	if err != nil {
		t.Fatalf("Blake160: %v", err)
	}
	reader := &MockL1Reader{}
	reader.SetBudgetOwner("0xprepay", args)

	if err := VerifyBudgetOwner(context.Background(), reader, "0xprepay", pubkey); err != nil {
		t.Fatalf("a producer's own budget cell must be accepted, got %v", err)
	}
}

// The attack this closes: a miner drawing on someone else's prepayment.
// FetchAllocation is told which miner to look up, so without this check a
// miner naming itself gets its own answer back, and V3 ends up comparing
// against a commitment the miner supplied.
func TestVerifyBudgetOwnerRejectsAnotherMinersCell(t *testing.T) {
	theirs, err := Blake160([]byte{0x02, 0xaa})
	if err != nil {
		t.Fatalf("Blake160: %v", err)
	}
	reader := &MockL1Reader{}
	reader.SetBudgetOwner("0xprepay", theirs)

	err = VerifyBudgetOwner(context.Background(), reader, "0xprepay", []byte{0x02, 0xbb})

	if !errors.Is(err, ErrBudgetNotOwned) {
		t.Fatalf("expected ErrBudgetNotOwned, got %v", err)
	}
}

func TestVerifyBudgetOwnerReportsAMissingCell(t *testing.T) {
	err := VerifyBudgetOwner(context.Background(), &MockL1Reader{}, "0xnothing", []byte{0x02})

	if err == nil {
		t.Fatal("a transaction that created no budget cell must be refused")
	}
}
