package consensus

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/yu-org/yu/common"
)

// anchoredReveal builds a reveal and records its commitment on L1 at
// `l1Height`, the way a submission that reached an L1 block would.
func anchoredReveal(t *testing.T, reader *MockL1Reader, l1Height uint64) *BlockReveal {
	t.Helper()

	blockHash := common.BytesToHash([]byte("the block"))
	random := strings.Repeat("ab", 32)
	commitment, err := CommitBlockHash(blockHash, random)
	if err != nil {
		t.Fatalf("committing to the block hash: %v", err)
	}

	reveal := &BlockReveal{
		L2BlockHeight: 7,
		L2BlockHash:   blockHash.String(),
		Random:        random,
		L1BlockHash:   "0xl1block",
		TxIdx:         3,
		MinerPubkey:   "0xminer",
	}
	reader.Anchor(&L1Location{BlockHash: reveal.L1BlockHash, TxIdx: reveal.TxIdx}, commitment, l1Height)
	return reveal
}

// V1 yields the anchoring height, which is as much the point as the check:
// V4 measures the payment against it.
func TestVerifyAnchorReturnsTheAnchoringHeight(t *testing.T) {
	reader := &MockL1Reader{}
	reveal := anchoredReveal(t, reader, 1000)

	height, err := VerifyAnchor(context.Background(), reader, reveal)

	if err != nil {
		t.Fatalf("VerifyAnchor: %v", err)
	}
	if height != 1000 {
		t.Fatalf("anchoring height = %d, want 1000", height)
	}
}

// The opening has to open what L1 actually holds. A miner revealing a
// different blinding factor produces a different commitment.
func TestVerifyAnchorRejectsAnOpeningThatDoesNotMatch(t *testing.T) {
	reader := &MockL1Reader{}
	reveal := anchoredReveal(t, reader, 1000)

	reveal.Random = strings.Repeat("cd", 32)

	if _, err := VerifyAnchor(context.Background(), reader, reveal); !errors.Is(err, ErrCommitmentMismatch) {
		t.Fatalf("expected ErrCommitmentMismatch, got %v", err)
	}
}

// A commitment in a block that a reorg took away counts for nothing. This is
// exactly why a reveal names that block by hash and not by height: a height
// would still resolve afterwards, and the commitment would appear to stand.
func TestVerifyAnchorRejectsACommitmentLostToAReorg(t *testing.T) {
	reader := &MockL1Reader{}
	reveal := anchoredReveal(t, reader, 1000)

	reader.Orphan(reveal.L1BlockHash)

	if _, err := VerifyAnchor(context.Background(), reader, reveal); !errors.Is(err, ErrNotOnChain) {
		t.Fatalf("expected ErrNotOnChain, got %v", err)
	}
}

func TestVerifyAnchorRejectsACommitmentThatIsNotThere(t *testing.T) {
	reveal := &BlockReveal{
		L2BlockHash: common.BytesToHash([]byte("unanchored")).String(),
		Random:      strings.Repeat("ab", 32),
		L1BlockHash: "0xnowhere",
	}

	if _, err := VerifyAnchor(context.Background(), &MockL1Reader{}, reveal); err == nil {
		t.Fatal("a commitment that is not on L1 must be refused")
	}
}

func TestVerifyAnchorRejectsAMissingReveal(t *testing.T) {
	if _, err := VerifyAnchor(context.Background(), &MockL1Reader{}, nil); err == nil {
		t.Fatal("a nil reveal must be refused")
	}
}

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
