package consensus

import (
	"context"
	"testing"

	"github.com/yu-org/yu/common"
)

// submitCommitment posts one commitment through the mock and returns its tx
// hash.
func submitCommitment(t *testing.T, m *MockL1CommitmentSubmitter, height common.BlockNum) string {
	t.Helper()
	txHash, err := m.SubmitCommitment(context.Background(), &BlockCommitment{
		L2BlockHeight: height,
		Commitment:    "0xcommitment",
	})
	if err != nil {
		t.Fatalf("SubmitCommitment: %v", err)
	}
	return txHash
}

// A submission the mock never handed out is reported as absent rather than as
// an error: "not on chain" is a normal state the caller acts on by resending,
// and conflating it with a failure would turn a retry into a dead stop.
func TestCommitmentOnChainReportsAbsenceWithoutError(t *testing.T) {
	m := NewMockL1CommitmentSubmitter()

	loc, err := m.CommitmentOnChain(context.Background(), "0xnever-submitted")
	if err != nil {
		t.Fatalf("an unknown submission must not error, got %v", err)
	}
	if loc != nil {
		t.Fatalf("location = %+v, want nil", loc)
	}
}

func TestCommitmentOnChainReportsALocation(t *testing.T) {
	m := NewMockL1CommitmentSubmitter()
	txHash := submitCommitment(t, m, 3)

	loc, err := m.CommitmentOnChain(context.Background(), txHash)
	if err != nil {
		t.Fatalf("CommitmentOnChain: %v", err)
	}
	if loc == nil {
		t.Fatal("a submitted commitment must report a location")
	}
	if loc.BlockHash == "" {
		t.Fatal("the location must name an L1 block")
	}

	// Asking twice must not move it: a verifier that reads the location later
	// has to find the same spot the submitter recorded.
	again, err := m.CommitmentOnChain(context.Background(), txHash)
	if err != nil {
		t.Fatalf("CommitmentOnChain: %v", err)
	}
	if again.BlockHash != loc.BlockHash || again.TxIdx != loc.TxIdx {
		t.Fatalf("location moved between reads: %+v then %+v", loc, again)
	}
}

// Two submissions must not look like they landed in the same place. A fixed
// stand-in would pass every test above while making every commitment appear to
// share one L1 block, which is exactly the fact the location exists to carry.
func TestCommitmentOnChainSeparatesSubmissions(t *testing.T) {
	m := NewMockL1CommitmentSubmitter()
	first := submitCommitment(t, m, 1)
	second := submitCommitment(t, m, 2)

	a, err := m.CommitmentOnChain(context.Background(), first)
	if err != nil {
		t.Fatalf("CommitmentOnChain: %v", err)
	}
	b, err := m.CommitmentOnChain(context.Background(), second)
	if err != nil {
		t.Fatalf("CommitmentOnChain: %v", err)
	}

	if a.BlockHash == b.BlockHash {
		t.Fatalf("two submissions share a location: %s", a.BlockHash)
	}
}
