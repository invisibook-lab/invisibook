package consensus

import (
	"context"
	"testing"

	"github.com/yu-org/yu/common"
	"github.com/yu-org/yu/core/types"
)

// A submission the mock never handed out is reported as absent rather than as
// an error: "not on chain" is a normal state the caller acts on by resending,
// and conflating it with a failure would turn a retry into a dead stop.
func TestHeaderOnChainReportsAbsenceWithoutError(t *testing.T) {
	m := NewMockL1HeaderSubmitter()

	onChain, err := m.HeaderOnChain(context.Background(), "0xnever-submitted")
	if err != nil {
		t.Fatalf("an unknown submission must not error, got %v", err)
	}
	if onChain {
		t.Fatal("an unknown submission must not be reported as on chain")
	}
}

func TestHeaderOnChainReportsASubmission(t *testing.T) {
	m := NewMockL1HeaderSubmitter()
	txHash, err := m.SubmitHeader(context.Background(), &types.Header{Height: common.BlockNum(3)})
	if err != nil {
		t.Fatalf("SubmitHeader: %v", err)
	}

	onChain, err := m.HeaderOnChain(context.Background(), txHash)
	if err != nil {
		t.Fatalf("HeaderOnChain: %v", err)
	}
	if !onChain {
		t.Fatal("a submitted header must be reported as on chain")
	}
}
