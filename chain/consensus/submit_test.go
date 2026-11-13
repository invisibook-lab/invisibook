package consensus

import (
	"testing"

	"github.com/yu-org/yu/common"
	"github.com/yu-org/yu/core/types"
)

// pendingAt wraps a bare block at `height` for the submission queue.
func pendingAt(height common.BlockNum) *pendingFinalization {
	return &pendingFinalization{block: &types.Block{Header: &types.Header{Height: height}}}
}

// An L2 running ahead of L1 must hold its headers until their window opens:
// one sent early lands before n+i, where no node looks, and the batch could
// never be decided. A header whose window has closed is not sent at all.
func TestSubmitOpenRespectsTheWindow(t *testing.T) {
	reader := &MockL1Reader{}
	// n=100, b=3, k=24: batch 0 opens at 100, batch 2 at 102.
	reader.SetTip(100)
	p := &ProofOfBuy{l1Reader: reader, l1Submitter: NewMockL1HeaderSubmitter(), schedule: testSchedule()}

	queued := []*pendingFinalization{pendingAt(1), pendingAt(7)}
	var pending []*pendingFinalization
	p.submitOpen(&queued, &pending)

	if len(pending) != 1 || pending[0].block.Height != 1 {
		t.Fatalf("submitted %d headers, want only height 1", len(pending))
	}
	if len(queued) != 1 || queued[0].block.Height != 7 {
		t.Fatalf("queued %d headers, want height 7 still waiting", len(queued))
	}

	// L1 moves to 125: batch 0's window [100, 124] has closed, batch 2's
	// [102, 126] is still open.
	reader.SetTip(125)
	queued = append(queued, pendingAt(2))
	p.submitOpen(&queued, &pending)

	if len(queued) != 0 {
		t.Fatalf("%d headers still queued, want none", len(queued))
	}
	if len(pending) != 2 || pending[1].block.Height != 7 {
		t.Fatalf("pending = %d headers, want height 7 added and height 2 dropped", len(pending))
	}
}
