package consensus

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"github.com/yu-org/yu/common"
	"github.com/yu-org/yu/core/types"
)

// BlockCommitment is what a miner posts on L1 for one L2 block: a single
// 32-byte value, and nothing else.
//
// The header and the score stay off chain deliberately. Every submission has
// to be packed by an L1 block producer before it reaches the chain, so
// anything legible here is something that producer could censor selectively —
// see proof_of_buy.md §9.6. What it gets to see instead is a structureless
// hash it cannot tell apart from any other.
//
// Only `Commitment` goes on chain. `L2BlockHeight` travels with it for logging
// and local bookkeeping; the height itself is bound inside the commitment.
type BlockCommitment struct {
	// L2BlockHeight is the height of the L2 block being committed to.
	L2BlockHeight common.BlockNum `json:"l2_block_height"`
	// Commitment is CommitBlockHash's output, a 64-char hex string.
	Commitment string `json:"commitment"`
}

// L1CommitmentSubmitter posts block commitments to L1 and reports how deeply
// each submission has been buried.
type L1CommitmentSubmitter interface {
	// SubmitCommitment posts one commitment to L1 and returns the L1 tx hash.
	SubmitCommitment(ctx context.Context, commitment *BlockCommitment) (l1TxHash string, err error)

	// ConfirmedDepth reports how many L1 blocks have been mined on top of the
	// one carrying `l1TxHash`, counting that block itself as depth 1.
	//
	// `found` separates "not yet deep enough" from "not on chain at all": the
	// first is a matter of waiting, the second means the submission never
	// landed and has to be sent again. A single bool could not tell a caller
	// which of the two it was looking at.
	ConfirmedDepth(ctx context.Context, l1TxHash string) (depth uint64, found bool, err error)
}

// pendingFinalization tracks a block awaiting enough depth on L1.
type pendingFinalization struct {
	block       *types.Block
	l1TxHash    string
	submittedAt time.Time
}

// MockL1CommitmentSubmitter is a mock implementation of L1CommitmentSubmitter.
// SubmitCommitment returns a random hex hash; ConfirmedDepth grows by one for
// every blockTime that has elapsed since the submission, simulating an L1 that
// keeps producing blocks on top of it.
type MockL1CommitmentSubmitter struct {
	// blockTime is the simulated L1 block interval.
	blockTime time.Duration

	mu          sync.Mutex
	submissions map[string]time.Time        // l1TxHash → submission time
	commitments map[string]*BlockCommitment // l1TxHash → what was submitted
}

// NewMockL1CommitmentSubmitter creates a mock submitter.
// `blockTimeMs` is the simulated L1 block interval in milliseconds and must be
// positive; a non-positive value would make every submission look infinitely
// deep the moment it was sent.
func NewMockL1CommitmentSubmitter(blockTimeMs int) *MockL1CommitmentSubmitter {
	if blockTimeMs <= 0 {
		blockTimeMs = 1
	}
	return &MockL1CommitmentSubmitter{
		blockTime:   time.Duration(blockTimeMs) * time.Millisecond,
		submissions: make(map[string]time.Time),
		commitments: make(map[string]*BlockCommitment),
	}
}

// SubmitCommitment returns a random hex hash and records the submission time.
func (m *MockL1CommitmentSubmitter) SubmitCommitment(_ context.Context, commitment *BlockCommitment) (string, error) {
	hashBytes := make([]byte, 32)
	_, _ = rand.Read(hashBytes)
	txHash := hex.EncodeToString(hashBytes)

	m.mu.Lock()
	m.submissions[txHash] = time.Now()
	m.commitments[txHash] = commitment
	m.mu.Unlock()

	return txHash, nil
}

// ConfirmedDepth reports one block of depth per elapsed blockTime, and
// found=false for a hash this mock never handed out.
func (m *MockL1CommitmentSubmitter) ConfirmedDepth(_ context.Context, l1TxHash string) (uint64, bool, error) {
	m.mu.Lock()
	submittedAt, ok := m.submissions[l1TxHash]
	m.mu.Unlock()

	if !ok {
		return 0, false, nil
	}
	return uint64(time.Since(submittedAt)/m.blockTime) + 1, true, nil
}
