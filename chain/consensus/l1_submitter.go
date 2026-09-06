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

// BlockHeaderSubmission contains the L2 block header data submitted to L1.
type BlockHeaderSubmission struct {
	// L2BlockHeight is the height of the L2 block.
	L2BlockHeight common.BlockNum `json:"l2_block_height"`
	// L2BlockHash is the hash of the L2 block.
	L2BlockHash common.Hash `json:"l2_block_hash"`
	// TxnRoot is the merkle root of the block's transactions.
	TxnRoot common.Hash `json:"txn_root"`
	// MinerPubkey is the hex-encoded public key of the block miner.
	MinerPubkey string `json:"miner_pubkey"`
}

// L1HeaderSubmitter abstracts the submission of L2 block headers to L1
// and the confirmation polling of those submissions.
type L1HeaderSubmitter interface {
	// SubmitBlockHeader submits a block header to L1 and returns the L1 tx hash.
	SubmitBlockHeader(ctx context.Context, header *BlockHeaderSubmission) (l1TxHash string, err error)
	// IsConfirmed checks whether the L1 transaction with the given hash has been confirmed.
	IsConfirmed(ctx context.Context, l1TxHash string) (bool, error)
}

// pendingFinalization tracks a block awaiting L1 confirmation before finalization.
type pendingFinalization struct {
	block       *types.Block
	l1TxHash    string
	submittedAt time.Time
}

// MockL1HeaderSubmitter is a mock implementation of L1HeaderSubmitter.
// SubmitBlockHeader returns a random hex hash.
// IsConfirmed returns true after MockL1ConfirmDelay has elapsed since submission.
type MockL1HeaderSubmitter struct {
	// confirmDelay is the duration after which IsConfirmed returns true.
	confirmDelay time.Duration

	mu          sync.Mutex
	submissions map[string]time.Time // l1TxHash → submission time
}

// NewMockL1HeaderSubmitter creates a MockL1HeaderSubmitter with the given confirm delay.
// `confirmDelayMs` is the simulated L1 confirmation delay in milliseconds.
func NewMockL1HeaderSubmitter(confirmDelayMs int) *MockL1HeaderSubmitter {
	return &MockL1HeaderSubmitter{
		confirmDelay: time.Duration(confirmDelayMs) * time.Millisecond,
		submissions:  make(map[string]time.Time),
	}
}

// SubmitBlockHeader returns a random hex hash and records the submission time.
func (m *MockL1HeaderSubmitter) SubmitBlockHeader(_ context.Context, _ *BlockHeaderSubmission) (string, error) {
	hashBytes := make([]byte, 32)
	_, _ = rand.Read(hashBytes)
	txHash := hex.EncodeToString(hashBytes)

	m.mu.Lock()
	m.submissions[txHash] = time.Now()
	m.mu.Unlock()

	return txHash, nil
}

// IsConfirmed returns true if confirmDelay has elapsed since the submission.
func (m *MockL1HeaderSubmitter) IsConfirmed(_ context.Context, l1TxHash string) (bool, error) {
	m.mu.Lock()
	submittedAt, ok := m.submissions[l1TxHash]
	m.mu.Unlock()

	if !ok {
		return false, nil
	}
	return time.Since(submittedAt) >= m.confirmDelay, nil
}
