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

// L1CommitmentSubmitter posts block commitments to L1 and reports whether they
// are on chain.
type L1CommitmentSubmitter interface {
	// SubmitCommitment posts one commitment to L1 and returns the L1 tx hash.
	SubmitCommitment(ctx context.Context, commitment *BlockCommitment) (l1TxHash string, err error)

	// CommitmentOnChain reports whether `l1TxHash` is in an L1 block.
	//
	// A submission that is not on chain never landed, or was taken back by an
	// L1 reorg; either way it has to be sent again, which is the only decision
	// this answer drives. How deep it sits once it is there is deliberately
	// not reported: nothing in PoB turns on a depth threshold — finality comes
	// from fork choice on L2, not from waiting out L1 blocks.
	CommitmentOnChain(ctx context.Context, l1TxHash string) (bool, error)
}

// pendingFinalization tracks a block whose commitment has been sent to L1.
type pendingFinalization struct {
	block       *types.Block
	l1TxHash    string
	submittedAt time.Time
}

// MockL1CommitmentSubmitter is a mock implementation of L1CommitmentSubmitter.
// SubmitCommitment returns a random hex hash, and every hash it handed out is
// reported as on chain — enough for a single node with no rivals.
type MockL1CommitmentSubmitter struct {
	mu          sync.Mutex
	commitments map[string]*BlockCommitment // l1TxHash → what was submitted
}

// NewMockL1CommitmentSubmitter creates a mock submitter.
func NewMockL1CommitmentSubmitter() *MockL1CommitmentSubmitter {
	return &MockL1CommitmentSubmitter{
		commitments: make(map[string]*BlockCommitment),
	}
}

// SubmitCommitment returns a random hex hash and records what was submitted.
func (m *MockL1CommitmentSubmitter) SubmitCommitment(_ context.Context, commitment *BlockCommitment) (string, error) {
	hashBytes := make([]byte, 32)
	_, _ = rand.Read(hashBytes)
	txHash := hex.EncodeToString(hashBytes)

	m.mu.Lock()
	m.commitments[txHash] = commitment
	m.mu.Unlock()

	return txHash, nil
}

// CommitmentOnChain reports true for any hash this mock handed out.
func (m *MockL1CommitmentSubmitter) CommitmentOnChain(_ context.Context, l1TxHash string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.commitments[l1TxHash]
	return ok, nil
}
