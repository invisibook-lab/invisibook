package consensus

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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

// ErrSubmissionPending reports that a commitment is in L1's pool: sent,
// accepted, and not yet in a block.
var ErrSubmissionPending = errors.New("the commitment is still waiting in L1's pool")

// L1CommitmentSubmitter posts block commitments to L1 and reports whether they
// are on chain.
type L1CommitmentSubmitter interface {
	// SubmitCommitment posts one commitment to L1 and returns the L1 tx hash.
	SubmitCommitment(ctx context.Context, commitment *BlockCommitment) (l1TxHash string, err error)

	// CommitmentOnChain reports where `l1TxHash` landed, nil when L1 has no
	// record of it at all, or an error wrapping ErrSubmissionPending while it
	// is still waiting in L1's pool.
	//
	// The three answers drive three different actions, which is why waiting
	// is not folded into nil. A submission L1 has never heard of never landed
	// or was taken back by a reorg, and has to be sent again; one sitting in
	// the pool has to be left alone, because re-sending it rebuilds the very
	// same transaction — same opening, same commitment, same inputs — and the
	// node rejects it as a duplicate. Treating the two alike turns every
	// block's normal wait into a resubmission loop that can never succeed.
	//
	// The location is not a convenience. Whoever later verifies the opening
	// has to find this commitment on L1, and without a position that means
	// scanning the chain; the block hash also dates the anchoring, which is
	// what distinguishes a fork that existed at the time from one bought
	// afterwards (whitepaper §8.2).
	CommitmentOnChain(ctx context.Context, l1TxHash string) (*L1Location, error)
}

// L1Location pins a submission to one spot on L1.
//
// The block is named by hash rather than height so that a reorg is visible:
// a hash that is no longer on the canonical chain took the commitment with it.
type L1Location struct {
	// BlockHash is the L1 block carrying the submission.
	BlockHash string `json:"l1_block_hash"`
	// TxIdx is the transaction's index inside that block.
	TxIdx uint32 `json:"tx_idx"`
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

// CommitmentOnChain reports a made-up but stable location for any hash this
// mock handed out, and nil for anything else.
func (m *MockL1CommitmentSubmitter) CommitmentOnChain(_ context.Context, l1TxHash string) (*L1Location, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.commitments[l1TxHash]; !ok {
		return nil, nil
	}

	// Derived from the submission so that two of them never look like they
	// landed in the same place, which a fixed stand-in would.
	sum := sha256.Sum256([]byte("mock-l1-block:" + l1TxHash))
	return &L1Location{BlockHash: hex.EncodeToString(sum[:]), TxIdx: 0}, nil
}
