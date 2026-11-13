package consensus

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/yu-org/yu/core/types"
)

// ErrSubmissionPending reports that a submission is in L1's pool: sent,
// accepted, and not yet in a block.
var ErrSubmissionPending = errors.New("the submission is still waiting in L1's pool")

// L1HeaderSubmitter posts L2 block headers to L1 and reports whether they are
// on chain.
type L1HeaderSubmitter interface {
	// SubmitHeader posts one header to L1 and returns the L1 tx hash.
	SubmitHeader(ctx context.Context, header *types.Header) (l1TxHash string, err error)

	// HeaderOnChain reports whether `l1TxHash` is in a block on L1's
	// canonical chain, false when L1 has no record of it at all, or an error
	// wrapping ErrSubmissionPending while it is still waiting in L1's pool.
	//
	// The three answers drive three different actions, which is why waiting
	// is not folded into false. A submission L1 has never heard of never
	// landed or was taken back by a reorg, and has to be sent again; one
	// sitting in the pool has to be left alone, because re-sending it rebuilds
	// the very same transaction and the node rejects it as a duplicate.
	HeaderOnChain(ctx context.Context, l1TxHash string) (bool, error)
}

// pendingFinalization tracks a block whose header has been sent to L1.
type pendingFinalization struct {
	block       *types.Block
	l1TxHash    string
	submittedAt time.Time
}

// MockL1HeaderSubmitter is a mock implementation of L1HeaderSubmitter.
// SubmitHeader returns a random hex hash, and every hash it handed out is
// reported as on chain — enough for a single node with no rivals.
type MockL1HeaderSubmitter struct {
	mu      sync.Mutex
	headers map[string]*types.Header // l1TxHash → what was submitted
}

// NewMockL1HeaderSubmitter creates a mock submitter.
func NewMockL1HeaderSubmitter() *MockL1HeaderSubmitter {
	return &MockL1HeaderSubmitter{
		headers: make(map[string]*types.Header),
	}
}

// SubmitHeader returns a random hex hash and records what was submitted.
func (m *MockL1HeaderSubmitter) SubmitHeader(_ context.Context, header *types.Header) (string, error) {
	hashBytes := make([]byte, 32)
	_, _ = rand.Read(hashBytes)
	txHash := hex.EncodeToString(hashBytes)

	m.mu.Lock()
	m.headers[txHash] = header
	m.mu.Unlock()

	return txHash, nil
}

// HeaderOnChain reports true for any hash this mock handed out.
func (m *MockL1HeaderSubmitter) HeaderOnChain(_ context.Context, l1TxHash string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.headers[l1TxHash]
	return ok, nil
}
