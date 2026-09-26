package consensus

import (
	"context"
	"fmt"
	"testing"

	"gorm.io/gorm/logger"

	"github.com/yu-org/yu/core/types"

	"github.com/invisibook-lab/invisibook/store"
)

// newTestPoB builds a ProofOfBuy carrying only what verifiedOpenings reads:
// the two L1 interfaces and a reveal store over an in-memory database.
func newTestPoB(t *testing.T, reader L1Reader, verifier L1PaymentVerifier) (*ProofOfBuy, *Reveals) {
	t.Helper()

	// A database per test: a shared-cache in-memory DSN is one database for
	// the whole process, so a fixed name would leak rows between tests.
	db, err := store.Open(fmt.Sprintf("file:%s?mode=memory&cache=shared", t.Name()), logger.Silent)
	if err != nil {
		t.Fatalf("opening the test database: %v", err)
	}
	if err := MigrateRevealTable(db); err != nil {
		t.Fatalf("migrating the reveal table: %v", err)
	}
	reveals := NewReveals(db)

	return &ProofOfBuy{l1Reader: reader, l1Verifier: verifier, reveals: reveals}, reveals
}

func TestVerifiedOpeningsAcceptsABlockBackedByL1(t *testing.T) {
	block, reveal, reader, verifier := l1Ready(t, 1000, 976)
	p, reveals := newTestPoB(t, reader, verifier)
	if err := reveals.Put(reveal.ToRow()); err != nil {
		t.Fatalf("storing the opening: %v", err)
	}

	opened := map[string]bool{}
	p.verifiedOpenings(context.Background(), []*types.Block{block}, opened)

	if !opened[block.Hash.String()] {
		t.Fatal("a block anchored, owned and paid for in time must count as opened")
	}
}

// The ordinary case, not a failure: an opening cannot go out before its
// commitment is in an L1 block, so a block this node has not seen revealed
// yet simply is not settled.
func TestVerifiedOpeningsHoldsWhileNothingIsRevealed(t *testing.T) {
	block, _, reader, verifier := l1Ready(t, 1000, 976)
	p, _ := newTestPoB(t, reader, verifier)

	opened := map[string]bool{}
	p.verifiedOpenings(context.Background(), []*types.Block{block}, opened)

	if len(opened) != 0 {
		t.Fatalf("opened = %v, want nothing settled without an opening", opened)
	}
}

// An opening is not enough on its own. Here the allocation was written 23
// blocks before the anchor instead of 24, so V4 refuses it — and a block L1
// does not back must not be written down.
func TestVerifiedOpeningsHoldsWhenL1DoesNotBackTheBlock(t *testing.T) {
	block, reveal, reader, verifier := l1Ready(t, 1000, 977)
	p, reveals := newTestPoB(t, reader, verifier)
	if err := reveals.Put(reveal.ToRow()); err != nil {
		t.Fatalf("storing the opening: %v", err)
	}

	opened := map[string]bool{}
	p.verifiedOpenings(context.Background(), []*types.Block{block}, opened)

	if len(opened) != 0 {
		t.Fatalf("opened = %v, want nothing settled when L1 does not back it", opened)
	}
}

// A reorg carrying the anchoring block away takes the block's backing with
// it, even though the opening is still on hand.
func TestVerifiedOpeningsHoldsAfterAnAnchorIsReorgedAway(t *testing.T) {
	block, reveal, reader, verifier := l1Ready(t, 1000, 976)
	p, reveals := newTestPoB(t, reader, verifier)
	if err := reveals.Put(reveal.ToRow()); err != nil {
		t.Fatalf("storing the opening: %v", err)
	}
	reader.Orphan(reveal.L1BlockHash)

	opened := map[string]bool{}
	p.verifiedOpenings(context.Background(), []*types.Block{block}, opened)

	if len(opened) != 0 {
		t.Fatalf("opened = %v, want nothing settled once the anchor is gone", opened)
	}
}
