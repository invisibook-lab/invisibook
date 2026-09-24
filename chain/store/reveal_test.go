package store

import (
	"testing"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/yu-org/yu/common"
)

// newReveals opens an in-memory chain database with the reveal table migrated.
func newReveals(t *testing.T) *Reveals {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("opening the in-memory database: %v", err)
	}
	if err := MigrateRevealTable(db); err != nil {
		t.Fatalf("migrating the reveal table: %v", err)
	}
	return NewReveals(db)
}

// sampleReveal is one well-formed opening at the given height.
func sampleReveal(hash string, height common.BlockNum) *Reveal {
	return &Reveal{
		BlockHash:   hash,
		Height:      height,
		Random:      "ab",
		L1BlockHash: "0xl1block",
		TxIdx:       3,
		MinerPubkey: "0xminer",
	}
}

func TestRevealsRoundTrip(t *testing.T) {
	reveals := newReveals(t)
	want := sampleReveal("0xblock", 7)

	if err := reveals.Put(want); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := reveals.Get("0xblock")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got == nil {
		t.Fatal("Get returned nothing for a reveal that was stored")
	}
	if got.Random != want.Random || got.L1BlockHash != want.L1BlockHash || got.TxIdx != want.TxIdx {
		t.Fatalf("Get = %+v, want %+v", got, want)
	}
}

// A block nobody has revealed yet is an ordinary state, not a failure: the
// opening may simply still be waiting on its commitment to reach L1.
func TestRevealsGetMissingIsNotAnError(t *testing.T) {
	reveals := newReveals(t)

	got, err := reveals.Get("0xnever-revealed")
	if err != nil {
		t.Fatalf("Get on an unknown block must not error, got %v", err)
	}
	if got != nil {
		t.Fatalf("Get = %+v, want nil", got)
	}
}

// Fork choice reads by height, and one height can carry several competing
// blocks — so the store has to hand back all of them, not just one.
func TestRevealsAtHeightReturnsEveryCompetitor(t *testing.T) {
	reveals := newReveals(t)
	for _, hash := range []string{"0xa", "0xb", "0xc"} {
		if err := reveals.Put(sampleReveal(hash, 9)); err != nil {
			t.Fatalf("Put %s: %v", hash, err)
		}
	}
	if err := reveals.Put(sampleReveal("0xother", 10)); err != nil {
		t.Fatalf("Put at another height: %v", err)
	}

	got, err := reveals.AtHeight(9)
	if err != nil {
		t.Fatalf("AtHeight: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("AtHeight(9) returned %d reveals, want 3", len(got))
	}
	for _, r := range got {
		if r.Height != 9 {
			t.Fatalf("AtHeight(9) returned a reveal at height %d", r.Height)
		}
	}
}

// What a starting node asks a peer for: everything from where its own record
// stops.
func TestRevealsSinceHeight(t *testing.T) {
	reveals := newReveals(t)
	for i, hash := range []string{"0xh5", "0xh6", "0xh7"} {
		if err := reveals.Put(sampleReveal(hash, common.BlockNum(5+i))); err != nil {
			t.Fatalf("Put %s: %v", hash, err)
		}
	}

	got, err := reveals.SinceHeight(6, 0)
	if err != nil {
		t.Fatalf("SinceHeight: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("SinceHeight(6) returned %d reveals, want 2", len(got))
	}
	// Ascending order matters: a catching-up node applies them in chain order.
	if got[0].Height != 6 || got[1].Height != 7 {
		t.Fatalf("SinceHeight(6) = heights %d,%d, want 6,7", got[0].Height, got[1].Height)
	}
}

func TestRevealsHighestHeight(t *testing.T) {
	reveals := newReveals(t)

	// An empty store reports 0 rather than failing: a fresh node has nothing
	// and must still be able to ask peers for everything.
	height, err := reveals.HighestHeight()
	if err != nil {
		t.Fatalf("HighestHeight on an empty store: %v", err)
	}
	if height != 0 {
		t.Fatalf("HighestHeight = %d on an empty store, want 0", height)
	}

	for i, hash := range []string{"0xa", "0xb"} {
		if err := reveals.Put(sampleReveal(hash, common.BlockNum(4+i*3))); err != nil {
			t.Fatalf("Put %s: %v", hash, err)
		}
	}
	height, err = reveals.HighestHeight()
	if err != nil {
		t.Fatalf("HighestHeight: %v", err)
	}
	if height != 7 {
		t.Fatalf("HighestHeight = %d, want 7", height)
	}
}

// An opening with no blinding factor cannot open anything, so it is refused
// rather than stored as a row that will never be usable.
func TestRevealsPutRejectsAnEmptyOpening(t *testing.T) {
	reveals := newReveals(t)

	if err := reveals.Put(&Reveal{BlockHash: "0xblock", Height: 1}); err == nil {
		t.Fatal("a reveal with no random must be rejected")
	}
	if err := reveals.Put(&Reveal{Height: 1, Random: "ab"}); err == nil {
		t.Fatal("a reveal with no block hash must be rejected")
	}
	if err := reveals.Put(nil); err == nil {
		t.Fatal("a nil reveal must be rejected")
	}
}
