package consensus

import (
	"testing"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// newBids opens an in-memory chain database with the bid table migrated.
func newBids(t *testing.T) *Bids {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("opening the in-memory database: %v", err)
	}
	if err := MigrateBidTable(db); err != nil {
		t.Fatalf("migrating the bid table: %v", err)
	}
	return NewBids(db)
}

// sampleBid is one well-formed opening.
func sampleBid() *BlockBid {
	return &BlockBid{
		BlockHash:  "0xblock",
		Height:     7,
		Goal:       "123456789",
		Random:     "ab",
		Commitment: "0xcommitment",
	}
}

func TestBidsRoundTrip(t *testing.T) {
	bids := newBids(t)
	want := sampleBid()

	if err := bids.Save(want); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := bids.Get(want.BlockHash)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got == nil {
		t.Fatal("Get returned nothing for a bid that was saved")
	}
	if got.Random != want.Random || got.Commitment != want.Commitment || got.Goal != want.Goal {
		t.Fatalf("Get = %+v, want %+v", got, want)
	}
	if got.Height != want.Height {
		t.Fatalf("height = %d, want %d", got.Height, want.Height)
	}
}

// TestBidsGetMissingIsNotAnError: a block this node never bid on is a normal
// state, not a failure — the caller distinguishes it by the nil result.
func TestBidsGetMissingIsNotAnError(t *testing.T) {
	bids := newBids(t)

	got, err := bids.Get("0xnever-bid-on")
	if err != nil {
		t.Fatalf("Get on an unknown block must not error, got %v", err)
	}
	if got != nil {
		t.Fatalf("Get = %+v, want nil", got)
	}
}

func TestBidsRecordSubmission(t *testing.T) {
	bids := newBids(t)
	bid := sampleBid()
	if err := bids.Save(bid); err != nil {
		t.Fatalf("Save: %v", err)
	}

	if err := bids.RecordSubmission(bid.BlockHash, "0xl1tx"); err != nil {
		t.Fatalf("RecordSubmission: %v", err)
	}

	got, err := bids.Get(bid.BlockHash)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.L1TxHash != "0xl1tx" {
		t.Fatalf("l1_tx_hash = %q, want %q", got.L1TxHash, "0xl1tx")
	}
	// The opening must survive recording the submission: it is the only thing
	// that can ever open the commitment now on L1.
	if got.Random != bid.Random || got.Commitment != bid.Commitment {
		t.Fatalf("recording the submission disturbed the opening: %+v", got)
	}
}

// TestBidsRecordSubmissionWithoutABid guards the ordering the whole store
// exists to enforce: the opening is written before the commitment goes out, so
// a submission with no opening behind it is a bug worth reporting, not a row
// to create.
func TestBidsRecordSubmissionWithoutABid(t *testing.T) {
	bids := newBids(t)

	if err := bids.RecordSubmission("0xunknown", "0xl1tx"); err == nil {
		t.Fatal("recording a submission for an unsaved block must fail")
	}
}

func TestBidsRecordLocation(t *testing.T) {
	bids := newBids(t)
	bid := sampleBid()
	if err := bids.Save(bid); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := bids.RecordSubmission(bid.BlockHash, "0xl1tx"); err != nil {
		t.Fatalf("RecordSubmission: %v", err)
	}

	if err := bids.RecordLocation(bid.BlockHash, "0xl1block", 7); err != nil {
		t.Fatalf("RecordLocation: %v", err)
	}

	got, err := bids.Get(bid.BlockHash)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.L1BlockHash != "0xl1block" || got.TxIdx != 7 {
		t.Fatalf("location = %q/%d, want %q/7", got.L1BlockHash, got.TxIdx, "0xl1block")
	}
	// The opening is the one thing that cannot be reconstructed, and the two
	// facts are written at different moments — so the later write must not
	// disturb the earlier one.
	if got.Random != bid.Random || got.Commitment != bid.Commitment {
		t.Fatalf("recording the location disturbed the opening: %+v", got)
	}
	if got.L1TxHash != "0xl1tx" {
		t.Fatalf("recording the location disturbed the tx hash: %q", got.L1TxHash)
	}
}

// A location for a block this node never bid on is a bug worth reporting, not
// a row to conjure up.
func TestBidsRecordLocationWithoutABid(t *testing.T) {
	bids := newBids(t)

	if err := bids.RecordLocation("0xunknown", "0xl1block", 0); err == nil {
		t.Fatal("recording a location for an unsaved block must fail")
	}
}

// TestBidsSaveReplacesTheSameBlock: a resubmission path must not end up with
// two openings for one block, which would leave it ambiguous which one the
// commitment on L1 corresponds to.
func TestBidsSaveReplacesTheSameBlock(t *testing.T) {
	bids := newBids(t)
	bid := sampleBid()
	if err := bids.Save(bid); err != nil {
		t.Fatalf("Save: %v", err)
	}

	updated := sampleBid()
	updated.Random = "cd"
	updated.Commitment = "0xother"
	if err := bids.Save(updated); err != nil {
		t.Fatalf("Save again: %v", err)
	}

	got, err := bids.Get(bid.BlockHash)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Random != "cd" || got.Commitment != "0xother" {
		t.Fatalf("Get = %+v, want the second save to have replaced the first", got)
	}
}

func TestBidsSaveRejectsAnEmptyBlockHash(t *testing.T) {
	bids := newBids(t)

	if err := bids.Save(&BlockBid{Height: 1}); err == nil {
		t.Fatal("a bid with no block hash must be rejected")
	}
	if err := bids.Save(nil); err == nil {
		t.Fatal("a nil bid must be rejected")
	}
}
