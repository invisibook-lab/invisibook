package account

import (
	"fmt"
	"testing"

	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/invisibook-lab/invisibook/store"
)

const (
	testOwner = "02aa"
	testToken = TokenID("ETH")
)

// newTestAccount builds an Account over an in-memory database with a staging
// layer wired up, and returns the syncer so tests can settle or drop heights.
func newTestAccount(t *testing.T) (*Account, *store.Pending, *gorm.DB) {
	t.Helper()
	// A database per test: a shared-cache in-memory DSN is one database for the
	// whole process, so a fixed name would leak rows between tests.
	db, err := store.Open(fmt.Sprintf("file:%s?mode=memory&cache=shared", t.Name()), logger.Silent)
	if err != nil {
		t.Fatalf("opening test database: %v", err)
	}
	if err := MigrateCashTable(db); err != nil {
		t.Fatalf("migrating cash: %v", err)
	}
	if err := store.MigrateStagedTable(db); err != nil {
		t.Fatalf("migrating staging: %v", err)
	}
	pending := store.NewPending(db)
	pending.Register(CashApplier{})

	return &Account{db: db, pending: pending}, pending, db
}

// settledCount counts rows in the cash table itself, bypassing the staged view.
func settledCount(t *testing.T, db *gorm.DB) int64 {
	t.Helper()
	var n int64
	if err := db.Model(&CashScheme{}).Count(&n).Error; err != nil {
		t.Fatalf("counting settled cash: %v", err)
	}
	return n
}

func cashAt(id string, status CashStatus) *Cash {
	return &Cash{ID: id, Pubkey: testOwner, Token: testToken, Amount: "ct", ZkProof: "p", Status: status}
}

// TestStagedWritesAreInvisibleInTheSettledTable is the property the whole
// design rests on: an unsettled block changes nothing durable.
func TestStagedWritesAreInvisibleInTheSettledTable(t *testing.T) {
	acc, pending, db := newTestAccount(t)
	pending.SetBlock(10, "0xh10")

	if err := acc.CreateCash(cashAt("c1", Active)); err != nil {
		t.Fatalf("CreateCash: %v", err)
	}

	// Readers see it...
	if got, err := acc.GetCash("c1"); err != nil || got.Status != Active {
		t.Fatalf("GetCash = %+v, %v — the staged view must show it", got, err)
	}
	// ...but the table it will eventually live in is still empty.
	if n := settledCount(t, db); n != 0 {
		t.Fatalf("settled rows = %d, want 0 until the height is settled", n)
	}
}

// TestDropFromUndoesABlock covers the case the follower exists for: a height
// L1 ruled against leaves no trace.
func TestDropFromUndoesABlock(t *testing.T) {
	acc, pending, _ := newTestAccount(t)

	// Height 10 creates a cash and is settled.
	pending.SetBlock(10, "0xh10")
	if err := acc.CreateCash(cashAt("c1", Active)); err != nil {
		t.Fatalf("CreateCash: %v", err)
	}
	if err := pending.ApplyThrough(10); err != nil {
		t.Fatalf("ApplyThrough: %v", err)
	}

	// Height 11 locks it, and is the height L1 rules against.
	pending.SetBlock(11, "0xh11")
	if err := acc.LockCash([]string{"c1"}, "order-1"); err != nil {
		t.Fatalf("LockCash: %v", err)
	}
	if got, _ := acc.GetCash("c1"); got.Status != Locked {
		t.Fatalf("status = %s, want Locked before the drop", got.Status)
	}

	if err := pending.DropFrom(11); err != nil {
		t.Fatalf("DropFrom: %v", err)
	}

	got, err := acc.GetCash("c1")
	if err != nil {
		t.Fatalf("GetCash after drop: %v", err)
	}
	if got.Status != Active {
		t.Fatalf("status = %s, want Active — height 11 was undone", got.Status)
	}
	if got.By != "" {
		t.Fatalf("by = %q, want empty — the lock was undone with it", got.By)
	}
}

// TestDropFromLeavesSettledHeightsAlone: only the blocks L1 ruled against go,
// not everything.
func TestDropFromLeavesSettledHeightsAlone(t *testing.T) {
	acc, pending, db := newTestAccount(t)

	pending.SetBlock(10, "0xh10")
	acc.CreateCash(cashAt("settled", Active))
	if err := pending.ApplyThrough(10); err != nil {
		t.Fatalf("ApplyThrough: %v", err)
	}

	pending.SetBlock(11, "0xh11")
	acc.CreateCash(cashAt("orphaned", Active))

	if err := pending.DropFrom(11); err != nil {
		t.Fatalf("DropFrom: %v", err)
	}

	if !acc.CashExists("settled") {
		t.Fatal("a cash from a settled height must survive the drop")
	}
	if acc.CashExists("orphaned") {
		t.Fatal("a cash from the dropped height must be gone")
	}
	if n := settledCount(t, db); n != 1 {
		t.Fatalf("settled rows = %d, want only the one settled cash", n)
	}
}

// TestApplyThroughMakesWritesDurable: settling a height moves its writes into
// the cash table and clears the staging behind them.
func TestApplyThroughMakesWritesDurable(t *testing.T) {
	acc, pending, db := newTestAccount(t)

	pending.SetBlock(10, "0xh10")
	acc.CreateCash(cashAt("c1", Active))
	pending.SetBlock(11, "0xh11")
	acc.LockCash([]string{"c1"}, "order-1")

	if err := pending.ApplyThrough(11); err != nil {
		t.Fatalf("ApplyThrough: %v", err)
	}

	var row CashScheme
	if err := db.First(&row, "cash_id = ?", "c1").Error; err != nil {
		t.Fatalf("reading settled cash: %v", err)
	}
	if row.Status != int(Locked) || row.By != "order-1" {
		t.Fatalf("settled row = %+v, want the state height 11 left it in", row)
	}

	var staged int64
	db.Model(&store.StagedWrite{}).Count(&staged)
	if staged != 0 {
		t.Fatalf("staged rows = %d, want 0 once promoted", staged)
	}
}

// TestApplyThroughKeepsLaterHeightsStaged: settling one height must not
// promote the heights above it, which L1 has not ruled on yet.
func TestApplyThroughKeepsLaterHeightsStaged(t *testing.T) {
	acc, pending, db := newTestAccount(t)

	pending.SetBlock(10, "0xh10")
	acc.CreateCash(cashAt("c1", Active))
	pending.SetBlock(11, "0xh11")
	acc.CreateCash(cashAt("c2", Active))

	if err := pending.ApplyThrough(10); err != nil {
		t.Fatalf("ApplyThrough: %v", err)
	}

	if n := settledCount(t, db); n != 1 {
		t.Fatalf("settled rows = %d, want only height 10's cash", n)
	}
	// c2 is still only staged, but readers see it all the same.
	if !acc.CashExists("c2") {
		t.Fatal("a staged cash must still be visible to readers")
	}
}

// TestSetQueryMergesBothViews: the three-way merge the set queries need —
// a settled row the staged view changed, one it left alone, and one it created.
func TestSetQueryMergesBothViews(t *testing.T) {
	acc, pending, _ := newTestAccount(t)

	pending.SetBlock(10, "0xh10")
	acc.CreateCash(cashAt("stays", Active))
	acc.CreateCash(cashAt("gets-locked", Active))
	if err := pending.ApplyThrough(10); err != nil {
		t.Fatalf("ApplyThrough: %v", err)
	}

	pending.SetBlock(11, "0xh11")
	acc.LockCash([]string{"gets-locked"}, "order-1") // settled Active → staged Locked
	acc.CreateCash(cashAt("created", Active))        // exists only in staging

	active, err := acc.FindActiveCash(testOwner, testToken)
	if err != nil {
		t.Fatalf("FindActiveCash: %v", err)
	}
	got := make(map[string]bool, len(active))
	for _, c := range active {
		got[c.ID] = true
	}
	if !got["stays"] {
		t.Error("an untouched settled cash must still be Active")
	}
	if got["gets-locked"] {
		t.Error("a cash the staged view locked must not count as Active")
	}
	if !got["created"] {
		t.Error("a cash created in an unsettled block must count as Active")
	}
}

// TestAppliedHeightRecordsPromotion: the boundary the restart path reads is
// written with the promotion it describes.
func TestAppliedHeightRecordsPromotion(t *testing.T) {
	acc, pending, _ := newTestAccount(t)

	if h, err := pending.AppliedHeight(); err != nil || h != 0 {
		t.Fatalf("AppliedHeight = %d, %v — nothing has been promoted yet", h, err)
	}

	pending.SetBlock(10, "0xh10")
	acc.CreateCash(cashAt("c1", Active))
	if err := pending.ApplyThrough(10); err != nil {
		t.Fatalf("ApplyThrough: %v", err)
	}

	if h, err := pending.AppliedHeight(); err != nil || h != 10 {
		t.Fatalf("AppliedHeight = %d, %v, want 10", h, err)
	}
}

// TestAppliedHeightSurvivesReopen covers what the whole record exists for: a
// process that died still knows how far its tables got.
func TestAppliedHeightSurvivesReopen(t *testing.T) {
	acc, pending, db := newTestAccount(t)

	pending.SetBlock(10, "0xh10")
	acc.CreateCash(cashAt("c1", Active))
	pending.ApplyThrough(10)

	// A second handle onto the same database stands in for a restart.
	restarted := store.NewPending(db)
	restarted.Register(CashApplier{})

	if h, err := restarted.AppliedHeight(); err != nil || h != 10 {
		t.Fatalf("AppliedHeight after restart = %d, %v, want 10", h, err)
	}
	// Height 11's staged rows would be dropped by reconciliation.
	pending.SetBlock(11, "0xh11")
	acc.CreateCash(cashAt("c2", Active))
	if err := restarted.DropFrom(11); err != nil {
		t.Fatalf("DropFrom: %v", err)
	}
	if acc.CashExists("c2") {
		t.Fatal("staged rows above the promoted height must not survive a restart")
	}
	if !acc.CashExists("c1") {
		t.Fatal("promoted state must survive a restart")
	}
}
