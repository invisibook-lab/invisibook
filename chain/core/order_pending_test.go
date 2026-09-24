package core

import (
	"fmt"
	"testing"

	"math/big"

	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/invisibook-lab/invisibook/store"
)

// newTestOrderBook builds an OrderBook over an in-memory database with a
// staging layer wired up.
func newTestOrderBook(t *testing.T) (*OrderBook, *store.Pending, *gorm.DB) {
	t.Helper()
	// A database per test: a shared-cache in-memory DSN is one database for the
	// whole process, so a fixed name would leak rows between tests.
	db, err := store.Open(fmt.Sprintf("file:%s?mode=memory&cache=shared", t.Name()), logger.Silent)
	if err != nil {
		t.Fatalf("opening test database: %v", err)
	}
	if err := MigrateOrderTables(db); err != nil {
		t.Fatalf("migrating orderbook: %v", err)
	}
	if err := store.MigrateStagedTable(db); err != nil {
		t.Fatalf("migrating staging: %v", err)
	}
	pending := store.NewPending(db)
	pending.Register(Appliers()...)

	return &OrderBook{db: db, pending: pending}, pending, db
}

func bigOne() *big.Int { return big.NewInt(1) }

func testOrder(id string, status OrderStat) *Order {
	return &Order{
		ID:           OrderID(id),
		Type:         Buy,
		Subject:      TradePair{Token1: "ETH", Token2: "USDT"},
		Amount:       "ct",
		Pubkey:       "02aa",
		InputCashIDs: []string{"c1"},
		Status:       status,
	}
}

// TestOrderDropFromUndoesAStatusChange is the order-side of the undo the
// follower depends on.
func TestOrderDropFromUndoesAStatusChange(t *testing.T) {
	ot, pending, _ := newTestOrderBook(t)

	pending.SetBlock(10, "0xh10")
	if err := ot.InsertOrder(testOrder("o1", Pending)); err != nil {
		t.Fatalf("InsertOrder: %v", err)
	}
	if err := pending.ApplyBlocks([]store.Block{{Height: 10, Hash: "0xh10"}}); err != nil {
		t.Fatalf("ApplyBlocks: %v", err)
	}

	pending.SetBlock(11, "0xh11")
	if err := ot.UpdateOrderStatus("o1", Matched); err != nil {
		t.Fatalf("UpdateOrderStatus: %v", err)
	}
	if got, _ := ot.GetOrder("o1"); got.Status != Matched {
		t.Fatalf("status = %d, want Matched before the drop", got.Status)
	}

	if err := pending.DropFrom(11); err != nil {
		t.Fatalf("DropFrom: %v", err)
	}
	got, err := ot.GetOrder("o1")
	if err != nil {
		t.Fatalf("GetOrder after drop: %v", err)
	}
	if got.Status != Pending {
		t.Fatalf("status = %d, want Pending — height 11 was undone", got.Status)
	}
}

// TestTombstoneHidesThenRestoresARow covers the deletion path: a row a block
// removed stops being visible, and comes back when that block is dropped.
func TestTombstoneHidesThenRestoresARow(t *testing.T) {
	ot, pending, _ := newTestOrderBook(t)

	pending.SetBlock(10, "0xh10")
	if err := ot.SaveCompareSubmission(&CompareSubmissionScheme{
		OrderID: "o1", MatchOrderID: "o2", MpcShareJSON: "{}",
	}); err != nil {
		t.Fatalf("SaveCompareSubmission: %v", err)
	}
	if err := pending.ApplyBlocks([]store.Block{{Height: 10, Hash: "0xh10"}}); err != nil {
		t.Fatalf("ApplyBlocks: %v", err)
	}

	// Height 11 consumes both shares and removes the row.
	pending.SetBlock(11, "0xh11")
	if err := ot.DeleteCompareSubmission("o1"); err != nil {
		t.Fatalf("DeleteCompareSubmission: %v", err)
	}
	if _, err := ot.GetCompareSubmission("o1"); err == nil {
		t.Fatal("a tombstoned row must read as absent")
	}

	if err := pending.DropFrom(11); err != nil {
		t.Fatalf("DropFrom: %v", err)
	}
	if _, err := ot.GetCompareSubmission("o1"); err != nil {
		t.Fatalf("dropping the tombstone must restore the row, got %v", err)
	}
}

// TestTombstoneAppliesAsARealDelete: once the height settles, the row really
// does leave the table.
func TestTombstoneAppliesAsARealDelete(t *testing.T) {
	ot, pending, db := newTestOrderBook(t)

	pending.SetBlock(10, "0xh10")
	ot.SaveCompareSubmission(&CompareSubmissionScheme{OrderID: "o1", MpcShareJSON: "{}"})
	pending.ApplyBlocks([]store.Block{{Height: 10, Hash: "0xh10"}})

	pending.SetBlock(11, "0xh11")
	ot.DeleteCompareSubmission("o1")
	if err := pending.ApplyBlocks([]store.Block{{Height: 11, Hash: "0xh11"}}); err != nil {
		t.Fatalf("ApplyBlocks: %v", err)
	}

	var n int64
	db.Model(&CompareSubmissionScheme{}).Count(&n)
	if n != 0 {
		t.Fatalf("settled rows = %d, want 0 — the delete was promoted", n)
	}
}

// TestMatchingSeesStagedOrders: the matching engine must find an order that
// only exists in an unsettled block, or two orders in the same block could
// never match each other.
func TestMatchingSeesStagedOrders(t *testing.T) {
	ot, pending, _ := newTestOrderBook(t)

	pending.SetBlock(10, "0xh10")
	order := testOrder("o1", Pending)
	order.Price = bigOne()
	if err := ot.InsertOrder(order); err != nil {
		t.Fatalf("InsertOrder: %v", err)
	}

	found, err := ot.FindPendingCounterOrders(TradePair{Token1: "ETH", Token2: "USDT"}, Buy)
	if err != nil {
		t.Fatalf("FindPendingCounterOrders: %v", err)
	}
	if len(found) != 1 || found[0].ID != "o1" {
		t.Fatalf("found = %+v, want the staged order", found)
	}
}

// TestMatchingSkipsOrdersStagedAsMatched: an order matched earlier in the same
// block must not be offered again.
func TestMatchingSkipsOrdersStagedAsMatched(t *testing.T) {
	ot, pending, _ := newTestOrderBook(t)

	pending.SetBlock(10, "0xh10")
	order := testOrder("o1", Pending)
	order.Price = bigOne()
	ot.InsertOrder(order)
	ot.UpdateOrderStatus("o1", Matched)

	found, err := ot.FindPendingCounterOrders(TradePair{Token1: "ETH", Token2: "USDT"}, Buy)
	if err != nil {
		t.Fatalf("FindPendingCounterOrders: %v", err)
	}
	if len(found) != 0 {
		t.Fatalf("found = %+v, want none — the order is already matched", found)
	}
}
