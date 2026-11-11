package core

import (
	"errors"
	"github.com/invisibook-lab/invisibook/store"
	"github.com/yu-org/yu/core/state/sqlstate"
	"gorm.io/gorm/logger"
	"path/filepath"
	"testing"
)

// TestOrderSQLTransactions verifies matching views, pagination and submission rollback in yu state.
func TestOrderSQLTransactions(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "state.db"), logger.Silent)
	if err != nil {
		t.Fatal(err)
	}
	s, err := sqlstate.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	var tables []*sqlstate.Table
	for _, m := range []any{&OrderScheme{}, &CompareSubmissionScheme{}, &SettleSubmissionScheme{}, &SettleAddrScheme{}} {
		table, err := s.RegisterTable("orderbook", m)
		if err != nil {
			t.Fatal(err)
		}
		tables = append(tables, table)
	}
	ot := &OrderBook{orders: tables[0], comparisons: tables[1], settlements: tables[2], addresses: tables[3]}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(s.Begin("g", "", 0))
	_, err = s.Commit()
	must(err)
	must(s.Finalize("g"))
	must(s.Begin("a", "g", 1))
	must(ot.InsertOrder(&Order{ID: "a", Type: Buy, Status: Pending, Subject: TradePair{Token1: "ETH", Token2: "CKB"}}))
	must(ot.InsertOrder(&Order{ID: "b", Type: Buy, Status: Pending}))
	matched := Matched
	must(ot.UpdateOrderStatus("a", matched))
	rows, err := ot.FindOrdersByFilter(OrderFilter{Status: &matched})
	must(err)
	if len(rows) != 1 || rows[0].ID != "a" {
		t.Fatal("query ignored current transaction")
	}
	rows, err = ot.FindOrdersByFilter(OrderFilter{Limit: 1, Offset: 1})
	must(err)
	if len(rows) != 1 || rows[0].ID != "b" {
		t.Fatal("unstable pagination")
	}
	must(ot.SaveCompareSubmission(&CompareSubmissionScheme{OrderID: "a"}))
	must(s.NextTxn())
	must(ot.DeleteCompareSubmission("a"))
	_, err = ot.GetCompareSubmission("a")
	if !errors.Is(err, sqlstate.ErrNotFound) {
		t.Fatal("deleted submission visible")
	}
	must(s.DiscardTxn())
	_, err = ot.GetCompareSubmission("a")
	must(err)
	_, err = s.Commit()
	must(err)
	must(s.Finalize("a"))
	must(s.Begin("b", "a", 2))
	must(ot.UpdateOrderStatus("a", Pending))
	s.Abort()
	order, err := ot.GetOrder("a")
	must(err)
	if order.Status != matched {
		t.Fatal("rollback changed finalized order")
	}
}
