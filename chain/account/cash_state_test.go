package account

import (
	"errors"
	"github.com/invisibook-lab/invisibook/store"
	"github.com/yu-org/yu/core/state/sqlstate"
	"gorm.io/gorm/logger"
	"path/filepath"
	"testing"
)

// TestCashSQLForks verifies branch isolation, deletion rollback and durable finalization through yu.
func TestCashSQLForks(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "state.db"), logger.Silent)
	if err != nil {
		t.Fatal(err)
	}
	s, err := sqlstate.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	table, err := s.RegisterTable("account", &CashScheme{})
	if err != nil {
		t.Fatal(err)
	}
	a := &Account{cash: table}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(s.Begin("genesis", "", 0))
	must(a.CreateCash(&Cash{ID: "cash", Pubkey: "owner", Token: "CKB", Amount: "ct", Status: Active}))
	_, err = s.Commit()
	must(err)
	must(s.Finalize("genesis"))
	must(s.Begin("loser", "genesis", 1))
	must(a.LockCash([]string{"cash"}, "order"))
	_, err = s.Commit()
	must(err)
	must(s.Begin("winner", "genesis", 1))
	c, err := a.GetCash("cash")
	must(err)
	if c.Status != Active {
		t.Fatal("losing branch leaked into sibling")
	}
	must(a.SpendCash([]string{"cash"}, "settlement"))
	_, err = s.Commit()
	must(err)
	must(s.Finalize("winner"))
	var row CashScheme
	must(table.GetFinalized("cash", &row))
	if row.Status != int(Spent) {
		t.Fatal("winner not finalized")
	}
	must(s.Begin("delete", "winner", 2))
	must(table.Delete("cash"))
	_, err = a.GetCash("cash")
	if !errors.Is(err, sqlstate.ErrNotFound) {
		t.Fatalf("deleted cash: %v", err)
	}
	s.Abort()
	c, err = a.GetCash("cash")
	must(err)
	if c.Status != Spent {
		t.Fatal("abort lost finalized row")
	}
	reopened, err := sqlstate.Open(db)
	must(err)
	restored, err := reopened.RegisterTable("account", &CashScheme{})
	must(err)
	must(restored.GetFinalized("cash", &row))
	if row.Status != int(Spent) {
		t.Fatal("restart lost state")
	}
}
