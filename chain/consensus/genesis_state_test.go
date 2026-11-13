package consensus

import (
	"github.com/invisibook-lab/invisibook/account"
	"github.com/yu-org/yu/common"
	"github.com/yu-org/yu/core/state/sqlstate"
	"github.com/yu-org/yu/core/types"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"path/filepath"
	"testing"
)

// TestGenesisSQLCommitment verifies initial balances are authenticated, repeatable and recoverable.
func TestGenesisSQLCommitment(t *testing.T) {
	cfg := account.DefaultConfig()
	cfg.GenesisCash = []account.GenesisCash{{ID: "initial", Pubkey: "owner", Token: "CKB", Amount: "123"}}
	root, err := genesisStateRoot(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	again, err := genesisStateRoot(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	if root != again {
		t.Fatal("genesis commitment differs across nodes")
	}
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "state.db")), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	s, err := sqlstate.NewState(db)
	if err != nil {
		t.Fatal(err)
	}
	cash, _, err := RegisterTables(s)
	if err != nil {
		t.Fatal(err)
	}
	genesis := &types.Block{Header: &types.Header{Hash: common.BytesToHash([]byte("genesis")), StateRoot: root}}
	consensusCfg := DefaultConsensusConfig()
	initializer, err := NewGenesis(&consensusCfg, s, cash, &cfg)
	if err != nil {
		t.Fatal(err)
	}
	if initializer.GenesisRoot != root {
		t.Fatal("constructor computed a different genesis commitment")
	}
	if err := initializer.initializeState(genesis); err != nil {
		t.Fatal(err)
	}
	if err := s.InitializeState(genesis); err != nil {
		t.Fatal(err)
	}
	restarted, err := sqlstate.NewState(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.InitializeState(genesis); err != nil {
		t.Fatal(err)
	}
	var row account.CashScheme
	restored, _, err := RegisterTables(restarted)
	if err != nil {
		t.Fatal(err)
	}
	if err := restored.GetFinalized("initial", &row); err != nil {
		t.Fatal(err)
	}
	if row.Amount != "123" {
		t.Fatal("genesis cash was not retained")
	}
	cfg.GenesisCash[0].Amount = "456"
	changed, err := genesisStateRoot(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	if changed == root {
		t.Fatal("genesis balances are absent from commitment")
	}
	other := *genesis.Header
	other.Hash = common.BytesToHash([]byte("another chain"))
	if err := restarted.InitializeState(&types.Block{Header: &other}); err == nil {
		t.Fatal("accepted foreign genesis")
	}
}
