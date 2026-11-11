package main

import (
	"fmt"
	"github.com/invisibook-lab/invisibook/account"
	"github.com/invisibook-lab/invisibook/core"
	"github.com/yu-org/yu/common"
	"github.com/yu-org/yu/core/state/sqlstate"
	"github.com/yu-org/yu/core/types"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// registerTables registers all business schemas before block execution begins.
func registerTables(s *sqlstate.State) (*sqlstate.Table, []*sqlstate.Table, error) {
	cash, err := s.RegisterTable("account", &account.CashScheme{})
	if err != nil {
		return nil, nil, err
	}
	var tables []*sqlstate.Table
	for _, model := range []any{&core.OrderScheme{}, &core.CompareSubmissionScheme{}, &core.SettleSubmissionScheme{}, &core.SettleAddrScheme{}} {
		t, err := s.RegisterTable(core.OrderBookTripodName, model)
		if err != nil {
			return nil, nil, err
		}
		tables = append(tables, t)
	}
	return cash, tables, nil
}

// seedCash writes configured genesis allocations into an active genesis transaction.
func seedCash(table *sqlstate.Table, cfg *account.Config) error {
	seen := make(map[string]bool)
	for _, c := range cfg.GenesisCash {
		if seen[c.ID] {
			return fmt.Errorf("duplicate genesis cash %s", c.ID)
		}
		seen[c.ID] = true
		if err := table.Put(&account.CashScheme{CashID: c.ID, Pubkey: c.Pubkey, Token: c.Token, Amount: c.Amount, ZkProof: "genesis", Status: int(account.Active)}); err != nil {
			return err
		}
	}
	return nil
}

// genesisStateRoot computes the configured allocation commitment independently of persisted finality.
func genesisStateRoot(cfg *account.Config) (common.Hash, error) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		return common.Hash{}, err
	}
	conn, err := db.DB()
	if err != nil {
		return common.Hash{}, err
	}
	defer conn.Close()
	s, err := sqlstate.NewState(db)
	if err != nil {
		return common.Hash{}, err
	}
	cash, _, err := registerTables(s)
	if err != nil {
		return common.Hash{}, err
	}
	if err := s.Store.Begin("genesis", "", 0); err != nil {
		return common.Hash{}, err
	}
	if err := seedCash(cash, cfg); err != nil {
		return common.Hash{}, err
	}
	root, err := s.Store.Commit()
	return common.BytesToHash(root), err
}

// initializeGenesis prepares the exact genesis version before yu anchors its finalized identity.
func initializeGenesis(s *sqlstate.State, cash *sqlstate.Table, cfg *account.Config, genesis *types.Block) error {
	if err := s.Store.Begin(genesis.Hash.String(), "", 0); err != nil {
		return err
	}
	if err := seedCash(cash, cfg); err != nil {
		s.Store.Abort()
		return err
	}
	_, err := s.Store.CommitExpected(genesis.StateRoot.Bytes())
	return err
}
