package main

import (
	"errors"
	"github.com/yu-org/yu/common"
	"github.com/yu-org/yu/common/yerror"
	"github.com/yu-org/yu/core/state/sqlstate"
	"github.com/yu-org/yu/core/types"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"path/filepath"
	"testing"
)

// TestRecoveringBind protects appended state and safely replaces an identical unappended crash residue.
func TestRecoveringBind(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "state.db")), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	s, err := sqlstate.NewState(db)
	if err != nil {
		t.Fatal(err)
	}
	genesis := &types.Block{Header: &types.Header{Hash: common.BytesToHash([]byte("g"))}}
	if err := s.InitializeState(genesis); err != nil {
		t.Fatal(err)
	}
	block := &types.Block{Header: &types.Header{Height: 1, PrevHash: genesis.Hash}}
	if err := s.BeginExecution(block); err != nil {
		t.Fatal(err)
	}
	root, err := s.Commit()
	if err != nil {
		t.Fatal(err)
	}
	block.StateRoot = common.BytesToHash(root)
	block.TxnRoot, err = types.MakeTxnRoot(nil)
	if err != nil {
		t.Fatal(err)
	}
	block.Hash, err = types.ComputeHeaderHash(block)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.BindBlock(block); err != nil {
		t.Fatal(err)
	}
	// A new execution rebuilds the same block after crashing before AppendBlock.
	copyHeader := *block.Header
	replay := &types.Block{Header: &copyHeader}
	if err := s.BeginExecution(replay); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatal(err)
	}
	exists := func(common.Hash) (*types.CompactBlock, error) { return block.Compact(), nil }
	if err := recoveringBind(s, exists, s.BindBlock)(replay); err == nil {
		t.Fatal("replaced appended block state")
	}
	if _, err := s.Store.Root(block.Hash.String()); err != nil {
		t.Fatal("existing state was deleted")
	}
	failure := errors.New("database unavailable")
	broken := func(common.Hash) (*types.CompactBlock, error) { return nil, failure }
	if err := recoveringBind(s, broken, s.BindBlock)(replay); !errors.Is(err, failure) {
		t.Fatal("database failure treated as absence")
	}
	missing := func(common.Hash) (*types.CompactBlock, error) { return nil, yerror.ErrBlockNotFound }
	if err := recoveringBind(s, missing, s.BindBlock)(replay); err != nil {
		t.Fatal(err)
	}
	if !s.ExecutionCommitted(replay) {
		t.Fatal("replayed execution was not bound")
	}
}
