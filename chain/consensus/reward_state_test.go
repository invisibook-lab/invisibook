package consensus

import (
	"path/filepath"
	"testing"

	"github.com/invisibook-lab/invisibook/account"
	"github.com/invisibook-lab/invisibook/store"
	"github.com/yu-org/yu/common"
	"github.com/yu-org/yu/core/env"
	"github.com/yu-org/yu/core/state/sqlstate"
	"github.com/yu-org/yu/core/tripod"
	"github.com/yu-org/yu/core/types"
	"gorm.io/gorm/logger"
)

// rewardState creates an independent node with identical genesis and an authenticated cash table.
func rewardState(t *testing.T) (*ProofOfBuy, *sqlstate.State, *sqlstate.Table, *types.Block) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "state.db"), logger.Silent)
	if err != nil {
		t.Fatal(err)
	}
	s, err := sqlstate.NewState(db)
	if err != nil {
		t.Fatal(err)
	}
	table, err := s.RegisterTable("account", &account.CashScheme{})
	if err != nil {
		t.Fatal(err)
	}
	genesis := &types.Block{Header: &types.Header{Hash: common.BytesToHash([]byte("reward-genesis"))}}
	if err := s.InitializeState(genesis); err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConsensusConfig()
	cfg.CoinbaseReward = "100"
	accCfg := account.DefaultConfig()
	p := &ProofOfBuy{Tripod: tripod.NewTripod(), cfg: &cfg, Account: account.NewAccount(&accCfg, table)}
	p.SetChainEnv(&env.ChainEnv{State: s})
	return p, s, table, genesis
}

// TestRewardStateCommitment verifies reward inclusion, independent replay, tamper rejection and atomic finalization.
func TestRewardStateCommitment(t *testing.T) {
	producer, s, table, genesis := rewardState(t)
	block, _, pub, priv := sealedRival(t, &MockL1PaymentVerifier{})
	block.Height = 1
	block.PrevHash = genesis.Hash
	block.Hash = common.Hash{}
	block.MinerSignature = nil
	if err := s.BeginExecution(block); err != nil {
		t.Fatal(err)
	}
	producer.Commit(block)
	root, err := s.Commit()
	if err != nil {
		t.Fatal(err)
	}
	block.StateRoot = common.BytesToHash(root)
	data, err := DecodeConsensusData(block.Extra)
	if err != nil {
		t.Fatal(err)
	}
	if err := SealBlock(block, block.Txns, data, pub, priv); err != nil {
		t.Fatal(err)
	}
	if err := s.BindBlock(block); err != nil {
		t.Fatal(err)
	}
	var finalized []account.CashScheme
	if err := table.FindFinalized(nil, &finalized); err != nil {
		t.Fatal(err)
	}
	if len(finalized) != 0 {
		t.Fatal("unfinalized reward leaked into finalized table")
	}
	receiver, other, _, _ := rewardState(t)
	copyHeader := *block.Header
	copyBlock := &types.Block{Header: &copyHeader, Txns: block.Txns}
	if err := other.BeginExecution(copyBlock); err != nil {
		t.Fatal(err)
	}
	receiver.Commit(copyBlock)
	replayed, err := other.Commit()
	if err != nil {
		t.Fatal(err)
	}
	if common.BytesToHash(replayed) != block.StateRoot {
		t.Fatal("producer and receiver reward roots differ")
	}
	if err := other.BindBlock(copyBlock); err != nil {
		t.Fatal(err)
	}
	if err := s.FinalizeState(block); err != nil {
		t.Fatal(err)
	}
	if err := table.FindFinalized(nil, &finalized); err != nil {
		t.Fatal(err)
	}
	if len(finalized) != 1 {
		t.Fatalf("finalized %d rewards, want one", len(finalized))
	}
	// Omitting the reward must fail against the signed producer root.
	_, missing, _, _ := rewardState(t)
	if err := missing.BeginExecution(copyBlock); err != nil {
		t.Fatal(err)
	}
	if _, err := missing.Commit(); err == nil {
		t.Fatal("accepted StateRoot without its reward")
	}
	missing.AbortExecution()
	// StateRoot and the final hash must not feed back into the reward identity.
	identity := rewardIdentity(block)
	changed := *block.Header
	changed.StateRoot = common.BytesToHash([]byte("changed"))
	changed.Hash = common.Hash{}
	if rewardIdentity(&types.Block{Header: &changed}) != identity {
		t.Fatal("reward depends on final state root or hash")
	}
	if err := VerifyHeaderSeal(&changed); err == nil {
		t.Fatal("changed StateRoot retained a valid seal")
	}
}
