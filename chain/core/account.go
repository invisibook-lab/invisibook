package core

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/yu-org/yu/core/tripod"
	"github.com/yu-org/yu/core/types"
)

// ────────────────────── Tripod ──────────────────────

// Account is the tripod that owns the shielded pool (notes, nullifiers,
// anchors). Pool notes hide owner, asset, and amount; the only on-chain
// value state is the commitment tree plus the nullifier set.
type Account struct {
	*tripod.Tripod
	db              *gorm.DB
	cfg             *AccountConfig
	noteDepositVK   *CircuitVK
	spendWithdrawVK *CircuitVK
	pool            pool
}

// NewAccount constructs the Account tripod and registers its writings and
// readings. `cfg` must carry a valid SQLite DSN and readable VK paths.
// DB init and VK loading panic on failure.
func NewAccount(cfg *AccountConfig) *Account {
	tri := tripod.NewTripodWithName("account")
	noteDepositVK, err := LoadVK("note_deposit", cfg.NoteDepositVKPath)
	if err != nil {
		panic(fmt.Sprintf("loading note_deposit VK: %v", err))
	}
	spendWithdrawVK, err := LoadVK("spend_withdraw", cfg.SpendWithdrawVKPath)
	if err != nil {
		panic(fmt.Sprintf("loading spend_withdraw VK: %v", err))
	}
	// Fail-closed in production (mirrors the OrderBook flag): a nil VK
	// means an empty path and silently skipped verification.
	if cfg.RequireProofs {
		for name, missing := range map[string]bool{
			"note_deposit":   noteDepositVK == nil,
			"spend_withdraw": spendWithdrawVK == nil,
		} {
			if missing {
				panic(fmt.Sprintf("require_proofs is set but %s VK path is empty; refusing to start with proof verification disabled", name))
			}
		}
	}
	a := &Account{
		Tripod:          tri,
		db:              InitAccountDB(cfg.DBPath, ParseGormLogLevel(cfg.DBLogLevel)),
		cfg:             cfg,
		noteDepositVK:   noteDepositVK,
		spendWithdrawVK: spendWithdrawVK,
	}
	if err := a.InitPool(); err != nil {
		panic(fmt.Sprintf("initializing note pool: %v", err))
	}
	a.SetWritings(a.NoteDeposit, a.NoteWithdraw)
	a.SetReadings(a.GetNotes, a.GetPoolInfo, a.GetNullifiers, a.GetNoteByCm)
	return a
}

// InitChain seeds the genesis pool notes at chain startup. It runs on
// EVERY boot (yu behavior), so seeding must never duplicate or shift state
// (see seedGenesisNotes).
func (a *Account) InitChain(block *types.Block) {
	a.seedGenesisNotes(uint64(block.Height))
}
