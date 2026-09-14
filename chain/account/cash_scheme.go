package account

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/invisibook-lab/invisibook/store"
)

// ────────────────────── SQL Model ──────────────────────

// CashScheme is the flat SQL model for the cash table.
// Each row represents one Cash output in one of three states: Active, Locked, Spent.
type CashScheme struct {
	CashID  string `gorm:"primaryKey;column:cash_id"`
	Pubkey  string `gorm:"column:pubkey;index:idx_pubkey_token"` // owner's raw ed25519 pubkey (64-char hex)
	Token   string `gorm:"column:token;index:idx_pubkey_token"`
	Amount  string `gorm:"column:amount;not null"`   // encrypted ciphertext
	ZkProof string `gorm:"column:zk_proof;not null"` // proof committed at creation
	Status  int    `gorm:"column:status;default:0"`  // 0=Active, 1=Locked, 2=Spent
	By      string `gorm:"column:by"`                // order ID (Locked) or tx/cash ID (Spent)
}

func (CashScheme) TableName() string { return "cash" }

// ────────────────────── DB Initialization ──────────────────────

// MigrateCashTable creates the cash table on the shared chain database.
func MigrateCashTable(db *gorm.DB) error {
	if err := db.AutoMigrate(&CashScheme{}); err != nil {
		return fmt.Errorf("migrating cash table: %w", err)
	}
	return nil
}

// ────────────────────── CRUD Operations ──────────────────────

// CashExists checks whether a Cash record with the given ID exists.
func (a *Account) CashExists(id string) bool {
	if _, found, deleted := a.latestStaged(id); found {
		return !deleted
	}
	var count int64
	a.db.Model(&CashScheme{}).Where("cash_id = ?", id).Count(&count)
	return count > 0
}

// CreateCash inserts a new Cash into the database, honouring the caller's
// Status + By fields. SendOrder's split branch relies on this to mint a
// Locked cash for the order's collateral; hardcoding Active here would
// silently un-lock split outputs and break settlement.
func (a *Account) CreateCash(cash *Cash) error {
	return a.stage(cashToScheme(cash))
}

// createCashDirect writes straight to the cash table, bypassing staging.
// Genesis cash predates every block, so there is no height to attribute it to
// and nothing that could ever undo it.
func (a *Account) createCashDirect(cash *Cash) error {
	row := cashToScheme(cash)
	return a.db.Create(&row).Error
}

// cashToScheme flattens a Cash into its SQL row.
func cashToScheme(cash *Cash) CashScheme {
	return CashScheme{
		CashID:  cash.ID,
		Pubkey:  cash.Pubkey,
		Token:   string(cash.Token),
		Amount:  string(cash.Amount),
		ZkProof: cash.ZkProof,
		Status:  int(cash.Status),
		By:      cash.By,
	}
}

// GetCash retrieves a single Cash by ID.
//
// An unsettled block's view wins: if any block since the last settled height
// touched this cash, that is its current state, and the settled row underneath
// is stale.
func (a *Account) GetCash(id string) (*Cash, error) {
	if row, found, deleted := a.latestStaged(id); found {
		if deleted {
			return nil, gorm.ErrRecordNotFound
		}
		return schemeToCash(&row), nil
	}
	var row CashScheme
	if err := a.db.First(&row, "cash_id = ?", id).Error; err != nil {
		return nil, err
	}
	return schemeToCash(&row), nil
}

// FindActiveCash returns all Active Cash for the given pubkey and token.
func (a *Account) FindActiveCash(pubkey string, token TokenID) ([]*Cash, error) {
	return a.findCash(pubkey, token, func(status int) bool { return status == int(Active) })
}

// FindNonSpentCash returns all Active and Locked Cash for the given pubkey and token.
func (a *Account) FindNonSpentCash(pubkey string, token TokenID) ([]*Cash, error) {
	return a.findCash(pubkey, token, func(status int) bool { return status != int(Spent) })
}

// findCash returns every cash of `pubkey` in `token` whose status `keep`
// accepts, as the chain currently sees it.
//
// The settled rows are read without any status condition on purpose: status is
// exactly what an unsettled block changes, so filtering in SQL would drop a
// cash the staged view has since unlocked, and keep one it has since spent.
// The whole filter is re-applied after the two views are merged.
func (a *Account) findCash(pubkey string, token TokenID, keep func(status int) bool) ([]*Cash, error) {
	var rows []CashScheme
	err := a.db.Where("pubkey = ? AND token = ?", pubkey, string(token)).Find(&rows).Error
	if err != nil {
		return nil, err
	}

	staged, err := store.LatestAll[CashScheme](a.pending, CashTable)
	if err != nil {
		return nil, err
	}

	merged := store.Overlay(rows, staged, func(row CashScheme) string { return row.CashID })

	// Every condition is re-applied, not just the mutable one. Overlay adds
	// rows the settled query never selected — cash an unsettled block created,
	// whoever owns it — so narrowing by owner and token has to happen here too.
	result := make([]*Cash, 0, len(merged))
	for i := range merged {
		row := &merged[i]
		if row.Pubkey != pubkey || row.Token != string(token) || !keep(row.Status) {
			continue
		}
		result = append(result, schemeToCash(row))
	}
	return result, nil
}

// LockCash transitions Active Cash to Locked state, setting By to the order ID.
// Returns an error if any Cash is not found, not Active, or fails proof verification.
func (a *Account) LockCash(cashIDs []string, orderID string) error {
	for _, id := range cashIDs {
		cash, err := a.GetCash(id)
		if err != nil {
			return fmt.Errorf("cash %s not found: %w", id, err)
		}
		if cash.Status != Active {
			return fmt.Errorf("cash %s is not Active (current: %s)", id, cash.Status.String())
		}
		if err := verifyProof(cash); err != nil {
			return fmt.Errorf("invalid proof for cash %s: %w", id, err)
		}
	}
	return a.restage(cashIDs, Locked, orderID)
}

// SpendCash transitions Active or Locked Cash to Spent state.
// Returns an error if any Cash is not found or already Spent.
func (a *Account) SpendCash(cashIDs []string, spentBy string) error {
	for _, id := range cashIDs {
		cash, err := a.GetCash(id)
		if err != nil {
			return fmt.Errorf("cash %s not found: %w", id, err)
		}
		if cash.Status == Spent {
			return fmt.Errorf("cash %s is already Spent", id)
		}
	}
	return a.restage(cashIDs, Spent, spentBy)
}

// UnlockCash transitions Locked Cash back to Active state (e.g. order cancellation).
func (a *Account) UnlockCash(cashIDs []string) error {
	return a.restage(cashIDs, Active, "")
}

// restage records each cash in its new status. Reading through GetCash first
// means the staged row carries the cash's current state, whether that came
// from the settled table or from an earlier block in this same batch.
func (a *Account) restage(cashIDs []string, status CashStatus, by string) error {
	for _, id := range cashIDs {
		cash, err := a.GetCash(id)
		if err != nil {
			return fmt.Errorf("cash %s not found: %w", id, err)
		}
		cash.Status = status
		cash.By = by
		if err := a.stage(cashToScheme(cash)); err != nil {
			return fmt.Errorf("staging cash %s: %w", id, err)
		}
	}
	return nil
}

// ────────────────────── Cash ↔ Scheme Conversion ──────────────────────

func schemeToCash(s *CashScheme) *Cash {
	return &Cash{
		ID:      s.CashID,
		Pubkey:  s.Pubkey,
		Token:   TokenID(s.Token),
		Amount:  CipherText(s.Amount),
		ZkProof: s.ZkProof,
		Status:  CashStatus(s.Status),
		By:      s.By,
	}
}
