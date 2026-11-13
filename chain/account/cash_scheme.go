package account

import (
	"fmt"
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
	Status  int    `gorm:"column:status"`            // 0=Active, 1=Locked, 2=Spent
	By      string `gorm:"column:by"`                // order ID (Locked) or tx/cash ID (Spent)
}

// TableName identifies the account business table.
func (CashScheme) TableName() string { return "cash" }

// ────────────────────── CRUD Operations ──────────────────────

// CashExists checks whether a Cash record with the given ID exists.
func (a *Account) CashExists(id string) bool {
	var row CashScheme
	return a.cash.Get(id, &row) == nil
}

// CreateCash inserts a new Cash into the database, honouring the caller's
// Status + By fields. SendOrder's split branch relies on this to mint a
// Locked cash for the order's collateral; hardcoding Active here would
// silently un-lock split outputs and break settlement.
func (a *Account) CreateCash(cash *Cash) error {
	return a.cash.Put(cashToScheme(cash))
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

// GetCash reads a cash from yu's current execution or retained state view.
func (a *Account) GetCash(id string) (*Cash, error) {
	var row CashScheme
	if err := a.cash.Get(id, &row); err != nil {
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

// findCash filters the deterministic current state scan by owner, token and status.
func (a *Account) findCash(pubkey string, token TokenID, keep func(status int) bool) ([]*Cash, error) {
	var merged []CashScheme
	if err := a.cash.Scan(&merged); err != nil {
		return nil, err
	}
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
	return a.updateCash(cashIDs, Locked, orderID)
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
	return a.updateCash(cashIDs, Spent, spentBy)
}

// UnlockCash transitions Locked Cash back to Active state (e.g. order cancellation).
func (a *Account) UnlockCash(cashIDs []string) error {
	return a.updateCash(cashIDs, Active, "")
}

// updateCash reads complete cash rows and writes their new status through yu.
func (a *Account) updateCash(cashIDs []string, status CashStatus, by string) error {
	for _, id := range cashIDs {
		cash, err := a.GetCash(id)
		if err != nil {
			return fmt.Errorf("cash %s not found: %w", id, err)
		}
		cash.Status = status
		cash.By = by
		if err := a.cash.Put(cashToScheme(cash)); err != nil {
			return fmt.Errorf("updating cash %s: %w", id, err)
		}
	}
	return nil
}

// ────────────────────── Cash ↔ Scheme Conversion ──────────────────────

// schemeToCash restores a cash from its persisted row.
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
