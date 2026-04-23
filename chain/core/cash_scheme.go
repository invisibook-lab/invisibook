package core

import (
	"fmt"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
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

// InitAccountDB opens a SQLite database and auto-migrates the cash table.
func InitAccountDB(dsn string) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		panic(fmt.Sprintf("failed to open accounts database: %v", err))
	}
	if err := db.AutoMigrate(&CashScheme{}); err != nil {
		panic(fmt.Sprintf("failed to migrate cash table: %v", err))
	}
	return db
}

// ────────────────────── CRUD Operations ──────────────────────

// CreateCash inserts a new Active Cash into the database.
func (a *Account) CreateCash(cash *Cash) error {
	return a.db.Create(&CashScheme{
		CashID:  cash.ID,
		Pubkey:  cash.Pubkey,
		Token:   string(cash.Token),
		Amount:  string(cash.Amount),
		ZkProof: cash.ZkProof,
		Status:  int(Active),
		By:      "",
	}).Error
}

// GetCash retrieves a single Cash by ID.
func (a *Account) GetCash(id string) (*Cash, error) {
	var row CashScheme
	if err := a.db.First(&row, "cash_id = ?", id).Error; err != nil {
		return nil, err
	}
	return schemeToCash(&row), nil
}

// FindActiveCash returns all Active Cash for the given pubkey and token.
func (a *Account) FindActiveCash(pubkey string, token TokenID) ([]*Cash, error) {
	var rows []CashScheme
	err := a.db.Where("pubkey = ? AND token = ? AND status = ?", pubkey, string(token), int(Active)).
		Find(&rows).Error
	if err != nil {
		return nil, err
	}
	result := make([]*Cash, 0, len(rows))
	for i := range rows {
		result = append(result, schemeToCash(&rows[i]))
	}
	return result, nil
}

// FindNonSpentCash returns all Active and Locked Cash for the given pubkey and token.
func (a *Account) FindNonSpentCash(pubkey string, token TokenID) ([]*Cash, error) {
	var rows []CashScheme
	err := a.db.Where("pubkey = ? AND token = ? AND status != ?", pubkey, string(token), int(Spent)).
		Find(&rows).Error
	if err != nil {
		return nil, err
	}
	result := make([]*Cash, 0, len(rows))
	for i := range rows {
		result = append(result, schemeToCash(&rows[i]))
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
	return a.db.Model(&CashScheme{}).
		Where("cash_id IN ? AND status = ?", cashIDs, int(Active)).
		Updates(map[string]any{"status": int(Locked), "by": orderID}).Error
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
	return a.db.Model(&CashScheme{}).
		Where("cash_id IN ? AND status IN ?", cashIDs, []int{int(Active), int(Locked)}).
		Updates(map[string]any{"status": int(Spent), "by": spentBy}).Error
}

// UnlockCash transitions Locked Cash back to Active state (e.g. order cancellation).
func (a *Account) UnlockCash(cashIDs []string) error {
	return a.db.Model(&CashScheme{}).
		Where("cash_id IN ? AND status = ?", cashIDs, int(Locked)).
		Updates(map[string]any{"status": int(Active), "by": ""}).Error
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
