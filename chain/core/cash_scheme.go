package core

import (
	"fmt"
	"log"
	"os"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
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
// `logLevel` controls GORM SQL logging verbosity.
func InitAccountDB(dsn string, logLevel logger.LogLevel) *gorm.DB {
	gormLogger := logger.New(
		log.New(os.Stdout, "\n", log.LstdFlags),
		logger.Config{
			SlowThreshold: 200 * time.Millisecond,
			LogLevel:      logLevel,
		},
	)
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{Logger: gormLogger})
	if err != nil {
		panic(fmt.Sprintf("failed to open accounts database: %v", err))
	}
	if err := db.AutoMigrate(&CashScheme{}, &NoteScheme{}, &NullifierScheme{},
		&AnchorScheme{}, &TreeStateScheme{}, &BridgeSeenScheme{}); err != nil {
		panic(fmt.Sprintf("failed to migrate cash table: %v", err))
	}
	return db
}

// ────────────────────── CRUD Operations ──────────────────────

// CashExists checks whether a Cash record with the given ID exists.
func (a *Account) CashExists(id string) bool {
	var count int64
	a.db.Model(&CashScheme{}).Where("cash_id = ?", id).Count(&count)
	return count > 0
}

// CreateCash inserts a new Cash into the database, honouring the caller's
// Status + By fields. SendOrder's split branch relies on this to mint a
// Locked cash for the order's collateral; hardcoding Active here would
// silently un-lock split outputs and break settlement.
func (a *Account) CreateCash(cash *Cash) error {
	return a.db.Create(&CashScheme{
		CashID:  cash.ID,
		Pubkey:  cash.Pubkey,
		Token:   string(cash.Token),
		Amount:  string(cash.Amount),
		ZkProof: cash.ZkProof,
		Status:  int(cash.Status),
		By:      cash.By,
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
