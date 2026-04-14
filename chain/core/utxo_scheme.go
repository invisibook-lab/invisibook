package core

import (
	"fmt"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// ────────────────────── SQL Model ──────────────────────

// UTXOScheme is the flat SQL model for the utxos table.
// Each row represents one (spent or unspent) transaction output.
type UTXOScheme struct {
	UTXOID  string `gorm:"primaryKey;column:utxo_id"`
	Owner   string `gorm:"column:owner;index:idx_owner_token"`
	Token   string `gorm:"column:token;index:idx_owner_token"`
	Amount  string `gorm:"column:amount;not null"`   // encrypted ciphertext
	ZkProof string `gorm:"column:zk_proof;not null"` // proof committed at creation
	Spent   bool   `gorm:"column:spent;default:false"`
	SpentBy string `gorm:"column:spent_by"`
}

func (UTXOScheme) TableName() string { return "utxos" }

// ────────────────────── DB Initialization ──────────────────────

// InitAccountDB opens a SQLite database and auto-migrates the utxos table.
func InitAccountDB(dsn string) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		panic(fmt.Sprintf("failed to open accounts database: %v", err))
	}
	if err := db.AutoMigrate(&UTXOScheme{}); err != nil {
		panic(fmt.Sprintf("failed to migrate utxos table: %v", err))
	}
	return db
}

// ────────────────────── CRUD Operations ──────────────────────

// CreateUTXO inserts a new UTXO into the database.
func (a *Account) CreateUTXO(utxo *UTXO) error {
	return a.db.Create(&UTXOScheme{
		UTXOID:  utxo.ID,
		Owner:   utxo.Owner,
		Token:   string(utxo.Token),
		Amount:  string(utxo.Amount),
		ZkProof: utxo.ZkProof,
		Spent:   false,
		SpentBy: "",
	}).Error
}

// GetUTXO retrieves a single UTXO by ID.
func (a *Account) GetUTXO(id string) (*UTXO, error) {
	var row UTXOScheme
	if err := a.db.First(&row, "utxo_id = ?", id).Error; err != nil {
		return nil, err
	}
	return schemeToUTXO(&row), nil
}

// FindUnspentUTXOs returns all unspent UTXOs for the given owner and token.
func (a *Account) FindUnspentUTXOs(owner string, token TokenID) ([]*UTXO, error) {
	var rows []UTXOScheme
	err := a.db.Where("owner = ? AND token = ? AND spent = ?", owner, string(token), false).
		Find(&rows).Error
	if err != nil {
		return nil, err
	}
	utxos := make([]*UTXO, 0, len(rows))
	for i := range rows {
		utxos = append(utxos, schemeToUTXO(&rows[i]))
	}
	return utxos, nil
}

// SpendUTXOs verifies the ZK proof on each UTXO then marks them all as spent.
// Returns an error if any UTXO is not found, already spent, or fails proof verification.
func (a *Account) SpendUTXOs(utxoIDs []string, spentBy string) error {
	for _, id := range utxoIDs {
		utxo, err := a.GetUTXO(id)
		if err != nil {
			return fmt.Errorf("UTXO %s not found: %w", id, err)
		}
		if utxo.Spent {
			return fmt.Errorf("UTXO %s is already spent", id)
		}
		if err := verifySpendProof(utxo); err != nil {
			return fmt.Errorf("invalid proof for UTXO %s: %w", id, err)
		}
	}
	return a.db.Model(&UTXOScheme{}).
		Where("utxo_id IN ?", utxoIDs).
		Updates(map[string]any{"spent": true, "spent_by": spentBy}).Error
}

// ────────────────────── UTXO ↔ Scheme Conversion ──────────────────────

func schemeToUTXO(s *UTXOScheme) *UTXO {
	return &UTXO{
		ID:      s.UTXOID,
		Owner:   s.Owner,
		Token:   TokenID(s.Token),
		Amount:  CipherText(s.Amount),
		ZkProof: s.ZkProof,
		Spent:   s.Spent,
		SpentBy: s.SpentBy,
	}
}
