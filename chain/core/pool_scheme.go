package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"sync"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// ────────────────────── SQL models ──────────────────────

// NoteScheme is one leaf of the note commitment tree. `cm` is deliberately
// a NON-unique index: duplicate commitments are legal (Faerie Gold is
// prevented by the position-bound rho, not by leaf uniqueness).
type NoteScheme struct {
	LeafIndex uint64 `gorm:"primaryKey;autoIncrement:false;column:leaf_index"`
	Cm        string `gorm:"column:cm;index;not null"` // 64-char hex
	Height    uint64 `gorm:"column:height"`
	Source    string `gorm:"column:source"` // "genesis" | "deposit" | "withdraw-change" | ...
}

func (NoteScheme) TableName() string { return "notes" }

// NullifierScheme is the presence-keyed spent set: a row exists iff the
// nullifier was published. No undo data — the row IS the bit.
type NullifierScheme struct {
	Nf     string `gorm:"primaryKey;column:nf"` // 64-char hex
	Height uint64 `gorm:"column:height"`
	By     string `gorm:"column:by"` // request kind for debugging, no identity
}

func (NullifierScheme) TableName() string { return "nullifiers" }

// AnchorScheme records every historical tree root. All anchors stay valid
// forever; spends may reference any of them.
type AnchorScheme struct {
	Root      string `gorm:"primaryKey;column:root"` // 64-char hex
	LeafCount uint64 `gorm:"column:leaf_count"`
	Height    uint64 `gorm:"column:height"`
}

func (AnchorScheme) TableName() string { return "anchors" }

// TreeStateScheme is the singleton frontier snapshot (id = 1). If it ever
// disagrees with the notes table, the frontier is rebuilt by replaying the
// notes in leaf order (self-healing).
type TreeStateScheme struct {
	ID           uint   `gorm:"primaryKey;column:id"`
	LeafCount    uint64 `gorm:"column:leaf_count"`
	FrontierJSON string `gorm:"column:frontier_json"`
}

func (TreeStateScheme) TableName() string { return "tree_state" }

// BridgeSeenScheme deduplicates bridge commitments: replaying the same
// deposit event cannot mint twice. (Forgery is separately gated by the
// bridge operator signature until the real inclusion proof lands.)
type BridgeSeenScheme struct {
	BridgeCommitment string `gorm:"primaryKey;column:bridge_commitment"`
	Height           uint64 `gorm:"column:height"`
}

func (BridgeSeenScheme) TableName() string { return "bridge_seen" }

// SettlementSeenScheme makes payout minting IDEMPOTENT per settlement: the
// row is created in the SAME transaction as both payouts and both hiding
// refund notes, keyed by
// the settlement id. A retry (crash between the mint and the order-side
// updates, then resubmission or restart) finds the row and skips the mint
// instead of minting again. The note commitments are recorded so a retry
// carrying DIFFERENT legs is rejected instead of silently skipped.
type SettlementSeenScheme struct {
	SettlementID     string `gorm:"primaryKey;column:settlement_id"`
	CmNoteA          string `gorm:"column:cm_note_a;not null"`
	CmNoteB          string `gorm:"column:cm_note_b;not null"`
	CmRefundA        string `gorm:"column:cm_refund_a;not null;default:''"`
	CmRefundB        string `gorm:"column:cm_refund_b;not null;default:''"`
	ALeafIndex       uint64 `gorm:"column:a_leaf_index"`
	BLeafIndex       uint64 `gorm:"column:b_leaf_index"`
	ARefundLeafIndex uint64 `gorm:"column:a_refund_leaf_index"`
	BRefundLeafIndex uint64 `gorm:"column:b_refund_leaf_index"`
	Height           uint64 `gorm:"column:height"`
}

func (SettlementSeenScheme) TableName() string { return "settlement_seen" }

// ────────────────────── DB Initialization ──────────────────────

// InitAccountDB opens a SQLite database and auto-migrates the shielded-pool
// tables. `logLevel` controls GORM SQL logging verbosity.
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
	if err := db.AutoMigrate(&NoteScheme{}, &NullifierScheme{},
		&AnchorScheme{}, &TreeStateScheme{}, &BridgeSeenScheme{},
		&SettlementSeenScheme{}); err != nil {
		panic(fmt.Sprintf("failed to migrate pool tables: %v", err))
	}
	return db
}

// ────────────────────── Pool store ──────────────────────

// pool holds the in-memory frontier mirror of the notes table, guarded for
// concurrent writings. The DB rows are the source of truth; the mirror is
// rebuilt from them whenever they disagree.
type pool struct {
	mu       sync.Mutex
	frontier *Frontier
}

// InitPool loads or rebuilds the frontier from the database. Call once at
// tripod construction, after AutoMigrate.
func (a *Account) InitPool() error {
	a.pool.mu.Lock()
	defer a.pool.mu.Unlock()
	f, err := loadFrontier(a.db)
	if err != nil {
		return err
	}
	a.pool.frontier = f
	return nil
}

// loadFrontier restores the frontier from tree_state, falling back to a
// full replay of the notes table when the snapshot is missing or stale.
func loadFrontier(db *gorm.DB) (*Frontier, error) {
	var noteCount int64
	if err := db.Model(&NoteScheme{}).Count(&noteCount).Error; err != nil {
		return nil, fmt.Errorf("counting notes: %w", err)
	}

	var st TreeStateScheme
	err := db.First(&st, "id = ?", 1).Error
	if err == nil && st.LeafCount == uint64(noteCount) {
		var fs FrontierState
		if jerr := json.Unmarshal([]byte(st.FrontierJSON), &fs); jerr == nil {
			if f, ferr := FrontierFromState(fs); ferr == nil {
				return f, nil
			}
		}
		// Fall through to replay on any decode failure.
	} else if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("loading tree state: %w", err)
	}

	// Replay all notes in leaf order.
	f := NewFrontier()
	var rows []NoteScheme
	if err := db.Order("leaf_index asc").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("replaying notes: %w", err)
	}
	for i, row := range rows {
		if row.LeafIndex != uint64(i) {
			return nil, fmt.Errorf("notes table has a gap: row %d has leaf_index %d", i, row.LeafIndex)
		}
		cm, ok := new(big.Int).SetString(row.Cm, 16)
		if !ok {
			return nil, fmt.Errorf("note %d cm is not hex: %q", row.LeafIndex, row.Cm)
		}
		if _, err := f.Append(cm); err != nil {
			return nil, err
		}
	}
	return f, nil
}

// PoolMutation is one atomic pool update: publish nullifiers, append
// notes, refresh the frontier snapshot, and record the new anchor — all in
// ONE SQLite transaction. `extra` (optional) runs inside the same
// transaction for request-specific rows (e.g. bridge_seen).
type PoolMutation struct {
	Nullifiers []string // 64-char hex, pre-checked unused
	NoteCms    []*big.Int
	Height     uint64
	Source     string
	By         string
	Extra      func(tx *gorm.DB) error
}

// ApplyPoolMutation executes the mutation atomically. On success it returns
// the leaf indices of the appended notes. On any error the transaction is
// rolled back and the in-memory frontier is restored from the database, so
// chain state and mirror can never diverge. The nullifier rows are written
// before the notes as defense-in-depth (never mint without having spent).
func (a *Account) ApplyPoolMutation(m PoolMutation) ([]uint64, error) {
	a.pool.mu.Lock()
	defer a.pool.mu.Unlock()

	// Trial-append on a copy so a full tree (or any frontier error) rejects
	// the request before any DB write.
	work := *a.pool.frontier
	indices := make([]uint64, 0, len(m.NoteCms))
	for _, cm := range m.NoteCms {
		idx, err := work.Append(cm)
		if err != nil {
			return nil, err
		}
		indices = append(indices, idx)
	}

	err := a.db.Transaction(func(tx *gorm.DB) error {
		for _, nf := range m.Nullifiers {
			if err := tx.Create(&NullifierScheme{Nf: nf, Height: m.Height, By: m.By}).Error; err != nil {
				return fmt.Errorf("inserting nullifier %s: %w", nf, err)
			}
		}
		for i, cm := range m.NoteCms {
			row := &NoteScheme{
				LeafIndex: indices[i],
				Cm:        FrToHex(cm),
				Height:    m.Height,
				Source:    m.Source,
			}
			if err := tx.Create(row).Error; err != nil {
				return fmt.Errorf("appending note %d: %w", indices[i], err)
			}
		}
		if len(m.NoteCms) > 0 {
			fs, err := json.Marshal(work.State())
			if err != nil {
				return err
			}
			st := TreeStateScheme{ID: 1, LeafCount: work.Size(), FrontierJSON: string(fs)}
			if err := tx.Save(&st).Error; err != nil {
				return fmt.Errorf("saving tree state: %w", err)
			}
			anchor := AnchorScheme{Root: FrToHex(work.Root()), LeafCount: work.Size(), Height: m.Height}
			if err := tx.Where(AnchorScheme{Root: anchor.Root}).
				FirstOrCreate(&anchor).Error; err != nil {
				return fmt.Errorf("recording anchor: %w", err)
			}
		}
		if m.Extra != nil {
			if err := m.Extra(tx); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	a.pool.frontier = &work
	return indices, nil
}

// NullifierSpent reports whether a nullifier is already in the spent set.
func (a *Account) NullifierSpent(nf string) (bool, error) {
	var count int64
	if err := a.db.Model(&NullifierScheme{}).Where("nf = ?", nf).Count(&count).Error; err != nil {
		return false, err
	}
	return count > 0, nil
}

// AnchorKnown reports whether a root was ever a tree root on this chain.
// The empty-tree root is always valid.
func (a *Account) AnchorKnown(root string) (bool, error) {
	if root == FrToHex(EmptyRoot(TreeDepth)) {
		return true, nil
	}
	var count int64
	if err := a.db.Model(&AnchorScheme{}).Where("root = ?", root).Count(&count).Error; err != nil {
		return false, err
	}
	return count > 0, nil
}

// SettlementMinted returns the mint record of `settlementID`, or nil when
// this settlement has not minted its payout notes yet.
func (a *Account) SettlementMinted(settlementID string) (*SettlementSeenScheme, error) {
	var row SettlementSeenScheme
	err := a.db.First(&row, "settlement_id = ?", settlementID).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &row, nil
}

// MintSettlementNotes mints the two payouts and two hiding refund notes of
// one settlement EXACTLY ONCE. The first call appends all four and records the settlement id in
// the same transaction; every later call with the same id returns the
// recorded leaf indices with `already = true` and appends nothing. A retry
// whose note commitments differ from the recorded ones is an error — a
// diverging resubmission must never mint a second output set.
// All commitment arguments must be canonical 64-char field-element hexes.
func (a *Account) MintSettlementNotes(
	settlementID, cmAHex, cmBHex, cmRefundAHex, cmRefundBHex string, height uint64, by string,
) (indices []uint64, already bool, err error) {
	check := func(row *SettlementSeenScheme) ([]uint64, bool, error) {
		if row.CmNoteA != cmAHex || row.CmNoteB != cmBHex ||
			row.CmRefundA != cmRefundAHex || row.CmRefundB != cmRefundBHex {
			return nil, false, fmt.Errorf(
				"settlement %s already minted different payout notes", settlementID)
		}
		return []uint64{row.ALeafIndex, row.BLeafIndex, row.ARefundLeafIndex, row.BRefundLeafIndex}, true, nil
	}
	if row, rerr := a.SettlementMinted(settlementID); rerr != nil {
		return nil, false, rerr
	} else if row != nil {
		return check(row)
	}
	cmA, err := ParseFrHex(cmAHex)
	if err != nil {
		return nil, false, fmt.Errorf("cm_note_a: %w", err)
	}
	cmB, err := ParseFrHex(cmBHex)
	if err != nil {
		return nil, false, fmt.Errorf("cm_note_b: %w", err)
	}
	cmRefundA, err := ParseFrHex(cmRefundAHex)
	if err != nil {
		return nil, false, fmt.Errorf("cm_refund_a: %w", err)
	}
	cmRefundB, err := ParseFrHex(cmRefundBHex)
	if err != nil {
		return nil, false, fmt.Errorf("cm_refund_b: %w", err)
	}
	minted, err := a.ApplyPoolMutation(PoolMutation{
		NoteCms: []*big.Int{cmA, cmB, cmRefundA, cmRefundB},
		Height:  height,
		Source:  "settle",
		By:      by,
		Extra: func(tx *gorm.DB) error {
			return tx.Create(&SettlementSeenScheme{
				SettlementID: settlementID,
				CmNoteA:      cmAHex,
				CmNoteB:      cmBHex,
				CmRefundA:    cmRefundAHex,
				CmRefundB:    cmRefundBHex,
				ALeafIndex:   0, // placeholder, set below
				BLeafIndex:   0,
				Height:       height,
			}).Error
		},
	})
	if err != nil {
		// A concurrent/duplicate insert lost the race on the primary key:
		// fall back to the recorded row.
		if row, rerr := a.SettlementMinted(settlementID); rerr == nil && row != nil {
			return check(row)
		}
		return nil, false, err
	}
	// Record the leaf indices (informational; the same transaction already
	// holds the id + commitments that gate idempotency).
	if err := a.db.Model(&SettlementSeenScheme{}).
		Where("settlement_id = ?", settlementID).
		Updates(map[string]any{"a_leaf_index": minted[0], "b_leaf_index": minted[1],
			"a_refund_leaf_index": minted[2], "b_refund_leaf_index": minted[3]}).Error; err != nil {
		return nil, false, err
	}
	return minted, false, nil
}

// BridgeSeen reports whether a bridge commitment was already consumed.
func (a *Account) BridgeSeen(bridgeCommitment string) (bool, error) {
	var count int64
	if err := a.db.Model(&BridgeSeenScheme{}).
		Where("bridge_commitment = ?", bridgeCommitment).Count(&count).Error; err != nil {
		return false, err
	}
	return count > 0, nil
}

// PoolSize returns the current leaf count.
func (a *Account) PoolSize() uint64 {
	a.pool.mu.Lock()
	defer a.pool.mu.Unlock()
	return a.pool.frontier.Size()
}

// PoolRoot returns the current tree root as 64-char hex.
func (a *Account) PoolRoot() string {
	a.pool.mu.Lock()
	defer a.pool.mu.Unlock()
	return FrToHex(a.pool.frontier.Root())
}

// FindNotes returns up to `limit` notes starting at `startIndex` in leaf
// order (limit <= 0 means no limit).
func (a *Account) FindNotes(startIndex uint64, limit int) ([]NoteScheme, error) {
	q := a.db.Where("leaf_index >= ?", startIndex).Order("leaf_index asc")
	if limit > 0 {
		q = q.Limit(limit)
	}
	var rows []NoteScheme
	if err := q.Find(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}

// FindNoteByCm returns the smallest leaf index holding `cm`, or -1.
func (a *Account) FindNoteByCm(cm string) (int64, error) {
	var row NoteScheme
	err := a.db.Where("cm = ?", cm).Order("leaf_index asc").First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return -1, nil
	}
	if err != nil {
		return -1, err
	}
	return int64(row.LeafIndex), nil
}
