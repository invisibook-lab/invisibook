package consensus

import (
	"errors"
	"fmt"

	"gorm.io/gorm"

	"github.com/yu-org/yu/common"
)

// Reveal is one miner's opening of the commitment it posted on L1 for one L2
// block, as it reached this node over the L2 network.
//
// Kept apart from BlockBid on purpose. A BlockBid is this node's own bid and
// holds `Random`, the one secret that can never be regenerated — lose it and
// the bid is void. A Reveal is public: it is what everybody broadcasts once
// their commitment is on L1, and every node needs the whole network's worth of
// them to run fork choice. Same shape, opposite lifecycles; one table for both
// would tangle this node's secret with everyone's public record.
//
// These are consensus input, not bookkeeping: without them a block's `goal`
// cannot be tied to anything on L1, so a node that has lost them cannot tell
// which fork is canonical. That is why they are persisted and why a starting
// node pulls the ones it missed.
type Reveal struct {
	// BlockHash is the L2 block this opening belongs to.
	BlockHash string `gorm:"primaryKey;column:block_hash"`
	// Height is that block's L2 height; fork choice walks by height.
	Height common.BlockNum `gorm:"column:height;index"`
	// Random is the 64-char hex blinding factor that opens the commitment.
	Random string `gorm:"column:random"`
	// L1BlockHash is the L1 block carrying the commitment. A hash rather than
	// a height so a reorg is visible: if it is no longer on L1's canonical
	// chain, the commitment went with it.
	L1BlockHash string `gorm:"column:l1_block_hash;index"`
	// TxIdx is the transaction's index inside that L1 block.
	TxIdx uint32 `gorm:"column:tx_idx"`
	// MinerPubkey is the hex-encoded compressed key of the block's producer.
	MinerPubkey string `gorm:"column:miner_pubkey;index"`
}

// TableName returns the SQL table name used by GORM for Reveal rows.
func (Reveal) TableName() string { return "reveals" }

// MigrateRevealTable creates the reveal table on the chain database.
func MigrateRevealTable(db *gorm.DB) error {
	if err := db.AutoMigrate(&Reveal{}); err != nil {
		return fmt.Errorf("migrating reveal table: %w", err)
	}
	return nil
}

// Reveals stores the openings this node has collected from the network.
type Reveals struct {
	db *gorm.DB
}

// NewReveals returns a reveal store over the chain database.
func NewReveals(db *gorm.DB) *Reveals {
	return &Reveals{db: db}
}

// Put records one opening, replacing any earlier row for the same block.
//
// Replacing is safe because the block hash pins the content: a second opening
// for the same block either repeats the first or is wrong, and a wrong one is
// caught when it is checked against the commitment on L1, not here.
func (r *Reveals) Put(reveal *Reveal) error {
	if reveal == nil || reveal.BlockHash == "" {
		return errors.New("reveal is missing a block hash")
	}
	if reveal.Random == "" {
		return fmt.Errorf("reveal for block %s carries no opening", reveal.BlockHash)
	}
	if err := r.db.Save(reveal).Error; err != nil {
		return fmt.Errorf("storing the reveal for block %s: %w", reveal.BlockHash, err)
	}
	return nil
}

// Get returns the opening recorded for `blockHash`, or nil when none has
// arrived. A missing opening is an ordinary state — the block may simply not
// have been revealed yet — so it is not an error.
func (r *Reveals) Get(blockHash string) (*Reveal, error) {
	var reveal Reveal
	err := r.db.First(&reveal, "block_hash = ?", blockHash).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading the reveal for block %s: %w", blockHash, err)
	}
	return &reveal, nil
}

// AtHeight returns every opening collected for one L2 height.
//
// Fork choice needs them by height: a height may carry several competing
// blocks, and only those whose opening has arrived can be scored at all.
func (r *Reveals) AtHeight(height common.BlockNum) ([]*Reveal, error) {
	var reveals []*Reveal
	if err := r.db.Where("height = ?", height).Find(&reveals).Error; err != nil {
		return nil, fmt.Errorf("reading reveals at height %d: %w", height, err)
	}
	return reveals, nil
}

// SinceHeight returns every opening at or above `height`, ordered by height.
//
// This is what answers a peer asking to catch up: a starting node knows how
// far its own record goes and asks for the rest.
func (r *Reveals) SinceHeight(height common.BlockNum, limit int) ([]*Reveal, error) {
	var reveals []*Reveal
	query := r.db.Where("height >= ?", height).Order("height ASC")
	if limit > 0 {
		query = query.Limit(limit)
	}
	if err := query.Find(&reveals).Error; err != nil {
		return nil, fmt.Errorf("reading reveals from height %d: %w", height, err)
	}
	return reveals, nil
}

// HighestHeight reports the greatest height this node holds an opening for,
// or 0 when it holds none.
func (r *Reveals) HighestHeight() (common.BlockNum, error) {
	var reveal Reveal
	err := r.db.Order("height DESC").First(&reveal).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("reading the highest revealed height: %w", err)
	}
	return reveal.Height, nil
}
