package store

import (
	"errors"
	"fmt"

	"gorm.io/gorm"

	"github.com/yu-org/yu/common"
)

// BlockBid is the opening of the commitment this node posted on L1 for one of
// its own blocks.
//
// Only the commitment reaches L1, so the opening is the sole way to prove later
// what that commitment stood for. Losing it forfeits the bid outright: the L1
// tokens were spent, the commitment sits on chain, and nothing can ever be
// shown to match it. That is why it is written to disk before the submission
// goes out rather than held in memory alongside it.
type BlockBid struct {
	// BlockHash identifies the L2 block this bid was made for.
	BlockHash string `gorm:"primaryKey;column:block_hash"`
	// Height is the L2 height of that block.
	Height common.BlockNum `gorm:"column:height;index"`
	// Goal is the block's competition score as a decimal string.
	Goal string `gorm:"column:goal"`
	// Random is the 64-char hex blinding factor of the commitment.
	Random string `gorm:"column:random"`
	// Commitment is the value posted on L1, 64-char hex.
	Commitment string `gorm:"column:commitment"`
	// L1TxHash is the L1 transaction carrying the commitment, empty until the
	// submission has been sent.
	L1TxHash string `gorm:"column:l1_tx_hash;index"`
	// L1BlockHash is the L1 block the commitment landed in, empty until it
	// has. Together with TxIdx it is what lets a verifier find the commitment
	// without scanning L1, and it dates the anchoring — which is how a fork
	// bought after the fact is told apart from one that existed at the time.
	//
	// A hash rather than a height on purpose: if this block is no longer on
	// L1's canonical chain, the commitment went with it.
	L1BlockHash string `gorm:"column:l1_block_hash;index"`
	// TxIdx is the transaction's index inside that L1 block.
	TxIdx uint32 `gorm:"column:tx_idx"`
}

// TableName returns the SQL table name used by GORM for BlockBid rows.
func (BlockBid) TableName() string { return "block_bids" }

// MigrateBidTable creates the bid table on the chain database.
func MigrateBidTable(db *gorm.DB) error {
	if err := db.AutoMigrate(&BlockBid{}); err != nil {
		return fmt.Errorf("migrating bid table: %w", err)
	}
	return nil
}

// Bids stores the openings of the commitments this node posts on L1.
type Bids struct {
	db *gorm.DB
}

// NewBids returns a bid store over the chain database.
func NewBids(db *gorm.DB) *Bids {
	return &Bids{db: db}
}

// Save records a bid's opening, replacing any earlier row for the same block.
// It must be called before the commitment is submitted to L1, so that a crash
// between the two leaves a recoverable opening rather than a dead commitment.
// Every field but `L1TxHash` must be set.
func (b *Bids) Save(bid *BlockBid) error {
	if bid == nil || bid.BlockHash == "" {
		return errors.New("bid is missing a block hash")
	}
	if err := b.db.Save(bid).Error; err != nil {
		return fmt.Errorf("saving the bid for block %s: %w", bid.BlockHash, err)
	}
	return nil
}

// RecordSubmission attaches the L1 transaction that carried the commitment.
// `blockHash` must name a bid already saved.
func (b *Bids) RecordSubmission(blockHash, l1TxHash string) error {
	result := b.db.Model(&BlockBid{}).
		Where("block_hash = ?", blockHash).
		Update("l1_tx_hash", l1TxHash)
	if result.Error != nil {
		return fmt.Errorf("recording the L1 submission of block %s: %w", blockHash, result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("no bid saved for block %s", blockHash)
	}
	return nil
}

// RecordLocation notes where on L1 the commitment for `blockHash` landed.
//
// Kept apart from RecordSubmission because the two become known at different
// moments: the transaction hash the instant the submission is sent, the
// location only once an L1 block has taken it in. `blockHash` must name a bid
// already saved.
//
// Takes plain strings rather than a location struct from the consensus package
// on purpose — that package already depends on this one, and importing it back
// would close a cycle.
func (b *Bids) RecordLocation(blockHash, l1BlockHash string, txIdx uint32) error {
	result := b.db.Model(&BlockBid{}).
		Where("block_hash = ?", blockHash).
		Updates(map[string]any{"l1_block_hash": l1BlockHash, "tx_idx": txIdx})
	if result.Error != nil {
		return fmt.Errorf("recording the L1 location of block %s: %w", blockHash, result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("no bid saved for block %s", blockHash)
	}
	return nil
}

// Get returns the opening recorded for `blockHash`, or nil when this node made
// no bid for that block.
func (b *Bids) Get(blockHash string) (*BlockBid, error) {
	var bid BlockBid
	err := b.db.First(&bid, "block_hash = ?", blockHash).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading the bid for block %s: %w", blockHash, err)
	}
	return &bid, nil
}
