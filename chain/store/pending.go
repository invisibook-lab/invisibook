package store

import (
	"fmt"
	"sync"

	"gorm.io/gorm"

	"github.com/yu-org/yu/common"
)

// Block identifies the block whose writes are being staged.
type Block struct {
	Height common.BlockNum
	Hash   string
}

// Pending is the staging layer that makes a block's writes undoable.
//
// A block's writes do not land in the tables they belong to. They are staged,
// tagged with the block that made them, and only promoted once L1 has settled
// that height. Until then they can be dropped by height, which is what lets a
// node discard the blocks L1 ruled against without touching anything L1 has
// already accepted.
//
// The main tables therefore only ever hold settled state: their schema, their
// indexes and every query over them stay exactly as they were, and a write
// that reaches them is durable immediately.
type Pending struct {
	db *gorm.DB

	mu sync.RWMutex
	// current is the block being executed. Execution is serial — the kernel
	// runs one block's writings to completion before starting the next — so a
	// single value suffices, set by the consensus tripod before it executes.
	current  Block
	appliers map[string]Applier
}

// NewPending returns a staging layer over the chain database.
func NewPending(db *gorm.DB) *Pending {
	return &Pending{db: db, appliers: make(map[string]Applier)}
}

// Register adds the tables this layer promotes and drops together.
func (p *Pending) Register(appliers ...Applier) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, applier := range appliers {
		p.appliers[applier.Table()] = applier
	}
}

// SetBlock records which block the writes that follow belong to. The consensus
// tripod calls it immediately before executing a block.
func (p *Pending) SetBlock(height common.BlockNum, hash string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.current = Block{Height: height, Hash: hash}
}

// Current returns the block writes are currently attributed to.
func (p *Pending) Current() Block {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.current
}

// ApplyThrough promotes every table's staged rows at or below `height`.
//
// Called once L1 has settled that height, which is also the point those writes
// become durable: they are written to the main tables and committed there.
// All tables are promoted in one transaction and in sequence order, so a block
// that settles an order and spends its cash lands as one change or not at all,
// and a row touched twice ends in the state the later change left it.
func (p *Pending) ApplyThrough(height common.BlockNum) error {
	return p.db.Transaction(func(tx *gorm.DB) error {
		var writes []StagedWrite
		if err := tx.Where("block_number <= ?", height).Order("seq ASC").Find(&writes).Error; err != nil {
			return fmt.Errorf("reading staged writes through height %d: %w", height, err)
		}

		for _, write := range writes {
			applier, ok := p.applier(write.Table)
			if !ok {
				return fmt.Errorf("no applier registered for staged table %s", write.Table)
			}
			if write.Deleted {
				if err := applier.Delete(tx, write.RowKey); err != nil {
					return fmt.Errorf("deleting %s/%s: %w", write.Table, write.RowKey, err)
				}
				continue
			}
			if err := applier.Upsert(tx, write.Payload); err != nil {
				return fmt.Errorf("writing %s/%s: %w", write.Table, write.RowKey, err)
			}
		}

		if err := tx.Where("block_number <= ?", height).Delete(&StagedWrite{}).Error; err != nil {
			return err
		}

		// Recorded with the promotion it describes: after a crash this is what
		// says how much of the chain's state actually reached the tables.
		return tx.Save(&AppliedHeight{ID: 1, Height: height}).Error
	})
}

// DropFrom discards every table's staged rows from `height` upwards, undoing
// the blocks L1 ruled against. The main tables are untouched — nothing in them
// came from an unsettled block.
func (p *Pending) DropFrom(height common.BlockNum) error {
	err := p.db.Where("block_number >= ?", height).Delete(&StagedWrite{}).Error
	if err != nil {
		return fmt.Errorf("dropping staged writes from height %d: %w", height, err)
	}
	return nil
}

// AppliedHeight returns the highest height whose staged writes have been
// promoted, or 0 when none have.
func (p *Pending) AppliedHeight() (common.BlockNum, error) {
	var row AppliedHeight
	err := p.db.First(&row, "id = ?", 1).Error
	if err != nil {
		// No row yet: nothing has ever been promoted.
		return 0, nil
	}
	return row.Height, nil
}

// applier returns the registered applier for a staged table.
func (p *Pending) applier(table string) (Applier, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	applier, ok := p.appliers[table]
	return applier, ok
}
