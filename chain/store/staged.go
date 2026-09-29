package store

import (
	"encoding/json"
	"fmt"

	"gorm.io/gorm"

	"github.com/yu-org/yu/common"
)

// StagedWrite is one row as an unsettled block left it.
//
// Every staged table shares this one table. The tables being staged are all
// keyed by a single string, and everything the staging layer does — promote by
// height, drop by height, find the latest state of a key — is the same for all
// of them, so splitting it per table would be four copies of one mechanism.
// Sharing it also makes promotion atomic across tables, which matters: a block
// that settles an order and spends its cash must not half-land.
type StagedWrite struct {
	// Seq orders changes within a block as well as across them. One block can
	// touch the same row twice — an order is inserted and matched by the same
	// writing — so height alone cannot order them.
	Seq         uint64          `gorm:"primaryKey;autoIncrement;column:seq"`
	BlockNumber common.BlockNum `gorm:"column:block_number;index"`
	BlockHash   string          `gorm:"column:block_hash"`
	// Table is the main table this row belongs to.
	Table string `gorm:"column:table_name;index:idx_staged_table_key"`
	// RowKey is the row's primary key in that table.
	RowKey string `gorm:"column:row_key;index:idx_staged_table_key"`
	// Deleted marks a row the block removed rather than wrote — a tombstone.
	// The row stays in the main table until the height settles; readers must
	// treat it as gone in the meantime.
	Deleted bool `gorm:"column:deleted"`
	// Payload is the row as JSON, empty for a tombstone.
	Payload string `gorm:"column:payload"`
}

// TableName returns the SQL table name used by GORM for StagedWrite rows.
func (StagedWrite) TableName() string { return "staged_writes" }

// AppliedHeight records how far the staged writes have been promoted.
//
// It lives in the chain database, written in the same transaction as the
// promotion it describes, so the two can never disagree. yu's own finalized
// marker cannot serve this purpose: it lives in a different store, so a crash
// between the two writes would leave a block whose state was applied but whose
// marker was not — and nothing on disk able to tell which.
type AppliedHeight struct {
	// ID is always 1: this is a single row.
	ID     uint8           `gorm:"primaryKey;column:id"`
	Height common.BlockNum `gorm:"column:height"`
}

// TableName returns the SQL table name used by GORM for AppliedHeight rows.
func (AppliedHeight) TableName() string { return "applied_height" }

// Applier writes one table's staged rows into the table itself. Each staged
// table registers one.
type Applier interface {
	// Table is the main table this applier owns, matching StagedWrite.Table.
	Table() string
	// Upsert writes `payload` — a JSON row — into the main table.
	Upsert(tx *gorm.DB, payload string) error
	// Delete removes the row `key` from the main table.
	Delete(tx *gorm.DB, key string) error
}

// MigrateStagedTable creates the staging table on the chain database.
func MigrateStagedTable(db *gorm.DB) error {
	if err := db.AutoMigrate(&StagedWrite{}, &AppliedHeight{}); err != nil {
		return fmt.Errorf("migrating staging tables: %w", err)
	}
	return nil
}

// Stage records `row` as the state the current block leaves `key` in.
// A nil `row` with `deleted` set stages a tombstone.
func (p *Pending) Stage(table, key string, row any, deleted bool) error {
	payload := ""
	if !deleted {
		encoded, err := json.Marshal(row)
		if err != nil {
			return fmt.Errorf("encoding staged row %s/%s: %w", table, key, err)
		}
		payload = string(encoded)
	}

	block := p.Current()
	return p.db.Create(&StagedWrite{
		BlockNumber: block.Height,
		BlockHash:   block.Hash,
		Table:       table,
		RowKey:      key,
		Deleted:     deleted,
		Payload:     payload,
	}).Error
}

// Latest decodes the newest staged state of one row into `into`.
//
// Returns found=false when no unsettled block has touched the key, in which
// case the settled table is the whole truth. Returns deleted=true for a
// tombstone, where the settled row still exists but must be treated as gone.
func (p *Pending) Latest(table, key string, into any) (found, deleted bool, err error) {
	var write StagedWrite
	err = p.db.Where("table_name = ? AND row_key = ?", table, key).Order("seq DESC").First(&write).Error
	if err != nil {
		return false, false, nil
	}
	if write.Deleted {
		return true, true, nil
	}
	if err := json.Unmarshal([]byte(write.Payload), into); err != nil {
		return false, false, fmt.Errorf("decoding staged row %s/%s: %w", table, key, err)
	}
	return true, false, nil
}

// LatestAll returns the newest staged state of every row of `table`, decoded
// and keyed by row key, ready to overlay onto a query of the settled table.
func LatestAll[T any](p *Pending, table string) (map[string]Staged[T], error) {
	var writes []StagedWrite
	err := p.db.Where("table_name = ?", table).Order("seq ASC").Find(&writes).Error
	if err != nil {
		return nil, fmt.Errorf("reading staged rows of %s: %w", table, err)
	}

	// Ascending order means a later change overwrites an earlier one.
	staged := make(map[string]Staged[T], len(writes))
	for _, write := range writes {
		if write.Deleted {
			staged[write.RowKey] = Staged[T]{Deleted: true}
			continue
		}
		var row T
		if err := json.Unmarshal([]byte(write.Payload), &row); err != nil {
			return nil, fmt.Errorf("decoding staged row %s/%s: %w", table, write.RowKey, err)
		}
		staged[write.RowKey] = Staged[T]{Row: row}
	}
	return staged, nil
}
