package account

import (
	"encoding/json"
	"fmt"

	"gorm.io/gorm"
)

// CashTable is the staging layer's name for the cash table.
const CashTable = "cash"

// CashApplier writes staged cash rows into the cash table.
type CashApplier struct{}

// Table identifies the table this applier owns.
func (CashApplier) Table() string { return CashTable }

// Upsert writes a staged cash row into the cash table.
func (CashApplier) Upsert(tx *gorm.DB, payload string) error {
	var row CashScheme
	if err := json.Unmarshal([]byte(payload), &row); err != nil {
		return fmt.Errorf("decoding staged cash: %w", err)
	}
	return tx.Save(&row).Error
}

// Delete removes a cash row. Cash is never deleted today — it moves between
// Active, Locked and Spent — but the staging layer supports it uniformly.
func (CashApplier) Delete(tx *gorm.DB, key string) error {
	return tx.Where("cash_id = ?", key).Delete(&CashScheme{}).Error
}

// stage records `row` as the state this block leaves the cash in.
func (a *Account) stage(row CashScheme) error {
	return a.pending.Stage(CashTable, row.CashID, row, false)
}

// latestStaged returns the newest staged state of one cash.
func (a *Account) latestStaged(cashID string) (row CashScheme, found, deleted bool) {
	found, deleted, err := a.pending.Latest(CashTable, cashID, &row)
	if err != nil {
		return CashScheme{}, false, false
	}
	return row, found, deleted
}
