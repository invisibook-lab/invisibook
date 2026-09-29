package core

import (
	"encoding/json"
	"fmt"

	"gorm.io/gorm"

	"github.com/invisibook-lab/invisibook/store"
)

// The staging layer's names for the orderbook's tables.
const (
	OrdersTable             = "orders"
	CompareSubmissionsTable = "compare_submissions"
	SettleSubmissionsTable  = "settle_submissions"
	SettleAddrsTable        = "settle_addrs"
)

// orderApplier writes staged order rows into the orders table.
type orderApplier struct{}

func (orderApplier) Table() string { return OrdersTable }

func (orderApplier) Upsert(tx *gorm.DB, payload string) error {
	var row OrderScheme
	if err := json.Unmarshal([]byte(payload), &row); err != nil {
		return fmt.Errorf("decoding staged order: %w", err)
	}
	return tx.Save(&row).Error
}

func (orderApplier) Delete(tx *gorm.DB, key string) error {
	return tx.Where("id = ?", key).Delete(&OrderScheme{}).Error
}

// compareSubmissionApplier writes staged compare submissions.
type compareSubmissionApplier struct{}

func (compareSubmissionApplier) Table() string { return CompareSubmissionsTable }

func (compareSubmissionApplier) Upsert(tx *gorm.DB, payload string) error {
	var row CompareSubmissionScheme
	if err := json.Unmarshal([]byte(payload), &row); err != nil {
		return fmt.Errorf("decoding staged compare submission: %w", err)
	}
	return tx.Save(&row).Error
}

func (compareSubmissionApplier) Delete(tx *gorm.DB, key string) error {
	return tx.Where("order_id = ?", key).Delete(&CompareSubmissionScheme{}).Error
}

// settleSubmissionApplier writes staged settle submissions.
type settleSubmissionApplier struct{}

func (settleSubmissionApplier) Table() string { return SettleSubmissionsTable }

func (settleSubmissionApplier) Upsert(tx *gorm.DB, payload string) error {
	var row SettleSubmissionScheme
	if err := json.Unmarshal([]byte(payload), &row); err != nil {
		return fmt.Errorf("decoding staged settle submission: %w", err)
	}
	return tx.Save(&row).Error
}

func (settleSubmissionApplier) Delete(tx *gorm.DB, key string) error {
	return tx.Where("order_id = ?", key).Delete(&SettleSubmissionScheme{}).Error
}

// settleAddrApplier writes staged settle addresses.
type settleAddrApplier struct{}

func (settleAddrApplier) Table() string { return SettleAddrsTable }

func (settleAddrApplier) Upsert(tx *gorm.DB, payload string) error {
	var row SettleAddrScheme
	if err := json.Unmarshal([]byte(payload), &row); err != nil {
		return fmt.Errorf("decoding staged settle address: %w", err)
	}
	return tx.Save(&row).Error
}

func (settleAddrApplier) Delete(tx *gorm.DB, key string) error {
	return tx.Where("order_id = ?", key).Delete(&SettleAddrScheme{}).Error
}

// Appliers returns the orderbook's staged tables, for registration with the
// staging layer.
func Appliers() []store.Applier {
	return []store.Applier{
		orderApplier{},
		compareSubmissionApplier{},
		settleSubmissionApplier{},
		settleAddrApplier{},
	}
}
