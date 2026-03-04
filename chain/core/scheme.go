package core

import (
	"fmt"
	"math/big"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// ────────────────────── SQL Model ──────────────────────

// OrderScheme is the flat SQL model for the orders table.
type OrderScheme struct {
	ID     string `gorm:"primaryKey;column:id"`
	Type   int    `gorm:"column:type;index:idx_pair_type"`
	Token1 string `gorm:"column:token1;index:idx_pair_type"`
	Token2 string `gorm:"column:token2;index:idx_pair_type"`
	Price  string `gorm:"column:price"`
	Amount string `gorm:"column:amount"`
	Status int    `gorm:"column:status;index"`
}

func (OrderScheme) TableName() string {
	return "orders"
}

// ────────────────────── DB Initialization ──────────────────────

// InitOrderDB opens a SQLite database and auto-migrates the orders table.
func InitOrderDB(dsn string) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		panic(fmt.Sprintf("failed to open orders database: %v", err))
	}
	if err := db.AutoMigrate(&OrderScheme{}); err != nil {
		panic(fmt.Sprintf("failed to migrate orders table: %v", err))
	}
	return db
}

// ────────────────────── Order ↔ Scheme Conversion ──────────────────────

func orderToScheme(o *Order) *OrderScheme {
	priceStr := ""
	if o.Price != nil {
		priceStr = o.Price.String()
	}
	return &OrderScheme{
		ID:     string(o.ID),
		Type:   int(o.Type),
		Token1: string(o.Subject.Token1),
		Token2: string(o.Subject.Token2),
		Price:  priceStr,
		Amount: string(o.Amount),
		Status: int(o.Status),
	}
}

func schemeToOrder(s *OrderScheme) *Order {
	var price *big.Int
	if s.Price != "" {
		price = new(big.Int)
		price.SetString(s.Price, 10)
	}
	return &Order{
		ID:   OrderID(s.ID),
		Type: TradeType(s.Type),
		Subject: TradePair{
			Token1: TokenID(s.Token1),
			Token2: TokenID(s.Token2),
		},
		Price:  price,
		Amount: CipherText(s.Amount),
		Status: OrderStat(s.Status),
	}
}
