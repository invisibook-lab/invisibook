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

// ────────────────────── CRUD Operations ──────────────────────

// InsertOrder inserts a new order into the database.
func InsertOrder(db *gorm.DB, order *Order) error {
	return db.Create(orderToScheme(order)).Error
}

// GetOrder retrieves a single order by ID.
func GetOrder(db *gorm.DB, id OrderID) (*Order, error) {
	var row OrderScheme
	if err := db.First(&row, "id = ?", string(id)).Error; err != nil {
		return nil, err
	}
	return schemeToOrder(&row), nil
}

// UpdateOrderStatus updates the status of an order by ID.
func UpdateOrderStatus(db *gorm.DB, id OrderID, status OrderStat) error {
	return db.Model(&OrderScheme{}).Where("id = ?", string(id)).Update("status", int(status)).Error
}

// FindPendingCounterOrders queries pending orders of the given type on the
// specified pair that have a non-empty price. All parameters are passed via
// GORM's parameterized placeholders to prevent SQL injection.
func FindPendingCounterOrders(db *gorm.DB, pair TradePair, counterType TradeType) ([]*Order, error) {
	var rows []OrderScheme
	err := db.Where(
		"status = ? AND type = ? AND token1 = ? AND token2 = ? AND price != ''",
		int(Pending), int(counterType),
		string(pair.Token1), string(pair.Token2),
	).Find(&rows).Error
	if err != nil {
		return nil, err
	}
	return schemesToOrders(rows), nil
}

// FindAllOrders returns every order in the database.
func FindAllOrders(db *gorm.DB) ([]*Order, error) {
	var rows []OrderScheme
	if err := db.Find(&rows).Error; err != nil {
		return nil, err
	}
	return schemesToOrders(rows), nil
}

// OrderFilter holds optional filter criteria for querying orders.
// All fields are pointers so that nil means "don't filter by this field".
type OrderFilter struct {
	ID     *OrderID
	Type   *TradeType
	Token1 *TokenID
	Token2 *TokenID
	Status *OrderStat
}

// FindOrdersByFilter queries orders matching the given filter criteria.
// Every condition is applied via parameterized placeholders (防止 SQL 注入).
func FindOrdersByFilter(db *gorm.DB, f OrderFilter) ([]*Order, error) {
	query := db.Model(&OrderScheme{})

	if f.ID != nil {
		query = query.Where("id = ?", string(*f.ID))
	}
	if f.Type != nil {
		query = query.Where("type = ?", int(*f.Type))
	}
	if f.Token1 != nil {
		query = query.Where("token1 = ?", string(*f.Token1))
	}
	if f.Token2 != nil {
		query = query.Where("token2 = ?", string(*f.Token2))
	}
	if f.Status != nil {
		query = query.Where("status = ?", int(*f.Status))
	}

	var rows []OrderScheme
	if err := query.Find(&rows).Error; err != nil {
		return nil, err
	}
	return schemesToOrders(rows), nil
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

func schemesToOrders(rows []OrderScheme) []*Order {
	orders := make([]*Order, 0, len(rows))
	for i := range rows {
		orders = append(orders, schemeToOrder(&rows[i]))
	}
	return orders
}
