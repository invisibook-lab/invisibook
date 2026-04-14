package core

import (
	"encoding/json"
	"fmt"
	"math/big"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// ────────────────────── SQL Model ──────────────────────

// OrderScheme is the flat SQL model for the orders table.
type OrderScheme struct {
	ID           string `gorm:"primaryKey;column:id"`
	Type         int    `gorm:"column:type;index:idx_pair_type"`
	Token1       string `gorm:"column:token1;index:idx_pair_type"`
	Token2       string `gorm:"column:token2;index:idx_pair_type"`
	Price        string `gorm:"column:price"`
	Amount       string `gorm:"column:amount"`
	Owner        string `gorm:"column:owner;index"`
	InputCashIDs string `gorm:"column:input_cash_ids"` // JSON array of cash IDs
	Status       int    `gorm:"column:status;index"`
	MatchOrder   string `gorm:"column:match_order"`
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
func (ot *OrderBook) InsertOrder(order *Order) error {
	return ot.db.Create(orderToScheme(order)).Error
}

// GetOrder retrieves a single order by ID.
func (ot *OrderBook) GetOrder(id OrderID) (*Order, error) {
	var row OrderScheme
	if err := ot.db.First(&row, "id = ?", string(id)).Error; err != nil {
		return nil, err
	}
	return schemeToOrder(&row), nil
}

// UpdateOrderStatus updates the status of an order by ID.
func (ot *OrderBook) UpdateOrderStatus(id OrderID, status OrderStat) error {
	return ot.db.Model(&OrderScheme{}).Where("id = ?", string(id)).Update("status", int(status)).Error
}

// UpdateOrderMatchOrder sets the match_order field of an order.
func (ot *OrderBook) UpdateOrderMatchOrder(id OrderID, matchID OrderID) error {
	return ot.db.Model(&OrderScheme{}).Where("id = ?", string(id)).Update("match_order", string(matchID)).Error
}

// FindPendingCounterOrders queries pending orders of the given type on the
// specified pair that have a non-empty price. All parameters are passed via
// GORM's parameterized placeholders to prevent SQL injection.
func (ot *OrderBook) FindPendingCounterOrders(pair TradePair, counterType TradeType) ([]*Order, error) {
	var rows []OrderScheme
	err := ot.db.Where(
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
func (ot *OrderBook) FindAllOrders() ([]*Order, error) {
	var rows []OrderScheme
	if err := ot.db.Find(&rows).Error; err != nil {
		return nil, err
	}
	return schemesToOrders(rows), nil
}

// OrderFilter holds optional filter criteria for querying orders.
// All fields are pointers so that nil means "don't filter by this field".
// Limit=0 means no limit; Offset=0 means start from beginning.
type OrderFilter struct {
	ID     *OrderID
	Type   *TradeType
	Token1 *TokenID
	Token2 *TokenID
	Status *OrderStat
	Limit  int
	Offset int
}

// FindOrdersByFilter queries orders matching the given filter criteria with pagination.
// Every condition is applied via parameterized placeholders (防止 SQL 注入).
func (ot *OrderBook) FindOrdersByFilter(f OrderFilter) ([]*Order, error) {
	query := ot.db.Model(&OrderScheme{})

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
	if f.Offset > 0 {
		query = query.Offset(f.Offset)
	}
	if f.Limit > 0 {
		query = query.Limit(f.Limit)
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
	cashIDsJSON := "[]"
	if len(o.InputCashIDs) > 0 {
		if b, err := json.Marshal(o.InputCashIDs); err == nil {
			cashIDsJSON = string(b)
		}
	}
	return &OrderScheme{
		ID:           string(o.ID),
		Type:         int(o.Type),
		Token1:       string(o.Subject.Token1),
		Token2:       string(o.Subject.Token2),
		Price:        priceStr,
		Amount:       string(o.Amount),
		Owner:        o.Owner,
		InputCashIDs: cashIDsJSON,
		Status:       int(o.Status),
		MatchOrder:   string(o.MatchOrder),
	}
}

func schemeToOrder(s *OrderScheme) *Order {
	var price *big.Int
	if s.Price != "" {
		price = new(big.Int)
		price.SetString(s.Price, 10)
	}
	var cashIDs []string
	if s.InputCashIDs != "" {
		_ = json.Unmarshal([]byte(s.InputCashIDs), &cashIDs)
	}
	return &Order{
		ID:   OrderID(s.ID),
		Type: TradeType(s.Type),
		Subject: TradePair{
			Token1: TokenID(s.Token1),
			Token2: TokenID(s.Token2),
		},
		Price:        price,
		Amount:       CipherText(s.Amount),
		Owner:        s.Owner,
		InputCashIDs: cashIDs,
		MatchOrder:   OrderID(s.MatchOrder),
		Status:       OrderStat(s.Status),
	}
}

func schemesToOrders(rows []OrderScheme) []*Order {
	orders := make([]*Order, 0, len(rows))
	for i := range rows {
		orders = append(orders, schemeToOrder(&rows[i]))
	}
	return orders
}
