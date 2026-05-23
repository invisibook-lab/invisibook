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
	Pubkey       string `gorm:"column:pubkey;index"`   // owner's ed25519 pubkey (64-char hex)
	InputCashIDs string `gorm:"column:input_cash_ids"` // JSON array of cash IDs
	HandlingFee  string `gorm:"column:handling_fee"`   // JSON array of fee strings
	BlockHeight  uint32 `gorm:"column:block_height"`
	Status       int    `gorm:"column:status;index"`
	MatchOrder   string `gorm:"column:match_order"`
	IsSmaller int `gorm:"column:is_smaller;default:0"` // 0=false, 1=true
}

// TableName returns the SQL table name used by GORM for OrderScheme rows.
func (OrderScheme) TableName() string {
	return "orders"
}

// ────────────────────── Compare Submission SQL Model ──────────────────────

// CompareSubmissionScheme stores a single party's pending MPC share submission
// until the counterparty submits theirs. Once both arrive, the chain verifies
// the MAC, reconstructs cmp and r_smaller, then deletes both rows.
type CompareSubmissionScheme struct {
	OrderID      string `gorm:"primaryKey;column:order_id"`
	MatchOrderID string `gorm:"column:match_order_id;index"`
	MpcShareJSON string `gorm:"column:mpc_share_json"`
}

// TableName returns the SQL table name used by GORM for CompareSubmissionScheme rows.
func (CompareSubmissionScheme) TableName() string {
	return "compare_submissions"
}

// ────────────────────── Settle Submission SQL Model ──────────────────────

// SettleSubmissionScheme stores a single party's pending ZK settle leg
// until the counterparty submits theirs. Once both arrive, the chain
// verifies proofs, transfers cash, and marks both orders Done.
type SettleSubmissionScheme struct {
	OrderID      string `gorm:"primaryKey;column:order_id"`
	MatchOrderID string `gorm:"column:match_order_id;index"`
	LegJSON      string `gorm:"column:leg_json"`
}

// TableName returns the SQL table name used by GORM for SettleSubmissionScheme rows.
func (SettleSubmissionScheme) TableName() string {
	return "settle_submissions"
}

// ────────────────────── Settle Address Exchange SQL Model ──────────────────────

// SettleAddrScheme stores the QUIC address a party registers for the MPC
// settle handshake. Both parties register independently; each can then query
// the counterparty's address.
// NOTE: This on-chain address exchange is temporary. In production, peer
// addresses will be exchanged via Tor or similar anonymous overlay network.
type SettleAddrScheme struct {
	OrderID      string `gorm:"primaryKey;column:order_id"`
	MatchOrderID string `gorm:"column:match_order_id;index"`
	Addr         string `gorm:"column:addr;not null"`
}

// TableName returns the SQL table name used by GORM for SettleAddrScheme rows.
func (SettleAddrScheme) TableName() string {
	return "settle_addrs"
}

// ────────────────────── DB Initialization ──────────────────────

// InitOrderDB opens a SQLite database and auto-migrates the orders and
// settle_submissions tables.
func InitOrderDB(dsn string) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		panic(fmt.Sprintf("failed to open orders database: %v", err))
	}
	if err := db.AutoMigrate(&OrderScheme{}, &CompareSubmissionScheme{}, &SettleSubmissionScheme{}, &SettleAddrScheme{}); err != nil {
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
// Every condition is applied via parameterized placeholders to prevent SQL injection.
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

// orderToScheme flattens a domain Order into its SQL row representation.
// Slice fields are JSON-encoded; *big.Int Price becomes its base-10 string form
// (empty string when nil).
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
	feeJSON := "[]"
	if len(o.HandlingFee) > 0 {
		if b, err := json.Marshal(o.HandlingFee); err == nil {
			feeJSON = string(b)
		}
	}
	isSmaller := 0
	if o.IsSmaller {
		isSmaller = 1
	}
	return &OrderScheme{
		ID:           string(o.ID),
		Type:         int(o.Type),
		Token1:       string(o.Subject.Token1),
		Token2:       string(o.Subject.Token2),
		Price:        priceStr,
		Amount:       string(o.Amount),
		Pubkey:       o.Pubkey,
		InputCashIDs: cashIDsJSON,
		HandlingFee:  feeJSON,
		BlockHeight:  o.BlockHeight,
		Status:       int(o.Status),
		MatchOrder: string(o.MatchOrder),
		IsSmaller:  isSmaller,
	}
}

// schemeToOrder rebuilds a domain Order from a SQL row, parsing the JSON-encoded
// slice fields and the base-10 string price. Malformed JSON yields a nil/empty
// slice rather than an error — rows are written by orderToScheme so corruption
// would indicate a schema bug.
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
	var fees []string
	if s.HandlingFee != "" {
		_ = json.Unmarshal([]byte(s.HandlingFee), &fees)
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
		Pubkey:       s.Pubkey,
		InputCashIDs: cashIDs,
		HandlingFee:  fees,
		BlockHeight:  s.BlockHeight,
		MatchOrder:   OrderID(s.MatchOrder),
		Status:    OrderStat(s.Status),
		IsSmaller: s.IsSmaller == 1,
	}
}

// schemesToOrders maps a slice of SQL rows to domain Orders.
func schemesToOrders(rows []OrderScheme) []*Order {
	orders := make([]*Order, 0, len(rows))
	for i := range rows {
		orders = append(orders, schemeToOrder(&rows[i]))
	}
	return orders
}

// ────────────────────── Order Comparison Update ──────────────────────

// UpdateOrderComparison sets the IsSmaller field of an order.
func (ot *OrderBook) UpdateOrderComparison(id OrderID, isSmaller bool) error {
	isSm := 0
	if isSmaller {
		isSm = 1
	}
	return ot.db.Model(&OrderScheme{}).Where("id = ?", string(id)).
		Update("is_smaller", isSm).Error
}

// ────────────────────── Compare Submission CRUD ──────────────────────

// SaveCompareSubmission inserts a pending compare submission row.
func (ot *OrderBook) SaveCompareSubmission(sub *CompareSubmissionScheme) error {
	return ot.db.Create(sub).Error
}

// GetCompareSubmission retrieves a pending compare submission by order ID.
// Returns nil, gorm.ErrRecordNotFound if not found.
func (ot *OrderBook) GetCompareSubmission(orderID OrderID) (*CompareSubmissionScheme, error) {
	var row CompareSubmissionScheme
	err := ot.db.First(&row, "order_id = ?", string(orderID)).Error
	if err != nil {
		return nil, err
	}
	return &row, nil
}

// DeleteCompareSubmission removes a pending compare submission by order ID.
func (ot *OrderBook) DeleteCompareSubmission(orderID OrderID) error {
	return ot.db.Where("order_id = ?", string(orderID)).Delete(&CompareSubmissionScheme{}).Error
}

// ────────────────────── Settle Submission CRUD ──────────────────────

// SaveSettleSubmission inserts a pending settle submission row.
func (ot *OrderBook) SaveSettleSubmission(sub *SettleSubmissionScheme) error {
	return ot.db.Create(sub).Error
}

// GetSettleSubmission retrieves a pending settle submission by order ID.
// Returns nil, gorm.ErrRecordNotFound if not found.
func (ot *OrderBook) GetSettleSubmission(orderID OrderID) (*SettleSubmissionScheme, error) {
	var row SettleSubmissionScheme
	err := ot.db.First(&row, "order_id = ?", string(orderID)).Error
	if err != nil {
		return nil, err
	}
	return &row, nil
}

// DeleteSettleSubmission removes a pending settle submission by order ID.
func (ot *OrderBook) DeleteSettleSubmission(orderID OrderID) error {
	return ot.db.Where("order_id = ?", string(orderID)).Delete(&SettleSubmissionScheme{}).Error
}

// ────────────────────── Settle Address CRUD ──────────────────────

// UpsertSettleAddr inserts or updates a settle address entry.
func (ot *OrderBook) UpsertSettleAddr(entry *SettleAddrScheme) error {
	return ot.db.Save(entry).Error
}

// GetSettleAddr retrieves a settle address entry by order ID.
// Returns nil, gorm.ErrRecordNotFound if not found.
func (ot *OrderBook) GetSettleAddr(orderID OrderID) (*SettleAddrScheme, error) {
	var row SettleAddrScheme
	err := ot.db.First(&row, "order_id = ?", string(orderID)).Error
	if err != nil {
		return nil, err
	}
	return &row, nil
}

// DeleteSettleAddr removes a settle address entry by order ID.
func (ot *OrderBook) DeleteSettleAddr(orderID OrderID) error {
	return ot.db.Where("order_id = ?", string(orderID)).Delete(&SettleAddrScheme{}).Error
}
