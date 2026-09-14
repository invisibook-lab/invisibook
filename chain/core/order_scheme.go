package core

import (
	"encoding/json"
	"fmt"
	"github.com/invisibook-lab/invisibook/account"
	"github.com/invisibook-lab/invisibook/store"
	"math/big"

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
	Pubkey       string `gorm:"column:pubkey;index"`   // owner's compressed secp256k1 pubkey (66-char hex)
	InputCashIDs string `gorm:"column:input_cash_ids"` // JSON array of cash IDs
	HandlingFee  string `gorm:"column:handling_fee"`   // JSON array of fee strings
	BlockHeight  uint32 `gorm:"column:block_height"`
	Status       int    `gorm:"column:status;index"`
	MatchOrder   string `gorm:"column:match_order"`
	IsSmaller    int    `gorm:"column:is_smaller;default:0"` // 0=false, 1=true
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

// MigrateOrderTables creates the orderbook's tables on the shared chain
// database.
func MigrateOrderTables(db *gorm.DB) error {
	err := db.AutoMigrate(&OrderScheme{}, &CompareSubmissionScheme{}, &SettleSubmissionScheme{}, &SettleAddrScheme{})
	if err != nil {
		return fmt.Errorf("migrating orderbook tables: %w", err)
	}
	return nil
}

// ────────────────────── CRUD Operations ──────────────────────

// InsertOrder inserts a new order into the database.
func (ot *OrderBook) InsertOrder(order *Order) error {
	row := orderToScheme(order)
	return ot.pending.Stage(OrdersTable, row.ID, row, false)
}

// GetOrder retrieves a single order by ID.
// An unsettled block's view wins: if any block since the last settled height
// touched this order, that is its current state.
func (ot *OrderBook) GetOrder(id OrderID) (*Order, error) {
	var staged OrderScheme
	found, deleted, err := ot.pending.Latest(OrdersTable, string(id), &staged)
	if err != nil {
		return nil, err
	}
	if found {
		if deleted {
			return nil, gorm.ErrRecordNotFound
		}
		return schemeToOrder(&staged), nil
	}

	var row OrderScheme
	if err := ot.db.First(&row, "id = ?", string(id)).Error; err != nil {
		return nil, err
	}
	return schemeToOrder(&row), nil
}

// UpdateOrderStatus updates the status of an order by ID.
func (ot *OrderBook) UpdateOrderStatus(id OrderID, status OrderStat) error {
	return ot.restageOrder(id, func(row *OrderScheme) { row.Status = int(status) })
}

// UpdateOrderMatchOrder sets the match_order field of an order.
func (ot *OrderBook) UpdateOrderMatchOrder(id OrderID, matchID OrderID) error {
	return ot.restageOrder(id, func(row *OrderScheme) { row.MatchOrder = string(matchID) })
}

// FindPendingCounterOrders queries pending orders of the given type on the
// specified pair that have a non-empty price. All parameters are passed via
// GORM's parameterized placeholders to prevent SQL injection.
//
// The settled rows are read without a status condition on purpose: status is
// exactly what an unsettled block changes, so filtering it in SQL would keep
// an order a later block has already matched, and drop one it has just
// created. The filter is applied after the two views are merged.
func (ot *OrderBook) FindPendingCounterOrders(pair TradePair, counterType TradeType) ([]*Order, error) {
	var rows []OrderScheme
	err := ot.db.Where(
		"type = ? AND token1 = ? AND token2 = ? AND price != ''",
		int(counterType), string(pair.Token1), string(pair.Token2),
	).Find(&rows).Error
	if err != nil {
		return nil, err
	}

	merged, err := ot.overlayOrders(rows)
	if err != nil {
		return nil, err
	}
	return schemesToOrders(filterOrders(merged, func(row OrderScheme) bool {
		return row.Status == int(Pending) &&
			row.Type == int(counterType) &&
			row.Token1 == string(pair.Token1) &&
			row.Token2 == string(pair.Token2) &&
			row.Price != ""
	})), nil
}

// FindAllOrders returns every order in the database.
func (ot *OrderBook) FindAllOrders() ([]*Order, error) {
	var rows []OrderScheme
	if err := ot.db.Find(&rows).Error; err != nil {
		return nil, err
	}
	merged, err := ot.overlayOrders(rows)
	if err != nil {
		return nil, err
	}
	return schemesToOrders(merged), nil
}

// restageOrder reads an order through the staged view, applies `mutate`, and
// stages the result. Reading through the staged view first means the new row
// carries the order's current state, whether that came from the settled table
// or from an earlier change in the same block.
func (ot *OrderBook) restageOrder(id OrderID, mutate func(*OrderScheme)) error {
	var row OrderScheme
	found, deleted, err := ot.pending.Latest(OrdersTable, string(id), &row)
	if err != nil {
		return err
	}
	if !found || deleted {
		if err := ot.db.First(&row, "id = ?", string(id)).Error; err != nil {
			return fmt.Errorf("order %s not found: %w", id, err)
		}
	}
	mutate(&row)
	return ot.pending.Stage(OrdersTable, row.ID, row, false)
}

// overlayOrders merges the staged order view over rows read from the settled
// table.
func (ot *OrderBook) overlayOrders(rows []OrderScheme) ([]OrderScheme, error) {
	staged, err := store.LatestAll[OrderScheme](ot.pending, OrdersTable)
	if err != nil {
		return nil, err
	}
	return store.Overlay(rows, staged, func(row OrderScheme) string { return row.ID }), nil
}

// filterOrders keeps the rows `keep` accepts.
func filterOrders(rows []OrderScheme, keep func(OrderScheme) bool) []OrderScheme {
	out := make([]OrderScheme, 0, len(rows))
	for i := range rows {
		if keep(rows[i]) {
			out = append(out, rows[i])
		}
	}
	return out
}

// OrderFilter holds optional filter criteria for querying orders.
// All fields are pointers so that nil means "don't filter by this field".
// Limit=0 means no limit; Offset=0 means start from beginning.
type OrderFilter struct {
	ID     *OrderID
	Type   *TradeType
	Token1 *account.TokenID
	Token2 *account.TokenID
	Status *OrderStat
	Limit  int
	Offset int
}

// FindOrdersByFilter queries orders matching the given filter criteria with
// pagination. Every condition is applied via parameterized placeholders to
// prevent SQL injection.
//
// Only the immutable fields narrow the SQL query. Status is what an unsettled
// block changes, and pagination over the settled rows alone would page through
// the wrong set, so both are applied after the staged view is merged in.
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

	var rows []OrderScheme
	if err := query.Find(&rows).Error; err != nil {
		return nil, err
	}

	merged, err := ot.overlayOrders(rows)
	if err != nil {
		return nil, err
	}

	merged = filterOrders(merged, func(row OrderScheme) bool {
		if f.ID != nil && row.ID != string(*f.ID) {
			return false
		}
		if f.Type != nil && row.Type != int(*f.Type) {
			return false
		}
		if f.Token1 != nil && row.Token1 != string(*f.Token1) {
			return false
		}
		if f.Token2 != nil && row.Token2 != string(*f.Token2) {
			return false
		}
		if f.Status != nil && row.Status != int(*f.Status) {
			return false
		}
		return true
	})

	return schemesToOrders(paginate(merged, f.Offset, f.Limit)), nil
}

// paginate applies an offset and a limit to already-merged rows.
// `offset` past the end yields nothing; `limit` of 0 means no limit.
func paginate(rows []OrderScheme, offset, limit int) []OrderScheme {
	if offset > 0 {
		if offset >= len(rows) {
			return nil
		}
		rows = rows[offset:]
	}
	if limit > 0 && limit < len(rows) {
		rows = rows[:limit]
	}
	return rows
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
		MatchOrder:   string(o.MatchOrder),
		IsSmaller:    isSmaller,
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
			Token1: account.TokenID(s.Token1),
			Token2: account.TokenID(s.Token2),
		},
		Price:        price,
		Amount:       account.CipherText(s.Amount),
		Pubkey:       s.Pubkey,
		InputCashIDs: cashIDs,
		HandlingFee:  fees,
		BlockHeight:  s.BlockHeight,
		MatchOrder:   OrderID(s.MatchOrder),
		Status:       OrderStat(s.Status),
		IsSmaller:    s.IsSmaller == 1,
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
	return ot.restageOrder(id, func(row *OrderScheme) { row.IsSmaller = isSm })
}

// UpdateOrderAmount replaces an order's hidden amount commitment (64-char
// hex). Used by co-zk settlement when the surviving larger order stays on the
// book with its remainder commitment.
func (ot *OrderBook) UpdateOrderAmount(id OrderID, amount account.CipherText) error {
	return ot.restageOrder(id, func(row *OrderScheme) { row.Amount = string(amount) })
}

// UpdateOrderInputCashIDs replaces an order's locked input cash IDs.
// `cashIDs` must be non-empty for an order that stays on the book.
func (ot *OrderBook) UpdateOrderInputCashIDs(id OrderID, cashIDs []string) error {
	b, err := json.Marshal(cashIDs)
	if err != nil {
		return err
	}
	return ot.restageOrder(id, func(row *OrderScheme) { row.InputCashIDs = string(b) })
}

// ────────────────────── Compare Submission CRUD ──────────────────────

// SaveCompareSubmission inserts a pending compare submission row.
func (ot *OrderBook) SaveCompareSubmission(sub *CompareSubmissionScheme) error {
	return ot.pending.Stage(CompareSubmissionsTable, sub.OrderID, sub, false)
}

// GetCompareSubmission retrieves a pending compare submission by order ID.
// Returns nil, gorm.ErrRecordNotFound if not found.
func (ot *OrderBook) GetCompareSubmission(orderID OrderID) (*CompareSubmissionScheme, error) {
	var staged CompareSubmissionScheme
	found, deleted, err := ot.pending.Latest(CompareSubmissionsTable, string(orderID), &staged)
	if err != nil {
		return nil, err
	}
	if found {
		if deleted {
			return nil, gorm.ErrRecordNotFound
		}
		return &staged, nil
	}

	var row CompareSubmissionScheme
	if err := ot.db.First(&row, "order_id = ?", string(orderID)).Error; err != nil {
		return nil, err
	}
	return &row, nil
}

// DeleteCompareSubmission removes a pending compare submission by order ID.
// The row is not removed yet: a tombstone is staged, so readers stop seeing it
// while the settled row stays put until L1 settles the height. Dropping the
// tombstone brings the row back, which is what makes the deletion undoable.
func (ot *OrderBook) DeleteCompareSubmission(orderID OrderID) error {
	return ot.pending.Stage(CompareSubmissionsTable, string(orderID), nil, true)
}

// ────────────────────── Settle Submission CRUD ──────────────────────

// SaveSettleSubmission inserts a pending settle submission row.
func (ot *OrderBook) SaveSettleSubmission(sub *SettleSubmissionScheme) error {
	return ot.pending.Stage(SettleSubmissionsTable, sub.OrderID, sub, false)
}

// GetSettleSubmission retrieves a pending settle submission by order ID.
// Returns nil, gorm.ErrRecordNotFound if not found.
func (ot *OrderBook) GetSettleSubmission(orderID OrderID) (*SettleSubmissionScheme, error) {
	var staged SettleSubmissionScheme
	found, deleted, err := ot.pending.Latest(SettleSubmissionsTable, string(orderID), &staged)
	if err != nil {
		return nil, err
	}
	if found {
		if deleted {
			return nil, gorm.ErrRecordNotFound
		}
		return &staged, nil
	}

	var row SettleSubmissionScheme
	if err := ot.db.First(&row, "order_id = ?", string(orderID)).Error; err != nil {
		return nil, err
	}
	return &row, nil
}

// DeleteSettleSubmission removes a pending settle submission by order ID.
// The row is not removed yet: a tombstone is staged, so readers stop seeing it
// while the settled row stays put until L1 settles the height. Dropping the
// tombstone brings the row back, which is what makes the deletion undoable.
func (ot *OrderBook) DeleteSettleSubmission(orderID OrderID) error {
	return ot.pending.Stage(SettleSubmissionsTable, string(orderID), nil, true)
}

// ────────────────────── Settle Address CRUD ──────────────────────

// UpsertSettleAddr inserts or updates a settle address entry.
func (ot *OrderBook) UpsertSettleAddr(entry *SettleAddrScheme) error {
	return ot.pending.Stage(SettleAddrsTable, entry.OrderID, entry, false)
}

// GetSettleAddr retrieves a settle address entry by order ID.
// Returns nil, gorm.ErrRecordNotFound if not found.
func (ot *OrderBook) GetSettleAddr(orderID OrderID) (*SettleAddrScheme, error) {
	var staged SettleAddrScheme
	found, deleted, err := ot.pending.Latest(SettleAddrsTable, string(orderID), &staged)
	if err != nil {
		return nil, err
	}
	if found {
		if deleted {
			return nil, gorm.ErrRecordNotFound
		}
		return &staged, nil
	}

	var row SettleAddrScheme
	if err := ot.db.First(&row, "order_id = ?", string(orderID)).Error; err != nil {
		return nil, err
	}
	return &row, nil
}

// DeleteSettleAddr removes a settle address entry by order ID.
// Staged as a tombstone; see DeleteCompareSubmission.
func (ot *OrderBook) DeleteSettleAddr(orderID OrderID) error {
	return ot.pending.Stage(SettleAddrsTable, string(orderID), nil, true)
}
