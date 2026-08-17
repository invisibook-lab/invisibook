package core

import (
	"errors"
	"fmt"
	"math/big"

	"log"
	"os"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// ────────────────────── SQL Model ──────────────────────

// OrderScheme is the flat SQL model for the orders table.
type OrderScheme struct {
	ID               string `gorm:"primaryKey;column:id"`
	Type             int    `gorm:"column:type;index:idx_pair_type"`
	Token1           string `gorm:"column:token1;index:idx_pair_type"`
	Token2           string `gorm:"column:token2;index:idx_pair_type"`
	Price            string `gorm:"column:price"`
	Amount           string `gorm:"column:amount"` // cm_q
	Pubkey           string `gorm:"column:pubkey;index"`
	LockedCommitment string `gorm:"column:locked_commitment"`
	Fee              uint64 `gorm:"column:fee"`
	BlockHeight      uint32 `gorm:"column:block_height"`
	IntraBlockIndex  uint32 `gorm:"column:intra_block_index"`
	Status           int    `gorm:"column:status;index"`
	MatchOrder       string `gorm:"column:match_order"`
}

// TableName returns the SQL table name used by GORM for OrderScheme rows.
func (OrderScheme) TableName() string {
	return "orders"
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

// ────────────────────── Compare Result SQL Model ──────────────────────

// CompareResultScheme records the dual-signed, proof-verified comparison
// result of a matched pair (paper π_cmp phase). Keyed by the canonical
// A-side (the maker); `Cmp` is sign(q_A − q_B).
type CompareResultScheme struct {
	OrderAID string `gorm:"primaryKey;column:order_a_id"`
	OrderBID string `gorm:"column:order_b_id;index"`
	Cmp      int    `gorm:"column:cmp"`
	Height   uint64 `gorm:"column:height"`
}

// TableName returns the SQL table name for CompareResultScheme rows.
func (CompareResultScheme) TableName() string {
	return "compare_results"
}

// ────────────────────── DB Initialization ──────────────────────

// InitOrderDB opens a SQLite database and auto-migrates the order-side
// tables. `logLevel` controls GORM SQL logging verbosity.
func InitOrderDB(dsn string, logLevel logger.LogLevel) *gorm.DB {
	gormLogger := logger.New(
		log.New(os.Stdout, "\n", log.LstdFlags),
		logger.Config{
			SlowThreshold: 200 * time.Millisecond,
			LogLevel:      logLevel,
		},
	)
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{Logger: gormLogger})
	if err != nil {
		panic(fmt.Sprintf("failed to open orders database: %v", err))
	}
	if err := db.AutoMigrate(&OrderScheme{}, &SettleAddrScheme{}, &CompareResultScheme{},
		&FeeCounterScheme{}, &SettlementJournalScheme{}); err != nil {
		panic(fmt.Sprintf("failed to migrate orders table: %v", err))
	}
	return db
}

// ────────────────────── Settlement Journal SQL Model ──────────────────────

// Journal states: a settlement is PENDING from the moment its legs verify
// until the order-side updates commit, then DONE.
const (
	SettlementPending = 0
	SettlementDone    = 1
)

// SettlementJournalScheme is the durable intent record of one atomic
// settlement (crash consistency). It is written to orders.db BEFORE the
// payout notes are minted in accounts.db and carries everything the
// order-side updates need, so a crash between the two databases can be
// completed idempotently — by a resubmission of the same SettlePair or by
// the startup recovery (`recoverPendingSettlements`). Rows are keyed by
// the settlement id (`orderA:orderB` — a pair settles at most once: the
// smaller side ends Done and can never be Matched again).
type SettlementJournalScheme struct {
	SettlementID   string `gorm:"primaryKey;column:settlement_id"`
	OrderAID       string `gorm:"column:order_a_id;not null"`
	OrderBID       string `gorm:"column:order_b_id;not null"`
	CmNoteA        string `gorm:"column:cm_note_a;not null"`
	CmNoteB        string `gorm:"column:cm_note_b;not null"`
	ALarge         bool   `gorm:"column:a_large"`
	BLarge         bool   `gorm:"column:b_large"`
	CmQResidualA   string `gorm:"column:cm_q_residual_a"`
	CmLockedResidA string `gorm:"column:cm_locked_residual_a"`
	CmQResidualB   string `gorm:"column:cm_q_residual_b"`
	CmLockedResidB string `gorm:"column:cm_locked_residual_b"`
	State          int    `gorm:"column:state;index"`
	Height         uint64 `gorm:"column:height"`
}

// TableName returns the SQL table name for SettlementJournalScheme rows.
func (SettlementJournalScheme) TableName() string {
	return "settlement_journal"
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
	return &OrderScheme{
		ID:               string(o.ID),
		Type:             int(o.Type),
		Token1:           string(o.Subject.Token1),
		Token2:           string(o.Subject.Token2),
		Price:            priceStr,
		Amount:           string(o.Amount),
		Pubkey:           o.Pubkey,
		LockedCommitment: o.LockedCommitment,
		Fee:              o.Fee,
		BlockHeight:      o.BlockHeight,
		IntraBlockIndex:  o.IntraBlockIndex,
		Status:           int(o.Status),
		MatchOrder:       string(o.MatchOrder),
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
	return &Order{
		ID:   OrderID(s.ID),
		Type: TradeType(s.Type),
		Subject: TradePair{
			Token1: TokenID(s.Token1),
			Token2: TokenID(s.Token2),
		},
		Price:            price,
		Amount:           CipherText(s.Amount),
		Pubkey:           s.Pubkey,
		LockedCommitment: s.LockedCommitment,
		Fee:              s.Fee,
		BlockHeight:      s.BlockHeight,
		IntraBlockIndex:  s.IntraBlockIndex,
		MatchOrder:       OrderID(s.MatchOrder),
		Status:           OrderStat(s.Status),
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

// UpdateOrderAmount replaces an order's hidden amount commitment (64-char
// hex). Used by co-zk settlement when the surviving larger order stays on the
// book with its remainder commitment.
func (ot *OrderBook) UpdateOrderAmount(id OrderID, amount CipherText) error {
	return ot.db.Model(&OrderScheme{}).Where("id = ?", string(id)).
		Update("amount", string(amount)).Error
}

// UpdateOrderLockedCommitment replaces an order's collateral commitment
// (used by settlement when the surviving larger order relists its residual).
func (ot *OrderBook) UpdateOrderLockedCommitment(id OrderID, locked string) error {
	return ot.db.Model(&OrderScheme{}).Where("id = ?", string(id)).
		Update("locked_commitment", locked).Error
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

// ────────────────────── Compare Result CRUD ──────────────────────

// SaveCompareResult upserts the pair's comparison row (an identical
// re-submission is idempotent).
func (ot *OrderBook) SaveCompareResult(res *CompareResultScheme) error {
	return ot.db.Save(res).Error
}

// GetCompareResult looks the pair up in either orientation. Returns the row
// plus whether `myID` is the canonical A side (callers normalize Cmp with
// it). gorm.ErrRecordNotFound when no comparison was recorded.
func (ot *OrderBook) GetCompareResult(myID, matchID OrderID) (*CompareResultScheme, bool, error) {
	var row CompareResultScheme
	err := ot.db.First(&row, "order_a_id = ? AND order_b_id = ?", string(myID), string(matchID)).Error
	if err == nil {
		return &row, true, nil
	}
	err = ot.db.First(&row, "order_a_id = ? AND order_b_id = ?", string(matchID), string(myID)).Error
	if err != nil {
		return nil, false, err
	}
	return &row, false, nil
}

// DeleteCompareResult removes the pair's comparison row (both orientations).
func (ot *OrderBook) DeleteCompareResult(x, y OrderID) error {
	return ot.db.
		Where("(order_a_id = ? AND order_b_id = ?) OR (order_a_id = ? AND order_b_id = ?)",
			string(x), string(y), string(y), string(x)).
		Delete(&CompareResultScheme{}).Error
}

// ────────────────────── Settlement Journal CRUD ──────────────────────

// UpsertSettlementJournal inserts or replaces the journal row of one
// settlement. Called BEFORE the payout mint; a retry after a crash simply
// rewrites the same row.
func (ot *OrderBook) UpsertSettlementJournal(row *SettlementJournalScheme) error {
	return ot.db.Save(row).Error
}

// GetSettlementJournal returns the journal row of `settlementID`, or nil
// when this settlement never started.
func (ot *OrderBook) GetSettlementJournal(settlementID string) (*SettlementJournalScheme, error) {
	var row SettlementJournalScheme
	err := ot.db.First(&row, "settlement_id = ?", settlementID).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &row, nil
}

// PendingSettlementJournals returns every journal row still in the PENDING
// state (crash-recovery scan).
func (ot *OrderBook) PendingSettlementJournals() ([]SettlementJournalScheme, error) {
	var rows []SettlementJournalScheme
	if err := ot.db.Where("state = ?", SettlementPending).Find(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}
