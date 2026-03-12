package core

import (
	"fmt"
	"math/big"
	"net/http"

	"gorm.io/gorm"

	"github.com/yu-org/yu/core/context"
	"github.com/yu-org/yu/core/tripod"
)

// ────────────────────── Tripod ──────────────────────

type OrderBook struct {
	*tripod.Tripod
	Account *Account `tripod:"account"`
	db      *gorm.DB
}

func NewOrderBook() *OrderBook {
	tri := tripod.NewTripodWithName("orderbook")
	ot := &OrderBook{Tripod: tri, db: InitOrderDB("orders.db")}
	ot.SetWritings(ot.SendOrder, ot.SettleOrder)
	ot.SetReadings(ot.QueryOrders)
	return ot
}

// ────────────────────── Writing: SendOrder ──────────────────────

type SendOrderRequest struct {
	ID      OrderID    `json:"id"      validate:"required"`
	Type    TradeType  `json:"type"    validate:"oneof=0 1"`
	Subject TradePair  `json:"subject"`
	Price   *big.Int   `json:"price,omitempty"`
	Amount  CipherText `json:"amount"  validate:"required"`
}

// SendOrder creates a new order, stores it via SQL, and attempts to match it.
func (ot *OrderBook) SendOrder(ctx *context.WriteContext) error {
	ctx.SetLei(100)

	req := new(SendOrderRequest)
	if err := ctx.BindJson(req); err != nil {
		return err
	}

	if err := Validator.Struct(req); err != nil {
		return err
	}

	// Validate that the client-submitted ID is the correct hash of the order content.
	if expectedID := ComputeOrderID(req.Type, req.Subject, req.Price, req.Amount); req.ID != expectedID {
		return fmt.Errorf("order ID mismatch: got %s, expected %s", req.ID, expectedID)
	}

	order := &Order{
		ID:      req.ID,
		Type:    req.Type,
		Subject: req.Subject,
		Price:   req.Price,
		Amount:  req.Amount,
		Status:  Pending,
	}

	if err := ot.InsertOrder(order); err != nil {
		return fmt.Errorf("failed to insert order: %w", err)
	}

	ctx.EmitStringEvent("order created: %s %s %s price=%s",
		string(req.ID), req.Type.String(), req.Subject.String(), order.Price.String())

	// Attempt to match
	matched, err := ot.matchOrder(order)
	if err != nil {
		return fmt.Errorf("failed to match order: %w", err)
	}

	if matched != nil {
		ctx.EmitStringEvent("order matched: %s <-> %s", order.ID, matched.ID)
	}

	return nil
}

// ────────────────────── Writing: SettleOrder ──────────────────────

type SettleOrderRequest struct {
	OrderIDs []OrderID `json:"order_ids" validate:"required,min=1"`
}

// SettleOrder transitions matched orders to Done status.
func (ot *OrderBook) SettleOrder(ctx *context.WriteContext) error {
	ctx.SetLei(100)

	req := new(SettleOrderRequest)
	if err := ctx.BindJson(req); err != nil {
		return err
	}

	if err := Validator.Struct(req); err != nil {
		return err
	}

	for _, id := range req.OrderIDs {
		order, err := ot.GetOrder(id)
		if err != nil {
			return fmt.Errorf("order %s not found: %w", id, err)
		}
		if order.Status != Matched {
			return fmt.Errorf("order %s is not in Matched status, current: %s", id, order.Status.String())
		}

		// TODO: verify zk_proof of order settlement.

		if err := ot.UpdateOrderStatus(id, Done); err != nil {
			return fmt.Errorf("failed to settle order %s: %w", id, err)
		}

		// TODO: update account balances after settlement.
		// Requires Order to carry an owner address field so the Account tripod
		// can credit the buyer with purchased tokens and the seller with payment.
	}

	ctx.EmitStringEvent("orders settled: %d orders", len(req.OrderIDs))
	return nil
}

// ────────────────────── Reading: QueryOrders ──────────────────────

// QueryOrdersRequest defines optional filter criteria for querying orders.
// All fields are pointers — nil means "don't filter by this field".
// Limit and Offset provide pagination; Limit=0 means no limit.
type QueryOrdersRequest struct {
	ID     *OrderID   `json:"id,omitempty"`
	Type   *TradeType `json:"type,omitempty"`
	Token1 *TokenID   `json:"token1,omitempty"`
	Token2 *TokenID   `json:"token2,omitempty"`
	Status *OrderStat `json:"status,omitempty"`
	Limit  int        `json:"limit,omitempty"`
	Offset int        `json:"offset,omitempty"`
}

// QueryOrders returns orders matching the given filter criteria with pagination.
func (ot *OrderBook) QueryOrders(ctx *context.ReadContext) {
	req := new(QueryOrdersRequest)
	if err := ctx.BindJson(req); err != nil {
		ctx.Json(http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	filter := OrderFilter{
		ID:     req.ID,
		Type:   req.Type,
		Token1: req.Token1,
		Token2: req.Token2,
		Status: req.Status,
		Limit:  req.Limit,
		Offset: req.Offset,
	}

	orders, err := ot.FindOrdersByFilter(filter)
	if err != nil {
		ctx.Json(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	ctx.JsonOk(orders)
}

// ────────────────────── Matching Logic ──────────────────────

// matchOrder finds a counterparty for the incoming order.
//
//	Buy  → looks for pending Sell orders where sell price ≤ buy price (picks lowest sell)
//	Sell → looks for pending Buy  orders where buy  price ≥ sell price (picks highest buy)
//
// If matched, both orders' Status is set to Matched via SQL UPDATE.
func (ot *OrderBook) matchOrder(order *Order) (*Order, error) {
	if order.Price == nil {
		return nil, nil // cannot match without a price
	}

	// Determine counter side
	counterType := Sell
	if order.Type == Sell {
		counterType = Buy
	}

	candidates, err := ot.FindPendingCounterOrders(order.Subject, counterType)
	if err != nil {
		return nil, err
	}

	var bestMatch *Order
	for _, candidate := range candidates {
		if candidate.Price == nil {
			continue
		}

		// Price compatibility
		if order.Type == Buy && candidate.Price.Cmp(order.Price) > 0 {
			continue // sell price > buy price → incompatible
		}
		if order.Type == Sell && candidate.Price.Cmp(order.Price) < 0 {
			continue // buy price < sell price → incompatible
		}

		// Best price selection
		if bestMatch == nil {
			bestMatch = candidate
		} else if order.Type == Buy && candidate.Price.Cmp(bestMatch.Price) < 0 {
			bestMatch = candidate // lower sell price is better for buyer
		} else if order.Type == Sell && candidate.Price.Cmp(bestMatch.Price) > 0 {
			bestMatch = candidate // higher buy price is better for seller
		}
	}

	if bestMatch == nil {
		return nil, nil
	}

	// Update both orders to Matched
	order.Status = Matched
	bestMatch.Status = Matched

	if err := ot.UpdateOrderStatus(order.ID, Matched); err != nil {
		return nil, err
	}
	if err := ot.UpdateOrderStatus(bestMatch.ID, Matched); err != nil {
		return nil, err
	}

	return bestMatch, nil
}
