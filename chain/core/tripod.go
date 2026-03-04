package core

import (
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"

	"github.com/yu-org/yu/core/context"
	"github.com/yu-org/yu/core/tripod"
)

type OrderTri struct {
	*tripod.Tripod
}

func NewOrderTri() *OrderTri {
	tri := tripod.NewTripodWithName("order")
	ot := &OrderTri{tri}
	ot.SetWritings(ot.SendOrder)
	ot.SetReadings(ot.QueryOrders, ot.AllOrders)
	return ot
}

// ────────────────────── Storage Keys ──────────────────────

const (
	orderPrefix = "order:"
	orderIDsKey = "order_ids"
)

// ────────────────────── Writing: SendOrder ──────────────────────

type SendOrderRequest struct {
	ID      OrderID    `json:"id"      validate:"required"`
	Type    TradeType  `json:"type"    validate:"oneof=0 1"`
	Subject TradePair  `json:"subject"`
	Price   *big.Int   `json:"price,omitempty"`
	Amount  CipherText `json:"amount"  validate:"required"`
}

// SendOrder creates a new order and stores it on chain.
// Request body: { "type": 0|1, "subject": {"token1":"ETH","token2":"USDT"}, "price": "3500", "amount": "0xcipher..." }
func (ot *OrderTri) SendOrder(ctx *context.WriteContext) error {
	ctx.SetLei(100)

	req := new(SendOrderRequest)
	err := ctx.BindJson(req)
	if err != nil {
		return err
	}

	// Validate struct tag constraints (required, oneof, etc.)
	if err := Validator.Struct(req); err != nil {
		return err
	}

	order := &Order{
		ID:      req.ID,
		Type:    req.Type,
		Subject: req.Subject,
		Price:   req.Price,
		Amount:  req.Amount,
		Status:  Pending,
	}

	// Store the order
	orderBytes, err := json.Marshal(order)
	if err != nil {
		return fmt.Errorf("failed to marshal order: %w", err)
	}
	ot.Set([]byte(orderPrefix+string(req.ID)), orderBytes)

	// Append order ID to the index
	ids, err := ot.getOrderIDs()
	if err != nil {
		return fmt.Errorf("failed to get order IDs: %w", err)
	}
	ids = append(ids, req.ID)
	idsBytes, err := json.Marshal(ids)
	if err != nil {
		return fmt.Errorf("failed to marshal order IDs: %w", err)
	}
	ot.Set([]byte(orderIDsKey), idsBytes)

	ctx.EmitStringEvent("order created: %s %s %s price=%s",
		string(req.ID), req.Type.String(), req.Subject.String(), req.Price.String())
	return nil
}

// getOrderIDs returns all stored order IDs from the on-chain index.
func (ot *OrderTri) getOrderIDs() ([]OrderID, error) {
	idsBytes, err := ot.Get([]byte(orderIDsKey))
	if err != nil || len(idsBytes) == 0 {
		return []OrderID{}, nil
	}
	var ids []OrderID
	if e := json.Unmarshal(idsBytes, &ids); e != nil {
		return nil, e
	}
	return ids, nil
}

// ────────────────────── Reading: QueryOrders ──────────────────────

type QueryOrdersRequest struct {
	Token1 TokenID    `json:"token1,omitempty"`
	Token2 TokenID    `json:"token2,omitempty"`
	Type   *TradeType `json:"type,omitempty"`
	Status *OrderStat `json:"status,omitempty"`
}

type OrdersResponse struct {
	Orders []*Order `json:"orders"`
}

// QueryOrders returns orders filtered by optional criteria.
// Request body: { "token1": "ETH", "token2": "USDT", "type": 0, "status": 0 }
// All fields are optional; omitted fields are not filtered.
func (ot *OrderTri) QueryOrders(ctx *context.ReadContext) {
	req := new(QueryOrdersRequest)
	err := ctx.BindJson(req)
	if err != nil {
		ctx.Err(http.StatusBadRequest, err)
		return
	}

	orders, err := ot.loadAllOrders()
	if err != nil {
		ctx.ErrOk(err)
		return
	}

	// Apply filters
	filtered := make([]*Order, 0)
	for _, order := range orders {
		if req.Token1 != "" && order.Subject.Token1 != req.Token1 {
			continue
		}
		if req.Token2 != "" && order.Subject.Token2 != req.Token2 {
			continue
		}
		if req.Type != nil && order.Type != *req.Type {
			continue
		}
		if req.Status != nil && order.Status != *req.Status {
			continue
		}
		filtered = append(filtered, order)
	}

	ctx.JsonOk(OrdersResponse{Orders: filtered})
}

// ────────────────────── Reading: AllOrders ──────────────────────

// AllOrders returns every order stored on chain without filtering.
func (ot *OrderTri) AllOrders(ctx *context.ReadContext) {
	orders, err := ot.loadAllOrders()
	if err != nil {
		ctx.ErrOk(err)
		return
	}
	ctx.JsonOk(OrdersResponse{Orders: orders})
}

// ────────────────────── Internal Helpers ──────────────────────

// loadAllOrders reads every order from on-chain state by iterating the ID index.
func (ot *OrderTri) loadAllOrders() ([]*Order, error) {
	ids, err := ot.getOrderIDs()
	if err != nil {
		return nil, err
	}

	orders := make([]*Order, 0, len(ids))
	for _, id := range ids {
		orderBytes, err := ot.Get([]byte(orderPrefix + string(id)))
		if err != nil {
			continue // skip unreadable entries
		}
		order := new(Order)
		if e := json.Unmarshal(orderBytes, order); e != nil {
			continue
		}
		orders = append(orders, order)
	}
	return orders, nil
}
