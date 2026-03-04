package core

import (
	"fmt"
	"math/big"

	"gorm.io/gorm"

	"github.com/yu-org/yu/core/context"
	"github.com/yu-org/yu/core/tripod"
)

// ────────────────────── Tripod ──────────────────────

type OrderTri struct {
	*tripod.Tripod
	db *gorm.DB
}

func NewOrderTri() *OrderTri {
	tri := tripod.NewTripodWithName("order")
	ot := &OrderTri{Tripod: tri, db: InitOrderDB("orders.db")}
	ot.SetWritings(ot.SendOrder, ot.SettleOrder)
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
func (ot *OrderTri) SendOrder(ctx *context.WriteContext) error {
	ctx.SetLei(100)

	req := new(SendOrderRequest)
	if err := ctx.BindJson(req); err != nil {
		return err
	}

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

	// Insert into SQL
	if err := ot.db.Create(orderToScheme(order)).Error; err != nil {
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
func (ot *OrderTri) SettleOrder(ctx *context.WriteContext) error {
	ctx.SetLei(100)

	req := new(SettleOrderRequest)
	if err := ctx.BindJson(req); err != nil {
		return err
	}

	if err := Validator.Struct(req); err != nil {
		return err
	}

	for _, id := range req.OrderIDs {
		var row OrderScheme
		if err := ot.db.First(&row, "id = ?", string(id)).Error; err != nil {
			return fmt.Errorf("order %s not found: %w", id, err)
		}
		if OrderStat(row.Status) != Matched {
			return fmt.Errorf("order %s is not in Matched status, current: %s", id, OrderStat(row.Status).String())
		}
		if err := ot.db.Model(&OrderScheme{}).Where("id = ?", string(id)).Update("status", int(Done)).Error; err != nil {
			return fmt.Errorf("failed to settle order %s: %w", id, err)
		}
	}

	ctx.EmitStringEvent("orders settled: %d orders", len(req.OrderIDs))
	return nil
}

// ────────────────────── Matching Logic ──────────────────────

// matchOrder finds a counterparty for the incoming order.
//
//	Buy  → looks for pending Sell orders where sell price ≤ buy price (picks lowest sell)
//	Sell → looks for pending Buy  orders where buy  price ≥ sell price (picks highest buy)
//
// If matched, both orders' Status is set to Matched via SQL UPDATE.
func (ot *OrderTri) matchOrder(order *Order) (*Order, error) {
	if order.Price == nil {
		return nil, nil // cannot match without a price
	}

	// Determine counter side
	counterType := Sell
	if order.Type == Sell {
		counterType = Buy
	}

	// Query pending orders of the opposite side on the same pair (with a price)
	var rows []OrderScheme
	err := ot.db.Where(
		"status = ? AND type = ? AND token1 = ? AND token2 = ? AND price != ''",
		int(Pending), int(counterType),
		string(order.Subject.Token1), string(order.Subject.Token2),
	).Find(&rows).Error
	if err != nil {
		return nil, err
	}

	var bestMatch *Order
	for _, r := range rows {
		candidate := schemeToOrder(&r)
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

	if err := ot.db.Model(&OrderScheme{}).Where("id = ?", string(order.ID)).Update("status", int(Matched)).Error; err != nil {
		return nil, err
	}
	if err := ot.db.Model(&OrderScheme{}).Where("id = ?", string(bestMatch.ID)).Update("status", int(Matched)).Error; err != nil {
		return nil, err
	}

	return bestMatch, nil
}
