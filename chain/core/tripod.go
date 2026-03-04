package core

import (
	"encoding/json"
	"fmt"
	"math/big"

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
	ot.Set([]byte(req.ID), orderBytes)

	ctx.EmitStringEvent("order created: %s %s %s price=%s",
		string(req.ID), req.Type.String(), req.Subject.String(), req.Price.String())
	return nil
}
