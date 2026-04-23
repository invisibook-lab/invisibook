package core

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/http"

	"gorm.io/gorm"

	"github.com/yu-org/yu/core/context"
	"github.com/yu-org/yu/core/tripod"
)

// ────────────────────── Events ──────────────────────

// OrderEvent is emitted as a JSON event after SendOrder succeeds.
// EventType is "created" when the order is stored, and "matched" when a
// counterparty is found (both the new order and the matched order are included).
type OrderEvent struct {
	EventType string `json:"event_type"`
	Order     *Order `json:"order"`
	Matched   *Order `json:"matched,omitempty"`
}

// ────────────────────── Tripod ──────────────────────

type OrderBook struct {
	*tripod.Tripod
	Account *Account `tripod:"account"`
	db      *gorm.DB
}

func NewOrderBook(cfg *OrderBookConfig) *OrderBook {
	tri := tripod.NewTripodWithName("orderbook")
	ot := &OrderBook{Tripod: tri, db: InitOrderDB(cfg.DBPath)}
	ot.SetWritings(ot.SendOrder, ot.SettleOrder)
	ot.SetReadings(ot.QueryOrders)
	return ot
}

// ────────────────────── Writing: SendOrder ──────────────────────

type SendOrderRequest struct {
	ID           OrderID    `json:"id"             validate:"required"`
	Type         TradeType  `json:"type"           validate:"oneof=0 1"`
	Subject      TradePair  `json:"subject"`
	Price        *big.Int   `json:"price,omitempty"`
	Amount       CipherText `json:"amount"         validate:"required"`
	Pubkey       string     `json:"pubkey"         validate:"required"` // sender's ed25519 pubkey (64-char hex)
	Signature    string     `json:"signature"      validate:"required"` // ed25519 sig over order ID bytes (128-char hex)
	InputCashIDs []string   `json:"input_cash_ids" validate:"required,min=1"`
	HandlingFee  []string   `json:"handling_fee"   validate:"required,min=1"` // must be plaintext.
}

// SendOrder creates a new order, locks the input Cash, stores it via SQL, and attempts to match it.
func (ot *OrderBook) SendOrder(ctx *context.WriteContext) error {
	ctx.SetLei(100)

	req := new(SendOrderRequest)
	if err := ctx.BindJson(req); err != nil {
		return err
	}

	if err := Validator.Struct(req); err != nil {
		return err
	}

	// Validate that the client-submitted ID is the correct hash of the input cash IDs.
	if expectedID := ComputeOrderID(req.InputCashIDs); req.ID != expectedID {
		return fmt.Errorf("order ID mismatch: got %s, expected %s", req.ID, expectedID)
	}

	// Verify the sender's ed25519 signature over the order ID bytes.
	pubkeyBytes, err := hex.DecodeString(req.Pubkey)
	if err != nil || len(pubkeyBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid pubkey: must be %d-byte ed25519 key as 64-char hex", ed25519.PublicKeySize)
	}
	sigBytes, err := hex.DecodeString(req.Signature)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature: must be %d-byte ed25519 sig as 128-char hex", ed25519.SignatureSize)
	}
	if !ed25519.Verify(pubkeyBytes, []byte(req.ID), sigBytes) {
		return fmt.Errorf("signature verification failed for order %s", req.ID)
	}

	// Determine expected token for the input Cash:
	// Buy(Token1/Token2) → paying with Token2
	// Sell(Token1/Token2) → selling Token1
	expectedToken := req.Subject.Token1
	if req.Type == Buy {
		expectedToken = req.Subject.Token2
	}

	// Validate each input Cash: exists, Active, pubkey matches, token matches
	for _, cashID := range req.InputCashIDs {
		cash, err := ot.Account.GetCash(cashID)
		if err != nil {
			return fmt.Errorf("input cash %s not found: %w", cashID, err)
		}
		if cash.Status != Active {
			return fmt.Errorf("input cash %s is not Active (current: %s)", cashID, cash.Status.String())
		}
		if cash.Pubkey != req.Pubkey {
			return fmt.Errorf("input cash %s pubkey mismatch: got %s, expected %s", cashID, cash.Pubkey, req.Pubkey)
		}
		if cash.Token != expectedToken {
			return fmt.Errorf("input cash %s token mismatch: got %s, expected %s", cashID, cash.Token, expectedToken)
		}
	}

	// Lock the input Cash
	if err := ot.Account.LockCash(req.InputCashIDs, string(req.ID)); err != nil {
		return fmt.Errorf("failed to lock cash: %w", err)
	}

	order := &Order{
		ID:           req.ID,
		Type:         req.Type,
		Subject:      req.Subject,
		Price:        req.Price,
		Amount:       req.Amount,
		Pubkey:       req.Pubkey,
		InputCashIDs: req.InputCashIDs,
		Status:       Pending,
	}

	if err := ot.InsertOrder(order); err != nil {
		return fmt.Errorf("failed to insert order: %w", err)
	}

	if err := ctx.EmitJsonEvent(&OrderEvent{EventType: "created", Order: order}); err != nil {
		return fmt.Errorf("failed to emit order created event: %w", err)
	}

	// Attempt to match
	matched, err := ot.matchOrder(order)
	if err != nil {
		return fmt.Errorf("failed to match order: %w", err)
	}

	if matched != nil {
		if err := ctx.EmitJsonEvent(&OrderEvent{EventType: "matched", Order: order, Matched: matched}); err != nil {
			return fmt.Errorf("failed to emit order matched event: %w", err)
		}
	}

	return nil
}

// ────────────────────── Writing: SettleOrder ──────────────────────

// CashOutput describes a new Cash to be minted as settlement output.
type CashOutput struct {
	Pubkey string     `json:"pubkey" validate:"required"` // recipient's ed25519 pubkey (64-char hex)
	Token  TokenID    `json:"token"  validate:"required"`
	Amount CipherText `json:"amount" validate:"required"`
}

type SettleOrderRequest struct {
	OrderIDs []OrderID    `json:"order_ids" validate:"required,len=2"` // matched pair
	Outputs  []CashOutput `json:"outputs"   validate:"required,min=1"` // output Cash
	ZkProof  string       `json:"zk_proof"  validate:"required"`
}

// SettleOrder spends the locked Cash of a matched pair, mints output Cash, and marks orders Done.
func (ot *OrderBook) SettleOrder(ctx *context.WriteContext) error {
	ctx.SetLei(100)

	req := new(SettleOrderRequest)
	if err := ctx.BindJson(req); err != nil {
		return err
	}

	if err := Validator.Struct(req); err != nil {
		return err
	}

	// Retrieve both orders and validate they are a matched pair
	order0, err := ot.GetOrder(req.OrderIDs[0])
	if err != nil {
		return fmt.Errorf("order %s not found: %w", req.OrderIDs[0], err)
	}
	order1, err := ot.GetOrder(req.OrderIDs[1])
	if err != nil {
		return fmt.Errorf("order %s not found: %w", req.OrderIDs[1], err)
	}

	if order0.Status != Matched {
		return fmt.Errorf("order %s is not Matched (current: %s)", order0.ID, order0.Status.String())
	}
	if order1.Status != Matched {
		return fmt.Errorf("order %s is not Matched (current: %s)", order1.ID, order1.Status.String())
	}
	if order0.MatchOrder != order1.ID || order1.MatchOrder != order0.ID {
		return fmt.Errorf("orders %s and %s are not matched with each other", order0.ID, order1.ID)
	}

	// TODO: verify ZkProof — proves that sum(inputs) == sum(outputs)

	// Spend locked Cash from both orders
	settleTxID := generateCashID()
	if len(order0.InputCashIDs) > 0 {
		if err := ot.Account.SpendCash(order0.InputCashIDs, settleTxID); err != nil {
			return fmt.Errorf("failed to spend cash for order %s: %w", order0.ID, err)
		}
	}
	if len(order1.InputCashIDs) > 0 {
		if err := ot.Account.SpendCash(order1.InputCashIDs, settleTxID); err != nil {
			return fmt.Errorf("failed to spend cash for order %s: %w", order1.ID, err)
		}
	}

	// Mint output Cash
	for _, out := range req.Outputs {
		if err := Validator.Struct(&out); err != nil {
			return fmt.Errorf("invalid cash output: %w", err)
		}
		newCash := &Cash{
			ID:      generateCashID(),
			Pubkey:  out.Pubkey,
			Token:   out.Token,
			Amount:  out.Amount,
			ZkProof: req.ZkProof,
			Status:  Active,
		}
		if err := ot.Account.CreateCash(newCash); err != nil {
			return fmt.Errorf("failed to create output cash: %w", err)
		}
	}

	// Mark both orders as Done
	if err := ot.UpdateOrderStatus(order0.ID, Done); err != nil {
		return fmt.Errorf("failed to settle order %s: %w", order0.ID, err)
	}
	if err := ot.UpdateOrderStatus(order1.ID, Done); err != nil {
		return fmt.Errorf("failed to settle order %s: %w", order1.ID, err)
	}

	ctx.EmitStringEvent("orders settled: %s <-> %s, %d outputs minted",
		order0.ID, order1.ID, len(req.Outputs))
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

	ctx.JsonOk(map[string]interface{}{"orders": orders})
}

// ────────────────────── Matching Logic ──────────────────────

// matchOrder finds a counterparty for the incoming order.
//
//	Buy  → looks for pending Sell orders where sell price ≤ buy price (picks lowest sell)
//	Sell → looks for pending Buy  orders where buy  price ≥ sell price (picks highest buy)
//
// If matched, both orders' Status is set to Matched and MatchOrder is set to each other.
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

	// Update both orders to Matched and set MatchOrder to each other
	order.Status = Matched
	order.MatchOrder = bestMatch.ID
	bestMatch.Status = Matched
	bestMatch.MatchOrder = order.ID

	if err := ot.UpdateOrderStatus(order.ID, Matched); err != nil {
		return nil, err
	}
	if err := ot.UpdateOrderMatchOrder(order.ID, bestMatch.ID); err != nil {
		return nil, err
	}
	if err := ot.UpdateOrderStatus(bestMatch.ID, Matched); err != nil {
		return nil, err
	}
	if err := ot.UpdateOrderMatchOrder(bestMatch.ID, order.ID); err != nil {
		return nil, err
	}

	return bestMatch, nil
}
