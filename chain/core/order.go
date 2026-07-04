package core

import (
	"crypto/sha256"
	"encoding/hex"
	"math/big"

	"github.com/go-playground/validator/v10"
)

// Validator is the shared validator instance for struct tag validation.
var Validator = validator.New()

// Order is the on-chain domain model of a buy or sell intent.
// `Amount` is encrypted ciphertext; `InputCashIDs` references the locked Cash
// that will fund settlement once the order is matched.
type Order struct {
	ID           OrderID    `json:"id"      validate:"required"`
	Type         TradeType  `json:"type"    validate:"oneof=0 1"`
	Subject      TradePair  `json:"subject"`
	Price        *big.Int   `json:"price,omitempty"`
	Amount       CipherText `json:"amount"  validate:"required"`
	Pubkey       string     `json:"pubkey"  validate:"required"` // owner's ed25519 pubkey (64-char hex)
	InputCashIDs []string   `json:"input_cash_ids" validate:"required,min=1"`
	HandlingFee  []string   `json:"handling_fee,omitempty"`
	BlockHeight  uint32     `json:"block_height"`
	MatchOrder   OrderID    `json:"match_order,omitempty"`
	Status       OrderStat  `json:"status"  validate:"oneof=0 1 2 3 4 5"`
	IsSmaller    bool       `json:"is_smaller"` // true if this order is the smaller side after MPC comparison
}

// Validate checks all struct tag constraints on the Order.
func (o *Order) Validate() error {
	return Validator.Struct(o)
}

// ComputeOrderID derives a deterministic order ID by SHA-256 hashing the
// concatenation of all input Cash IDs.
// Must match the Rust compute_order_id in invisibook-lib.
func ComputeOrderID(inputCashIDs []string) OrderID {
	h := sha256.New()
	for _, id := range inputCashIDs {
		h.Write([]byte(id))
	}
	return OrderID(hex.EncodeToString(h.Sum(nil)))
}

// Domain identifier and enum types used across the order/cash modules.
type (
	OrderID    string // hex-encoded SHA-256 of the order's input cash IDs
	TradeType  int    // Buy or Sell
	CipherText string // opaque encrypted amount, never decrypted on-chain
	OrderStat  int    // Pending, Matched, Done, Cancelled, Frozen, Compared
)

const (
	Buy TradeType = iota
	Sell
)

const (
	Pending OrderStat = iota
	Matched
	Done
	Cancelled
	Frozen
	Settling // MPC comparison done, awaiting ZK settlement
)

// TradePair names the two tokens involved in an order. By convention Token1
// is the asset being bought/sold and Token2 is the quote/payment asset.
type TradePair struct {
	Token1 TokenID `json:"token1" validate:"required"`
	Token2 TokenID `json:"token2" validate:"required"`
}

// String renders the pair as "Token1/Token2".
func (tp TradePair) String() string {
	return string(tp.Token1) + "/" + string(tp.Token2)
}

// String returns "BUY", "SELL", or "UNKNOWN" for unexpected values.
func (t TradeType) String() string {
	switch t {
	case Buy:
		return "BUY"
	case Sell:
		return "SELL"
	default:
		return "UNKNOWN"
	}
}

// String returns the human-readable name of an OrderStat value.
func (s OrderStat) String() string {
	switch s {
	case Pending:
		return "Pending"
	case Matched:
		return "Matched"
	case Done:
		return "Done"
	case Cancelled:
		return "Cancelled"
	case Frozen:
		return "Frozen"
	case Settling:
		return "Settling"
	default:
		return "Unknown"
	}
}
