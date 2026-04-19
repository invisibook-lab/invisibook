package core

import (
	"crypto/sha256"
	"encoding/hex"
	"math/big"

	"github.com/go-playground/validator/v10"
)

// Validator is the shared validator instance for struct tag validation.
var Validator = validator.New()

type Order struct {
	ID           OrderID    `json:"id"      validate:"required"`
	Type         TradeType  `json:"type"    validate:"oneof=0 1"`
	Subject      TradePair  `json:"subject"`
	Price        *big.Int   `json:"price,omitempty"`
	Amount       CipherText `json:"amount"  validate:"required"`
	Owner        string     `json:"owner"   validate:"required"`
	InputCashIDs []string   `json:"input_cash_ids" validate:"required,min=1"`
	MatchOrder   OrderID    `json:"match_order,omitempty"`
	Status       OrderStat  `json:"status"  validate:"oneof=0 1 2 3 4"`
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

type (
	OrderID    string
	TradeType  int
	CipherText string
	OrderStat  int
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
)

type TradePair struct {
	Token1 TokenID `json:"token1" validate:"required"`
	Token2 TokenID `json:"token2" validate:"required"`
}

func (tp TradePair) String() string {
	return string(tp.Token1) + "/" + string(tp.Token2)
}

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
	default:
		return "Unknown"
	}
}
