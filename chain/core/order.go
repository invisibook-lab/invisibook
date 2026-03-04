package core

import (
	"math/big"

	"github.com/go-playground/validator/v10"
)

// Validator is the shared validator instance for struct tag validation.
var Validator = validator.New()

type Order struct {
	ID      OrderID    `json:"id"      validate:"required"`
	Type    TradeType  `json:"type"    validate:"oneof=0 1"`
	Subject TradePair  `json:"subject"`
	Price   *big.Int   `json:"price,omitempty"`
	Amount  CipherText `json:"amount"  validate:"required"`
	Status  OrderStat  `json:"status"  validate:"oneof=0 1 2 3"`
}

// Validate checks all struct tag constraints on the Order.
func (o *Order) Validate() error {
	return Validator.Struct(o)
}

func (o *Order) Id() OrderID {
	return o.ID
}

func (o *Order) Length() uint64 {
	return 0
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
	default:
		return "Unknown"
	}
}
