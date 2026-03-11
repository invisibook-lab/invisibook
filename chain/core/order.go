package core

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
	Targets []OrderID  `json:"targets,omitempty"`
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

// ComputeOrderID derives a deterministic order ID by hashing the order's
// immutable content fields (type, pair, price, amount) with SHA-256.
// The client must compute and submit this value as the order ID.
func ComputeOrderID(orderType TradeType, subject TradePair, price *big.Int, amount CipherText) OrderID {
	type content struct {
		Type   int    `json:"type"`
		Token1 string `json:"token1"`
		Token2 string `json:"token2"`
		Price  string `json:"price"`
		Amount string `json:"amount"`
	}

	priceStr := ""
	if price != nil {
		priceStr = price.String()
	}

	c := content{
		Type:   int(orderType),
		Token1: string(subject.Token1),
		Token2: string(subject.Token2),
		Price:  priceStr,
		Amount: string(amount),
	}

	data, _ := json.Marshal(c)
	h := sha256.Sum256(data)
	return OrderID(hex.EncodeToString(h[:]))
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
