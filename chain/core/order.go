package core

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/big"
)

type Order struct {
	ID      OrderID    `json:"id"`
	Type    TradeType  `json:"type"`
	Subject TradePair  `json:"subject"`
	Price   *big.Int   `json:"price,omitempty"`
	Amount  CipherText `json:"amount"`
	Targets []OrderID  `json:"targets,omitempty"`
	Status  OrderStat  `json:"status"`
}

func (o *Order) Id() OrderID {
	return ""
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
	Buy = iota
	Sell
)

const (
	Pending OrderStat = iota
	Matched
	Done
	Cancelled
)

type TradePair struct {
	Token1 TokenID `json:"token1"`
	Token2 TokenID `json:"token2"`
}
