package core

import "math/big"

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
}
