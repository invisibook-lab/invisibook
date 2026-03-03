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
	Token1 TokenID `json:"token1"`
	Token2 TokenID `json:"token2"`
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
