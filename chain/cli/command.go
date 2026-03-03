package main

import (
	"fmt"
	"math/big"
	"strings"

	"github.com/invisibook-lab/invisibook/core"
)

// ────────────────────── Command Handling ──────────────────────

func (m model) handleCommand(input string) model {
	parts := strings.Fields(input)
	if len(parts) != 5 {
		m.message = "✗ 格式错误! 用法: buy/sell {token_1} {amount_1} {token_2} {amount_2}"
		m.isError = true
		return m
	}

	action := strings.ToLower(parts[0])
	token1 := core.TokenID(strings.ToUpper(parts[1]))
	amount1Str := parts[2]
	token2 := core.TokenID(strings.ToUpper(parts[3]))
	amount2Str := parts[4]

	var tradeType core.TradeType
	switch action {
	case "buy":
		tradeType = core.Buy
	case "sell":
		tradeType = core.Sell
	default:
		m.message = "✗ 未知操作! 请使用 buy 或 sell"
		m.isError = true
		return m
	}

	price := new(big.Int)
	if _, ok := price.SetString(amount2Str, 10); !ok {
		m.message = "✗ token_2 数量格式错误，请输入整数!"
		m.isError = true
		return m
	}

	order := core.Order{
		ID:   nextOrderID(),
		Type: tradeType,
		Subject: core.TradePair{
			Token1: token1,
			Token2: token2,
		},
		Price:  price,
		Amount: mockCipherText(amount1Str),
		Status: core.Pending,
	}

	m.orders = append(m.orders, order)
	sortOrders(m.orders)

	typeName := "买入"
	if tradeType == core.Sell {
		typeName = "卖出"
	}
	m.message = fmt.Sprintf("✓ 订单已创建: %s %s/%s 报价 %s", typeName, token1, token2, amount2Str)
	m.isError = false
	m.expanded = -1
	return m
}
