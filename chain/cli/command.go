package main

import (
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/invisibook-lab/invisibook/core"
)

// ────────────────────── Command Handling ──────────────────────

func (m model) handleCommand(input string) model {
	parts := strings.Fields(input)
	if len(parts) != 5 {
		m.message = "✗ Invalid format! Usage: buy/sell {token_1} {amount_1} {token_2} {amount_2}"
		m.isError = true
		return m
	}

	action := strings.ToLower(parts[0])
	token1 := core.TokenID(strings.ToUpper(parts[1]))
	amount1Str := parts[2]
	token2 := core.TokenID(strings.ToUpper(parts[3]))
	amount2Str := parts[4]

	// validate action
	var tradeType core.TradeType
	switch action {
	case "buy":
		tradeType = core.Buy
	case "sell":
		tradeType = core.Sell
	default:
		m.message = "✗ Unknown action! Please use buy or sell"
		m.isError = true
		return m
	}

	// validate amount_1 is a number
	if _, err := strconv.ParseFloat(amount1Str, 64); err != nil {
		m.message = "✗ amount_1 must be a number!"
		m.isError = true
		return m
	}

	// validate amount_2 (price) is a number
	price := new(big.Int)
	if _, ok := price.SetString(amount2Str, 10); !ok {
		m.message = "✗ amount_2 must be a number!"
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
	m.ownOrderIDs[order.ID] = amount1Str // track own order with plain amount
	sortOrders(m.orders)

	typeName := "BUY"
	if tradeType == core.Sell {
		typeName = "SELL"
	}
	m.message = fmt.Sprintf("✓ Order created: %s %s/%s price %s", typeName, token1, token2, amount2Str)
	m.isError = false
	m.expanded = -1
	return m
}
