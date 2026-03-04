package main

import (
	"fmt"
	"math/big"
	"strings"

	"github.com/invisibook-lab/invisibook/core"
)

// ────────────────────── Command Handling ──────────────────────
// Syntax: buy/sell {token_1} {price} {amount} {token_2}

func (m model) handleCommand(input string) model {
	parts := strings.Fields(input)
	if len(parts) != 5 {
		m.message = "✗ Invalid format! Usage: buy/sell {token_1} {price} {amount} {token_2}"
		m.isError = true
		return m
	}

	action := strings.ToLower(parts[0])
	token1 := core.TokenID(strings.ToUpper(parts[1]))
	priceStr := parts[2]
	amountStr := parts[3]
	token2 := core.TokenID(strings.ToUpper(parts[4]))

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

	// validate price is a positive integer
	price := new(big.Int)
	if _, ok := price.SetString(priceStr, 10); !ok || price.Sign() <= 0 {
		m.message = "✗ price must be a positive integer!"
		m.isError = true
		return m
	}

	// validate amount is a positive integer
	amount := new(big.Int)
	if _, ok := amount.SetString(amountStr, 10); !ok || amount.Sign() <= 0 {
		m.message = "✗ amount must be a positive integer!"
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
		Amount: mockCipherText(amountStr),
		Status: core.Pending,
	}

	m.orders = append(m.orders, order)
	m.ownOrderIDs[order.ID] = amountStr // track own order with plain amount
	sortOrders(m.orders)

	typeName := "BUY"
	if tradeType == core.Sell {
		typeName = "SELL"
	}
	m.message = fmt.Sprintf("✓ Order created: %s %s/%s price %s amount %s", typeName, token1, token2, priceStr, amountStr)
	m.isError = false
	m.expanded = -1
	return m
}
