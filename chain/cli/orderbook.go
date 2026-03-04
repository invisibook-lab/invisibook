package main

import (
	"crypto/sha256"
	"fmt"
	"math/big"
	"sort"
	"sync/atomic"

	"github.com/invisibook-lab/invisibook/core"
)

// ────────────────────── ID Generator ──────────────────────

var orderSeq atomic.Int64

func init() {
	orderSeq.Store(100) // sample orders use 0001‑0005
}

func nextOrderID() core.OrderID {
	id := orderSeq.Add(1)
	return core.OrderID(fmt.Sprintf("ord-%04d", id))
}

// ────────────────────── Cipher Mock ──────────────────────

// mockCipherText simulates FHE encryption – returns a hex digest.
func mockCipherText(plaintext string) core.CipherText {
	h := sha256.Sum256([]byte(plaintext))
	return core.CipherText(fmt.Sprintf("0x%x", h[:10]))
}

// ────────────────────── Order Helpers ──────────────────────

func sortOrders(orders []core.Order) {
	sort.Slice(orders, func(i, j int) bool {
		pi, pj := orders[i].Price, orders[j].Price
		if pi == nil {
			return false
		}
		if pj == nil {
			return true
		}
		return pi.Cmp(pj) > 0
	})
}

// ────────────────────── Sample Data ──────────────────────

func sampleOrders() []core.Order {
	return []core.Order{
		{
			ID:      "ord-0001",
			Type:    core.Buy,
			Subject: core.TradePair{Token1: "ETH", Token2: "USDT"},
			Price:   big.NewInt(3500),
			Amount:  mockCipherText("10"),
			Status:  core.Pending,
		},
		{
			ID:      "ord-0002",
			Type:    core.Sell,
			Subject: core.TradePair{Token1: "ETH", Token2: "USDT"},
			Price:   big.NewInt(3600),
			Amount:  mockCipherText("5"),
			Status:  core.Pending,
		},
		{
			ID:      "ord-0003",
			Type:    core.Buy,
			Subject: core.TradePair{Token1: "BTC", Token2: "USDT"},
			Price:   big.NewInt(65000),
			Amount:  mockCipherText("2"),
			Status:  core.Pending,
		},
		{
			ID:      "ord-0004",
			Type:    core.Sell,
			Subject: core.TradePair{Token1: "BTC", Token2: "USDT"},
			Price:   big.NewInt(64500),
			Amount:  mockCipherText("1"),
			Status:  core.Matched,
		},
		{
			ID:      "ord-0005",
			Type:    core.Buy,
			Subject: core.TradePair{Token1: "SOL", Token2: "USDT"},
			Price:   big.NewInt(180),
			Amount:  mockCipherText("50"),
			Status:  core.Pending,
		},
	}
}
