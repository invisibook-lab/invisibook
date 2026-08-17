package core

import (
	"encoding/hex"
	"math/big"
	"path/filepath"
	"strings"
	"testing"
)

// matchFixture is an OrderBook on a fresh temp database (dev mode).
func matchFixture(t *testing.T) *OrderBook {
	t.Helper()
	return NewOrderBook(&OrderBookConfig{
		DBPath:        filepath.Join(t.TempDir(), "orders.db"),
		RequireProofs: false,
	})
}

// mkOrder builds a Pending order with the given side, price, and height.
func mkOrder(id string, typ TradeType, price uint64, height uint32) *Order {
	return &Order{
		ID:               OrderID(id),
		Type:             typ,
		Subject:          TradePair{Token1: "ETH", Token2: "USDT"},
		Price:            new(big.Int).SetUint64(price),
		Amount:           CipherText("00" + strings.Repeat(hex.EncodeToString([]byte{0xAA}), 31)),
		Pubkey:           "pk-" + id,
		LockedCommitment: "00" + strings.Repeat(hex.EncodeToString([]byte{0xBB}), 31),
		BlockHeight:      height,
		Status:           Pending,
	}
}

// P1-5 regression: a buy at 5 and a sell at 4 CROSS but are not equal —
// they must NOT match (a matched unequal pair could never settle and has
// no cancel path). Both stay Pending.
func TestMatcherRejectsCrossingUnequalPrices(t *testing.T) {
	ot := matchFixture(t)
	sell := mkOrder("sell-4", Sell, 4, 1)
	if err := ot.InsertOrder(sell); err != nil {
		t.Fatal(err)
	}
	buy := mkOrder("buy-5", Buy, 5, 2)
	if err := ot.InsertOrder(buy); err != nil {
		t.Fatal(err)
	}

	matched, err := ot.matchOrder(buy)
	if err != nil {
		t.Fatal(err)
	}
	if matched != nil {
		t.Fatalf("buy@5 must NOT match sell@4, matched %s", matched.ID)
	}
	for _, id := range []OrderID{"sell-4", "buy-5"} {
		order, err := ot.GetOrder(id)
		if err != nil {
			t.Fatal(err)
		}
		if order.Status != Pending {
			t.Fatalf("order %s must stay Pending, got %s", id, order.Status.String())
		}
		if order.MatchOrder != "" {
			t.Fatalf("order %s must have no match link, got %s", id, order.MatchOrder)
		}
	}
}

// P1-5 regression: equal prices match normally, linking both orders.
func TestMatcherMatchesEqualPrices(t *testing.T) {
	ot := matchFixture(t)
	sell := mkOrder("sell-5", Sell, 5, 1)
	if err := ot.InsertOrder(sell); err != nil {
		t.Fatal(err)
	}
	buy := mkOrder("buy-5", Buy, 5, 2)
	if err := ot.InsertOrder(buy); err != nil {
		t.Fatal(err)
	}

	matched, err := ot.matchOrder(buy)
	if err != nil {
		t.Fatal(err)
	}
	if matched == nil || matched.ID != "sell-5" {
		t.Fatalf("buy@5 must match sell@5, got %v", matched)
	}
	buyRow, _ := ot.GetOrder("buy-5")
	sellRow, _ := ot.GetOrder("sell-5")
	if buyRow.Status != Matched || sellRow.Status != Matched {
		t.Fatalf("both orders must be Matched, got %s / %s",
			buyRow.Status.String(), sellRow.Status.String())
	}
	if buyRow.MatchOrder != "sell-5" || sellRow.MatchOrder != "buy-5" {
		t.Fatal("match links must point at each other")
	}
}

// Equal-price candidates keep the height → fee → intra-block priority: the
// earlier block wins even when a better-crossing (unequal) price exists.
func TestMatcherEqualPricePriorityAndNoCrossPick(t *testing.T) {
	ot := matchFixture(t)
	// A "better" crossing sell at 3 must be ignored entirely.
	if err := ot.InsertOrder(mkOrder("sell-3", Sell, 3, 1)); err != nil {
		t.Fatal(err)
	}
	if err := ot.InsertOrder(mkOrder("sell-5-late", Sell, 5, 9)); err != nil {
		t.Fatal(err)
	}
	if err := ot.InsertOrder(mkOrder("sell-5-early", Sell, 5, 2)); err != nil {
		t.Fatal(err)
	}
	buy := mkOrder("buy-5", Buy, 5, 10)
	if err := ot.InsertOrder(buy); err != nil {
		t.Fatal(err)
	}

	matched, err := ot.matchOrder(buy)
	if err != nil {
		t.Fatal(err)
	}
	if matched == nil || matched.ID != "sell-5-early" {
		t.Fatalf("must match the EARLIER equal-price sell, got %v", matched)
	}
	untouched, _ := ot.GetOrder("sell-3")
	if untouched.Status != Pending {
		t.Fatal("the crossing unequal-price sell must stay Pending")
	}
}
