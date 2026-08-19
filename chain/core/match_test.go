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
		Pubkey:           "pk-" + id,
		LockedCommitment: "00" + strings.Repeat(hex.EncodeToString([]byte{0xBB}), 31),
		BlockHeight:      height,
		Status:           Pending,
	}
}

// Crossing unequal prices match and persist the resting (maker) price.
func TestMatcherMatchesCrossingUnequalPrices(t *testing.T) {
	ot := matchFixture(t)
	sell := mkOrder("sell-4", Sell, 4, 1)
	if err := ot.InsertOrder(sell); err != nil {
		t.Fatal(err)
	}
	buy := mkOrder("buy-5", Buy, 5, 2)
	if err := ot.InsertOrder(buy); err != nil {
		t.Fatal(err)
	}

	matched, err := ot.matchOrder(buy, uint64(buy.BlockHeight))
	if err != nil {
		t.Fatal(err)
	}
	if matched == nil || matched.ID != sell.ID {
		t.Fatalf("buy@5 must match sell@4, got %v", matched)
	}
	for _, id := range []OrderID{"sell-4", "buy-5"} {
		order, err := ot.GetOrder(id)
		if err != nil {
			t.Fatal(err)
		}
		if order.Status != Matched {
			t.Fatalf("order %s must be Matched, got %s", id, order.Status.String())
		}
		if order.ExecutionPrice == nil || order.ExecutionPrice.Uint64() != 4 {
			t.Fatalf("order %s execution price must be maker sell price 4", id)
		}
		if order.MatchHeight != 2 || compareProofShareDeadline(order, order) != 12 {
			t.Fatalf("order %s match height/deadline = %d/%d, want 2/12", id,
				order.MatchHeight, compareProofShareDeadline(order, order))
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

	matched, err := ot.matchOrder(buy, uint64(buy.BlockHeight))
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

// Price priority precedes height: the better ask wins even when it is newer.
func TestMatcherPricePrecedesTime(t *testing.T) {
	ot := matchFixture(t)
	// The better crossing sell at 3 must win.
	if err := ot.InsertOrder(mkOrder("sell-3", Sell, 3, 20)); err != nil {
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

	matched, err := ot.matchOrder(buy, uint64(buy.BlockHeight))
	if err != nil {
		t.Fatal(err)
	}
	if matched == nil || matched.ID != "sell-3" {
		t.Fatalf("must match the best-priced sell, got %v", matched)
	}
	untouched, _ := ot.GetOrder("sell-5-early")
	if untouched.Status != Pending {
		t.Fatal("the worse-priced sell must stay Pending")
	}
}

func TestMatcherTieBreakPriority(t *testing.T) {
	base := mkOrder("base", Sell, 5, 10)
	base.Fee = 7
	base.IntraBlockIndex = 4

	tests := []struct {
		name string
		edit func(*Order)
	}{
		{"earlier block beats fee", func(o *Order) { o.BlockHeight, o.Fee = 9, 0 }},
		{"higher fee beats intra-block index", func(o *Order) { o.Fee, o.IntraBlockIndex = 8, 99 }},
		{"earlier intra-block index wins", func(o *Order) { o.IntraBlockIndex = 3 }},
		{"order id is deterministic final tie-break", func(o *Order) { o.ID = "aaa" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			candidate := mkOrder("candidate", Sell, 5, 10)
			candidate.Fee = 7
			candidate.IntraBlockIndex = 4
			tt.edit(candidate)
			if !betterCounter(candidate, base) {
				t.Fatal("candidate must outrank base at the tested tie-break")
			}
		})
	}
}

func mkMarketOrder(id string, typ TradeType, protection uint64, height uint32) *Order {
	o := mkOrder(id, typ, protection, height)
	o.Kind = Market
	o.Price = nil
	o.ProtectionPrice = new(big.Int).SetUint64(protection)
	return o
}

func TestMatcherMarketFlagPrecedesLimitPrice(t *testing.T) {
	market := mkMarketOrder("market", Sell, 5, 10)
	limit := mkOrder("limit", Sell, 1, 1)
	if !betterCounter(market, limit) {
		t.Fatal("a crossing market candidate must outrank a limit candidate")
	}
}

func TestMatcherMarketLimitAndProtection(t *testing.T) {
	ot := matchFixture(t)
	sell := mkOrder("sell-4", Sell, 4, 1)
	if err := ot.InsertOrder(sell); err != nil {
		t.Fatal(err)
	}
	buy := mkMarketOrder("market-buy", Buy, 5, 2)
	if err := ot.InsertOrder(buy); err != nil {
		t.Fatal(err)
	}
	matched, err := ot.matchOrder(buy, uint64(buy.BlockHeight))
	if err != nil {
		t.Fatal(err)
	}
	if matched == nil || matched.ID != sell.ID {
		t.Fatalf("protected market buy must match limit sell, got %v", matched)
	}
	if buy.ExecutionPrice.Uint64() != 4 {
		t.Fatalf("market/limit must execute at limit price, got %s", buy.ExecutionPrice)
	}
}

func TestMatcherMarketMarketDoesNotMatch(t *testing.T) {
	ot := matchFixture(t)
	sell := mkMarketOrder("market-sell", Sell, 4, 1)
	buy := mkMarketOrder("market-buy", Buy, 5, 2)
	if err := ot.InsertOrder(sell); err != nil {
		t.Fatal(err)
	}
	if err := ot.InsertOrder(buy); err != nil {
		t.Fatal(err)
	}
	matched, err := ot.matchOrder(buy, uint64(buy.BlockHeight))
	if err != nil {
		t.Fatal(err)
	}
	if matched != nil {
		t.Fatalf("market/market has no execution-price reference, got %v", matched)
	}
}

func TestMatcherRejectsNonCrossingLimits(t *testing.T) {
	ot := matchFixture(t)
	sell := mkOrder("sell-6", Sell, 6, 1)
	buy := mkOrder("buy-5", Buy, 5, 2)
	if err := ot.InsertOrder(sell); err != nil {
		t.Fatal(err)
	}
	if err := ot.InsertOrder(buy); err != nil {
		t.Fatal(err)
	}
	matched, err := ot.matchOrder(buy, uint64(buy.BlockHeight))
	if err != nil {
		t.Fatal(err)
	}
	if matched != nil {
		t.Fatalf("non-crossing limits must remain pending, got %v", matched)
	}
}

func TestMatcherAssignsSharedMonotonicRound(t *testing.T) {
	ot := matchFixture(t)
	sell := mkOrder("relisted-sell", Sell, 4, 1)
	sell.MatchRound = 7
	buy := mkOrder("fresh-buy", Buy, 5, 2)
	if err := ot.InsertOrder(sell); err != nil {
		t.Fatal(err)
	}
	if err := ot.InsertOrder(buy); err != nil {
		t.Fatal(err)
	}
	if _, err := ot.matchOrder(buy, uint64(buy.BlockHeight)); err != nil {
		t.Fatal(err)
	}
	for _, id := range []OrderID{sell.ID, buy.ID} {
		order, err := ot.GetOrder(id)
		if err != nil {
			t.Fatal(err)
		}
		if order.MatchRound != 8 {
			t.Fatalf("order %s round = %d, want shared round 8", id, order.MatchRound)
		}
	}
}

// A relisted/aborted survivor may be passed to matchOrder even though it is
// older than every pending candidate. Execution price still belongs to the
// true maker, not mechanically to the candidate argument.
func TestMatcherRematchUsesChronologicalMakerPrice(t *testing.T) {
	ot := matchFixture(t)
	oldSell := mkOrder("old-sell", Sell, 4, 1)
	newBuy := mkOrder("new-buy", Buy, 5, 9)
	if err := ot.InsertOrder(oldSell); err != nil {
		t.Fatal(err)
	}
	if err := ot.InsertOrder(newBuy); err != nil {
		t.Fatal(err)
	}
	matched, err := ot.matchOrder(oldSell, 100)
	if err != nil {
		t.Fatal(err)
	}
	if matched == nil || oldSell.ExecutionPrice == nil || oldSell.ExecutionPrice.Uint64() != 4 {
		t.Fatalf("rematch must execute at old maker price 4, got match=%v price=%v", matched, oldSell.ExecutionPrice)
	}
	for _, id := range []OrderID{oldSell.ID, newBuy.ID} {
		order, err := ot.GetOrder(id)
		if err != nil {
			t.Fatal(err)
		}
		if order.MatchHeight != 100 || compareProofShareDeadline(order, order) != 110 {
			t.Fatalf("rematched order %s has match height/deadline %d/%d", id,
				order.MatchHeight, compareProofShareDeadline(order, order))
		}
	}
}
