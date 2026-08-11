package core

import (
	"math/big"
	"testing"
)

// The settlement circuits take `price` as a public input and multiply it by
// 64-bit amounts, relying on price < 2^64 for the products to stay
// integer-exact below the BN254 modulus. Every path from an Order to the
// circuit goes through big.Int.Uint64(), which truncates silently, so
// out-of-range prices have to be rejected before they are stored.
func TestValidateOrderPrice(t *testing.T) {
	twoPow64 := new(big.Int).Lsh(big.NewInt(1), 64)

	valid := []*big.Int{
		nil, // no price: the order simply never matches
		big.NewInt(1),
		big.NewInt(3),
		new(big.Int).SetUint64(^uint64(0)), // 2^64 - 1, the largest representable
	}
	for _, p := range valid {
		if err := validateOrderPrice(p); err != nil {
			t.Errorf("validateOrderPrice(%v) = %v, want nil", p, err)
		}
	}

	invalid := []*big.Int{
		big.NewInt(0),
		big.NewInt(-1),
		twoPow64, // first value that truncates to 0
		new(big.Int).Add(twoPow64, big.NewInt(5)), // truncates to 5
		new(big.Int).Lsh(big.NewInt(1), 200),      // far out of range
	}
	for _, p := range invalid {
		if err := validateOrderPrice(p); err == nil {
			t.Errorf("validateOrderPrice(%v) = nil, want error", p)
		}
	}
}

// A price above 2^64 truncates to a *different, still-plausible* number rather
// than to something obviously wrong, which is what makes the missing check
// dangerous: the book would match on one price and settle on another.
func TestOutOfRangePriceTruncatesSilently(t *testing.T) {
	p := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(5))
	if got := p.Uint64(); got != 5 {
		t.Fatalf("Uint64() of 2^64+5 = %d, want 5 (truncation assumption changed)", got)
	}
	if err := validateOrderPrice(p); err == nil {
		t.Fatal("a price that truncates to 5 must be rejected")
	}
}
