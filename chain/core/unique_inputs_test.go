package core

import (
	"strings"
	"testing"
)

// validSendOrderRequest returns a v2 request passing every struct-tag
// validation.
func validSendOrderRequest() *SendOrderRequest {
	return &SendOrderRequest{
		ID:                         "order-1",
		Type:                       Buy,
		Subject:                    TradePair{Token1: "ETH", Token2: "USDT"},
		Pubkey:                     "alice-pk",
		Signature:                  "sig",
		Anchor:                     strings.Repeat("b", 64),
		CollateralNullifiers:       []string{strings.Repeat("c", 64), strings.Repeat("d", 64)},
		FeeNullifiers:              []string{strings.Repeat("1", 64), strings.Repeat("2", 64)},
		LockedCommitment:           strings.Repeat("e", 64),
		CollateralChangeCommitment: strings.Repeat("f", 64),
		FeeChangeCommitment:        strings.Repeat("a", 64),
		ZkProof:                    "proof",
	}
}

// SendOrder always spends exactly two nullifier slots. A well-formed request
// with distinct nullifiers validates; the runtime handler additionally
// rejects a request whose two nullifiers are equal (a duplicate would let one
// note satisfy both slots). Struct-tag validation covers the shape; the
// equal-nullifier rejection is exercised by the pool/e2e tests where the
// handler runs.
func TestSendOrderNullifierShapeValidates(t *testing.T) {
	if err := Validator.Struct(validSendOrderRequest()); err != nil {
		t.Fatalf("well-formed v2 request must validate, got: %v", err)
	}
	// Wrong length (one nullifier) must fail the len=2 tag.
	bad := validSendOrderRequest()
	bad.CollateralNullifiers = []string{strings.Repeat("c", 64)}
	if err := Validator.Struct(bad); err == nil {
		t.Fatal("a request without two nullifier slots must fail validation")
	}
}
