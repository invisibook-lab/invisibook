package core

import (
	"crypto/ed25519"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
)

// sendOrderV4Vector is the frozen byte-lockstep signing vector (Go↔Rust).
const sendOrderV4Vector = "00000018696e76697369626f6f6b2d73656e642d6f726465722d7634000000076f726465722d310000000130000000013000000003455448000000045553445400000004333530300000000000000008616c6963652d706b00000040626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262620000004063636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363000000406464646464646464646464646464646464646464646464646464646464646464646464646464646464646464646464646464646464646464646464646464646400000040313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131310000004032323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232000000406565656565656565656565656565656565656565656565656565656565656565656565656565656565656565656565656565656565656565656565656565656500000008000000000000000700000040666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666660000004061616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161"

// fullSigningRequest builds a SendOrder v4 request exercising every field of
// the signing message.
func fullSigningRequest() *SendOrderRequest {
	return &SendOrderRequest{
		ID:                         "order-1",
		Kind:                       Limit,
		Type:                       Buy,
		Subject:                    TradePair{Token1: "ETH", Token2: "USDT"},
		Price:                      big.NewInt(3500),
		Pubkey:                     "alice-pk",
		Anchor:                     strings.Repeat("b", 64),
		CollateralNullifiers:       []string{strings.Repeat("c", 64), strings.Repeat("d", 64)},
		FeeNullifiers:              []string{strings.Repeat("1", 64), strings.Repeat("2", 64)},
		LockedCommitment:           strings.Repeat("e", 64),
		Fee:                        7,
		CollateralChangeCommitment: strings.Repeat("f", 64),
		FeeChangeCommitment:        strings.Repeat("a", 64),
	}
}

// The signing message must match the byte layout shared with the Rust client
// (`send_order_signing_message` in invisibook-lib): each field u32-BE
// length-prefixed, fee as a u64-BE 8-byte field. The vector was recomputed
// from the frozen layout; the Rust test asserts the identical bytes.
func TestSendOrderSigningMessageLockstepVectors(t *testing.T) {
	got := hex.EncodeToString(SendOrderSigningMessage(fullSigningRequest()))
	if got != sendOrderV4Vector {
		t.Errorf("signing message mismatch:\n got  %s\n want %s", got, sendOrderV4Vector)
	}
}

// A signature over the canonical message must stop verifying as soon as any
// covered field changes.
func TestSendOrderSignatureCoversAllFields(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	req := fullSigningRequest()
	sig := ed25519.Sign(priv, SendOrderSigningMessage(req))
	if !ed25519.Verify(pub, SendOrderSigningMessage(req), sig) {
		t.Fatal("signature over unmodified request must verify")
	}

	tampered := map[string]func(r *SendOrderRequest){
		"price":       func(r *SendOrderRequest) { r.Price = big.NewInt(1) },
		"type":        func(r *SendOrderRequest) { r.Type = Sell },
		"token1":      func(r *SendOrderRequest) { r.Subject.Token1 = "SHIB" },
		"anchor":      func(r *SendOrderRequest) { r.Anchor = strings.Repeat("9", 64) },
		"nullifier 0": func(r *SendOrderRequest) { r.CollateralNullifiers[0] = strings.Repeat("9", 64) },
		"locked":      func(r *SendOrderRequest) { r.LockedCommitment = strings.Repeat("9", 64) },
		"fee":         func(r *SendOrderRequest) { r.Fee = 8 },
		"change":      func(r *SendOrderRequest) { r.CollateralChangeCommitment = strings.Repeat("9", 64) },
	}
	for name, mutate := range tampered {
		r := fullSigningRequest()
		mutate(r)
		if ed25519.Verify(pub, SendOrderSigningMessage(r), sig) {
			t.Errorf("signature still verifies after tampering with %s", name)
		}
	}
}
