package core

import (
	"crypto/ed25519"
	"encoding/hex"
	"math/big"
	"testing"
)

// fullSigningRequest builds a SendOrderRequest exercising every field of the
// signing message: split mode with change output and locked commitment.
func fullSigningRequest() *SendOrderRequest {
	return &SendOrderRequest{
		ID:           "order-1",
		Type:         Buy,
		Subject:      TradePair{Token1: "ETH", Token2: "USDT"},
		Price:        big.NewInt(3500),
		Amount:       "amt-commit",
		Pubkey:       "alice-pk",
		InputCashIDs: []string{"cash-a", "cash-b"},
		HandlingFee:  []string{"5", "10"},
		Change: &CashChangeOutput{
			CashID: "change-cash",
			Amount: "change-amt",
		},
		LockedCommitment: "locked-commit",
	}
}

// The signing message must match the byte layout shared with the Rust client
// (`send_order_signing_message` in invisibook-lib): each field u32-BE
// length-prefixed, lists prefixed with a u32-BE element count. The expected
// hex was computed independently from the layout spec; the Rust side asserts
// the identical vectors.
func TestSendOrderSigningMessageLockstepVectors(t *testing.T) {
	const fullVector = "00000018696e76697369626f6f6b2d73656e642d6f726465722d7631000000076f726465722d31000000013000000003455448000000045553445400000004333530300000000a616d742d636f6d6d697400000008616c6963652d706b0000000200000006636173682d6100000006636173682d6200000002000000013500000002313000000001310000000b6368616e67652d636173680000000a6368616e67652d616d740000000d6c6f636b65642d636f6d6d6974"
	if got := hex.EncodeToString(SendOrderSigningMessage(fullSigningRequest())); got != fullVector {
		t.Errorf("full request message mismatch:\n got  %s\n want %s", got, fullVector)
	}

	// Minimal request: nil price, no change, no locked commitment — all three
	// encode as empty fields (with change flag "0") rather than being omitted.
	const minimalVector = "00000018696e76697369626f6f6b2d73656e642d6f726465722d7631000000076f726465722d3200000001310000000345544800000004555344540000000000000003616d7400000006626f622d706b0000000100000006636173682d630000000100000001300000000130000000000000000000000000"
	minimal := &SendOrderRequest{
		ID:           "order-2",
		Type:         Sell,
		Subject:      TradePair{Token1: "ETH", Token2: "USDT"},
		Amount:       "amt",
		Pubkey:       "bob-pk",
		InputCashIDs: []string{"cash-c"},
		HandlingFee:  []string{"0"},
	}
	if got := hex.EncodeToString(SendOrderSigningMessage(minimal)); got != minimalVector {
		t.Errorf("minimal request message mismatch:\n got  %s\n want %s", got, minimalVector)
	}
}

// Length-prefixed encoding must keep adjacent fields and list elements
// unambiguous: moving a byte across any boundary has to change the message.
// A plain delimiter join would collapse several of these pairs.
func TestSendOrderSigningMessageUnambiguous(t *testing.T) {
	base := fullSigningRequest()

	mutations := map[string]func(r *SendOrderRequest){
		"shift byte between tokens":        func(r *SendOrderRequest) { r.Subject = TradePair{Token1: "ETHU", Token2: "SDT"} },
		"shift byte between list elements": func(r *SendOrderRequest) { r.InputCashIDs = []string{"cash-ac", "ash-b"} },
		"merge list elements":              func(r *SendOrderRequest) { r.InputCashIDs = []string{"cash-acash-b"} },
		"move element across lists": func(r *SendOrderRequest) {
			r.InputCashIDs = []string{"cash-a"}
			r.HandlingFee = []string{"cash-b", "5", "10"}
		},
		"drop change into locked": func(r *SendOrderRequest) { r.Change = nil; r.LockedCommitment = "change-cashchange-amtlocked-commit" },
	}

	baseMsg := hex.EncodeToString(SendOrderSigningMessage(base))
	for name, mutate := range mutations {
		r := fullSigningRequest()
		mutate(r)
		if got := hex.EncodeToString(SendOrderSigningMessage(r)); got == baseMsg {
			t.Errorf("%s: mutated request produced an identical signing message", name)
		}
	}
}

// A signature over the canonical message must stop verifying as soon as any
// covered field changes — this is the property the old sign-the-ID scheme
// lacked (price, pair, and fees were malleable by any observer).
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
		"price":        func(r *SendOrderRequest) { r.Price = big.NewInt(1) },
		"type":         func(r *SendOrderRequest) { r.Type = Sell },
		"token1":       func(r *SendOrderRequest) { r.Subject.Token1 = "SHIB" },
		"amount":       func(r *SendOrderRequest) { r.Amount = "other-commit" },
		"handling fee": func(r *SendOrderRequest) { r.HandlingFee = []string{"999999"} },
		"change dest":  func(r *SendOrderRequest) { r.Change.CashID = "attacker-cash" },
	}
	for name, mutate := range tampered {
		r := fullSigningRequest()
		mutate(r)
		if ed25519.Verify(pub, SendOrderSigningMessage(r), sig) {
			t.Errorf("signature still verifies after tampering with %s", name)
		}
	}
}
