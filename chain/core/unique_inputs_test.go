package core

import (
	"strings"
	"testing"
)

// validSendOrderRequest returns a request passing every struct-tag validation.
func validSendOrderRequest() *SendOrderRequest {
	return &SendOrderRequest{
		ID:           "order-1",
		Type:         Buy,
		Subject:      TradePair{Token1: "ETH", Token2: "USDT"},
		Amount:       "amt-commit",
		Pubkey:       "alice-pk",
		Signature:    "sig",
		InputCashIDs: []string{"cash-a", "cash-b"},
		HandlingFee:  []string{"0"},
	}
}

// validWithdrawRequest returns a request passing every struct-tag validation.
func validWithdrawRequest() *WithdrawRequest {
	return &WithdrawRequest{
		Pubkey:              "alice-pk",
		Token:               "ETH",
		Inputs:              []string{"cash-a", "cash-b"},
		BridgeOutCommitment: strings.Repeat("a", 64),
		OutputCommitments:   []string{strings.Repeat("b", 64), strings.Repeat("c", 64)},
		ZkProof:             "proof",
	}
}

// Listing the same cash twice would make both the split and withdraw circuits
// count its commitment twice (sum(inputs) doubles) while SpendCash only spends
// the single row once — minting value from nothing. The `unique` validator tag
// must reject such requests before any state or proof check runs.
func TestDuplicateInputCashIDsRejected(t *testing.T) {
	if err := Validator.Struct(validSendOrderRequest()); err != nil {
		t.Fatalf("distinct input cash IDs must validate, got: %v", err)
	}
	dup := validSendOrderRequest()
	dup.InputCashIDs = []string{"cash-a", "cash-a"}
	if err := Validator.Struct(dup); err == nil {
		t.Fatal("duplicate input_cash_ids must fail validation")
	}
}

// Same double-count hazard as SendOrder, on the withdraw path: duplicate
// inputs would let a client withdraw twice the value of a single cash.
func TestDuplicateWithdrawInputsRejected(t *testing.T) {
	if err := Validator.Struct(validWithdrawRequest()); err != nil {
		t.Fatalf("distinct withdraw inputs must validate, got: %v", err)
	}
	dup := validWithdrawRequest()
	dup.Inputs = []string{"cash-a", "cash-a"}
	if err := Validator.Struct(dup); err == nil {
		t.Fatal("duplicate withdraw inputs must fail validation")
	}
}
