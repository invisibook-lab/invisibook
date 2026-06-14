package consensus

import (
	"crypto/rand"
	"encoding/hex"
	"math/big"
)

// L1Payment represents a payment proof from L1.
// In Phase 1 this is fully mocked.
type L1Payment struct {
	// TxHash is the L1 transaction hash (mock: randomly generated).
	TxHash string `json:"tx_hash"`
	// Amount is the payment amount in the smallest unit.
	Amount *big.Int `json:"amount"`
	// Payer is the miner's L1 address.
	Payer string `json:"payer"`
}

// L1PaymentVerifier abstracts L1 payment verification.
// Implement this interface for each supported L1 (e.g. CKB).
type L1PaymentVerifier interface {
	// VerifyPayment checks whether the given L1 payment proof is valid.
	VerifyPayment(payment *L1Payment) bool
}

// MockL1PaymentVerifier is a no-op verifier that always returns true.
// Used in Phase 1 / testing.
type MockL1PaymentVerifier struct{}

// VerifyPayment always returns true for mock usage.
func (m *MockL1PaymentVerifier) VerifyPayment(_ *L1Payment) bool {
	return true
}

// MockL1Payment creates a mock L1 payment with the given amount.
// `amount` must not be nil.
func MockL1Payment(amount *big.Int) *L1Payment {
	txHash := make([]byte, 32)
	// best-effort random; ignore error for mock usage
	_, _ = rand.Read(txHash)
	return &L1Payment{
		TxHash: hex.EncodeToString(txHash),
		Amount: new(big.Int).Set(amount),
		Payer:  "0xMOCK_PAYER",
	}
}
