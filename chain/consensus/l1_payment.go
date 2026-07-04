package consensus

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"math/big"
)

// L1PaymentInput carries a payment hash submitted by an external client
// via the Reading interface.
type L1PaymentInput struct {
	// PaymentHash is the L1 payment hash (e.g. from Fiber send_payment).
	PaymentHash string `json:"payment_hash"`
	// BlockHeight is the target block height this payment is intended for.
	BlockHeight uint64 `json:"block_height"`
}

// L1Payment represents a payment proof from L1.
// In Phase 1 this is fully mocked.
type L1Payment struct {
	// TxHash is the L1 transaction hash (mock: randomly generated).
	TxHash string `json:"tx_hash"`
	// Amount is the payment amount in the smallest unit.
	Amount *big.Int `json:"amount"`
	// Payer is the miner's L1 address.
	Payer string `json:"payer"`
	// MinerPubkey identifies which miner made this payment.
	MinerPubkey string `json:"miner_pubkey"`
}

// L1PaymentVerifier abstracts L1 payment verification.
// Implement this interface for each supported L1 (e.g. CKB).
type L1PaymentVerifier interface {
	// VerifyPayment checks whether the given payment exists on L1.
	VerifyPayment(ctx context.Context, payment *L1Payment) bool
}

// MockL1PaymentVerifier is a mock verifier used in Phase 1 / testing.
// VerifyPayment always returns true.
type MockL1PaymentVerifier struct{}

// VerifyPayment always returns true for mock usage.
func (m *MockL1PaymentVerifier) VerifyPayment(_ context.Context, _ *L1Payment) bool {
	return true
}

// MockL1Payment creates a mock L1 payment with the given amount and miner pubkey.
// `amount` must not be nil.
func MockL1Payment(amount *big.Int, minerPubkey string) *L1Payment {
	txHash := make([]byte, 32)
	// best-effort random; ignore error for mock usage
	_, _ = rand.Read(txHash)
	return &L1Payment{
		TxHash:      hex.EncodeToString(txHash),
		Amount:      new(big.Int).Set(amount),
		Payer:       "0xMOCK_PAYER",
		MinerPubkey: minerPubkey,
	}
}
