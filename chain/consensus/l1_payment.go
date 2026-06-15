package consensus

import (
	"context"
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
	// MinerPubkey identifies which miner made this payment.
	MinerPubkey string `json:"miner_pubkey"`
}

// L1PaymentVerifier abstracts L1 payment fetching and verification.
// Implement this interface for each supported L1 (e.g. CKB).
type L1PaymentVerifier interface {
	// FetchAndVerifyPayments polls L1 for all miners' payments,
	// verifies them, and returns only the valid ones.
	FetchAndVerifyPayments(ctx context.Context) ([]*L1Payment, error)
}

// MockL1PaymentVerifier is a mock verifier that returns a single payment
// for the local node. Used in Phase 1 / testing.
type MockL1PaymentVerifier struct {
	// MinPayment is the mock payment amount (decimal string).
	MinPayment string
	// MinerPubkey is the hex-encoded public key of this node.
	MinerPubkey string
}

// FetchAndVerifyPayments returns a single mock payment for this node.
func (m *MockL1PaymentVerifier) FetchAndVerifyPayments(_ context.Context) ([]*L1Payment, error) {
	amount, ok := new(big.Int).SetString(m.MinPayment, 10)
	if !ok {
		amount = big.NewInt(100)
	}
	payment := MockL1Payment(amount, m.MinerPubkey)
	return []*L1Payment{payment}, nil
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
