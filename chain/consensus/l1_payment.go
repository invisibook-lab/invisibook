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

// VerifyL1Payment checks the validity of an L1 payment proof.
// Phase 1 mock: always returns true.
// TODO: implement real L1 payment verification.
func VerifyL1Payment(_ *L1Payment) bool {
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
