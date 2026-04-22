package core

import (
	"crypto/rand"
	"fmt"
)

// ────────────────────── Cash Status ──────────────────────

type CashStatus int

const (
	Active CashStatus = iota // 0 — available for spending or locking
	Locked                   // 1 — reserved by an order
	Spent                    // 2 — consumed
)

func (s CashStatus) String() string {
	switch s {
	case Active:
		return "Active"
	case Locked:
		return "Locked"
	case Spent:
		return "Spent"
	default:
		return "Unknown"
	}
}


// ────────────────────── Domain Models ──────────────────────

// Cash is the domain model for a single transaction output.
// Amount is an encrypted ciphertext — the plaintext is never revealed on-chain.
// ZkProof is committed at creation (e.g. the deposit bridge proof); it must
// verify successfully before this Cash can be consumed.
type Cash struct {
	ID      string     `json:"id"`
	Owner   string     `json:"owner"`
	Token   TokenID    `json:"token"`
	Amount  CipherText `json:"amount"`   // encrypted amount
	ZkProof string     `json:"zk_proof"` // proof committed at creation
	Status  CashStatus `json:"status"`
	By      string     `json:"by,omitempty"` // Locked: order ID; Spent: tx/cash ID
}

func (c *Cash) IsNative() bool {
	return c.Token.IsNative()
}

// AccountRecord is the response returned by GetAccount.
// Because amounts are ciphertext, no aggregate balance is computed on-chain.
type AccountRecord struct {
	Address string  `json:"address"`
	Token   TokenID `json:"token"`
	Cash    []*Cash `json:"cash"`
}

// ChangeOutput describes the change Cash that the client wants minted back
// to themselves after a withdrawal.
type ChangeOutput struct {
	Owner  string     `json:"owner"  validate:"required"`
	Amount CipherText `json:"amount" validate:"required"`
}

// ────────────────────── Helpers ──────────────────────

// generateCashID returns a random 32-hex-character string.
func generateCashID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("failed to generate Cash ID: %v", err))
	}
	return fmt.Sprintf("%x", b)
}

// verifyProof checks that the ZK proof stored on the Cash is valid,
// authorising this output to be consumed.
// TODO: implement actual ZK proof verification.
func verifyProof(cash *Cash) error {
	_ = cash // TODO: verify cash.ZkProof
	return nil
}
