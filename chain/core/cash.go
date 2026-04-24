package core

import (
	"crypto/sha256"
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
	Pubkey  string     `json:"pubkey"`   // owner's raw ed25519 public key (64-char hex)
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
	Pubkey string  `json:"pubkey"`
	Token  TokenID `json:"token"`
	Cash   []*Cash `json:"cash"`
}

// ChangeOutput describes the change Cash that the client wants minted back
// to themselves after a withdrawal.
type ChangeOutput struct {
	Pubkey string     `json:"pubkey" validate:"required"`
	Amount CipherText `json:"amount" validate:"required"`
}

// ────────────────────── Helpers ──────────────────────

// computeCashID derives a deterministic Cash ID from its contents: SHA256(pubkey + token + amount).
func computeCashID(pubkey string, token TokenID, amount CipherText) string {
	h := sha256.New()
	h.Write([]byte(pubkey))
	h.Write([]byte(token))
	h.Write([]byte(amount))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// verifyProof checks that the ZK proof stored on the Cash is valid,
// authorising this output to be consumed.
// TODO: implement actual ZK proof verification.
func verifyProof(cash *Cash) error {
	_ = cash // TODO: verify cash.ZkProof
	return nil
}
