package core

import (
	"crypto/rand"
	"fmt"
)

// ────────────────────── Domain Models ──────────────────────

// UTXO is the domain model for a single transaction output.
// Amount is an encrypted ciphertext — the plaintext is never revealed on-chain.
// ZkProof is committed at creation (e.g. the deposit bridge proof); it must
// verify successfully before this UTXO can be marked as spent.
type UTXO struct {
	ID      string     `json:"id"`
	Owner   string     `json:"owner"`
	Token   TokenID    `json:"token"`
	Amount  CipherText `json:"amount"`   // encrypted amount
	ZkProof string     `json:"zk_proof"` // proof committed at creation
	Spent   bool       `json:"spent"`
	SpentBy string     `json:"spent_by,omitempty"`
}

// AccountRecord is the response returned by GetAccount.
// Because amounts are ciphertext, no aggregate balance is computed on-chain.
type AccountRecord struct {
	Address string  `json:"address"`
	Token   TokenID `json:"token"`
	UTXOs   []*UTXO `json:"utxos"`
}

// ChangeOutput describes the change UTXO that the client wants minted back
// to themselves after a withdrawal.
type ChangeOutput struct {
	Owner  string     `json:"owner"  validate:"required"`
	Amount CipherText `json:"amount" validate:"required"`
}

// ────────────────────── Helpers ──────────────────────

// generateUTXOID returns a random 32-hex-character string.
func generateUTXOID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("failed to generate UTXO ID: %v", err))
	}
	return fmt.Sprintf("%x", b)
}

// verifySpendProof checks that the ZK proof stored on the UTXO is valid,
// authorising this output to be consumed.
// TODO: implement actual ZK proof verification.
func verifySpendProof(utxo *UTXO) error {
	_ = utxo // TODO: verify utxo.ZkProof
	return nil
}
