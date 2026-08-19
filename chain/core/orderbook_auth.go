package core

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
)

// verifyOrderOwnerSignature authenticates a round-scoped orderbook action
// against the ed25519 owner key committed in the order row.
func verifyOrderOwnerSignature(order *Order, message []byte, signature string) error {
	pubkey, err := hex.DecodeString(order.Pubkey)
	if err != nil || len(pubkey) != ed25519.PublicKeySize {
		return fmt.Errorf("order %s has invalid owner pubkey", order.ID)
	}
	sig, err := hex.DecodeString(signature)
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(pubkey, message, sig) {
		return fmt.Errorf("owner signature verification failed for order %s", order.ID)
	}
	return nil
}
