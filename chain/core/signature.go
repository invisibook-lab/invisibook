package core

import (
	"encoding/hex"
	"fmt"

	"github.com/yu-org/yu/core/keypair"
)

const (
	// OwnerPubkeySize is a compressed secp256k1 public key: 33 bytes, 66 hex
	// chars. Owner keys, miner block-signing keys and CKB payment keys are all
	// on this curve and in this encoding, so one key serves every role.
	OwnerPubkeySize = 33
	// OwnerSignatureSize is the byte length of a compact secp256k1 signature.
	OwnerSignatureSize = 64
)

// VerifyOwnerSignature checks `sigHex` over `message` against `pubkeyHex`.
//
// Verification goes through yu's own secp256k1 key type, so an owner signature
// and a block signature are checked by exactly the same code.
// `pubkeyHex` is a compressed public key as hex with no type tag; `sigHex` is
// a compact signature as hex; `message` is the exact byte string signed.
func VerifyOwnerSignature(pubkeyHex string, message, sigHex string) error {
	pubkeyBytes, err := hex.DecodeString(pubkeyHex)
	if err != nil {
		return fmt.Errorf("pubkey is not hex: %w", err)
	}
	if len(pubkeyBytes) != OwnerPubkeySize {
		return fmt.Errorf("pubkey must be %d bytes, got %d", OwnerPubkeySize, len(pubkeyBytes))
	}
	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil {
		return fmt.Errorf("signature is not hex: %w", err)
	}
	if len(sigBytes) != OwnerSignatureSize {
		return fmt.Errorf("signature must be %d bytes, got %d", OwnerSignatureSize, len(sigBytes))
	}

	if !keypair.SecpPubkeyFromBytes(pubkeyBytes).VerifySignature([]byte(message), sigBytes) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

// ValidOwnerPubkey reports whether `pubkeyHex` is a well-formed owner key.
func ValidOwnerPubkey(pubkeyHex string) error {
	pubkeyBytes, err := hex.DecodeString(pubkeyHex)
	if err != nil {
		return fmt.Errorf("pubkey is not hex: %w", err)
	}
	if len(pubkeyBytes) != OwnerPubkeySize {
		return fmt.Errorf("pubkey must be %d bytes, got %d", OwnerPubkeySize, len(pubkeyBytes))
	}
	return nil
}
