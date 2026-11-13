package consensus

import (
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/iden3/go-iden3-crypto/constants"
	"github.com/iden3/go-iden3-crypto/poseidon"
)

// CommitmentHexLen is the length of a commitment rendered as big-endian hex:
// a BN254 field element padded to 32 bytes.
const CommitmentHexLen = 64

// RandomHexLen is the length of a blinding factor rendered as hex. The opening
// of a commitment is always a 32-byte value.
const RandomHexLen = 64

// PoseidonCommit computes `Poseidon(2)([amount, random])` over the BN254
// scalar field and renders it as a lowercase 64-char big-endian hex string.
//
// This is the same commitment shape the wallet circuits use, so a value
// committed on L1 by the miner's wallet and a value recomputed here agree
// byte for byte. `amount` must be non-nil and within the field; `randomHex`
// must be 64 hex characters, and is reduced modulo the field order exactly as
// the Rust side does.
func PoseidonCommit(amount *big.Int, randomHex string) (string, error) {
	if amount == nil {
		return "", fmt.Errorf("amount is missing")
	}
	if amount.Sign() < 0 {
		return "", fmt.Errorf("amount must not be negative")
	}
	random, err := decodeRandom(randomHex)
	if err != nil {
		return "", err
	}
	commitment, err := poseidon.Hash([]*big.Int{amount, random})
	if err != nil {
		return "", fmt.Errorf("poseidon hash: %w", err)
	}
	return fmt.Sprintf("%064x", commitment), nil
}

// decodeRandom parses a 64-char hex blinding factor into a field element,
// reducing it modulo the BN254 scalar field order the way the wallet does
// when it builds the same commitment.
func decodeRandom(randomHex string) (*big.Int, error) {
	if len(randomHex) != RandomHexLen {
		return nil, fmt.Errorf("random must be %d hex chars, got %d", RandomHexLen, len(randomHex))
	}
	raw, err := hex.DecodeString(randomHex)
	if err != nil {
		return nil, fmt.Errorf("decoding random %q: %w", randomHex, err)
	}
	return new(big.Int).Mod(new(big.Int).SetBytes(raw), constants.Q), nil
}
