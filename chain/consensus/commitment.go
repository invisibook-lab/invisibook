package consensus

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/iden3/go-iden3-crypto/constants"
	"github.com/iden3/go-iden3-crypto/poseidon"

	"github.com/yu-org/yu/common"
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

// CommitBlockHash computes the commitment a miner posts on L1 for one of its
// blocks:
//
//	SHA256(block_hash || random)
//
// The block hash is the only thing worth committing to. It already determines
// the entire block — height, goal, VRF output, parent link, every transaction
// — so binding any of those in alongside it would commit to the same facts
// twice. Revealing `(blockHash, random)` is enough: anyone holding the block
// checks the opening against the commitment, and the block against its hash.
//
// This is also all that reaches L1. Submitting the header and the score in the
// clear would hand the L1 block producer exactly what it needs to censor
// selectively — see proof_of_buy.md §9.6 — so what goes on chain is a value
// nobody can read and nobody but the miner can open.
//
// SHA256 rather than Poseidon, because nothing ever opens this commitment
// inside a circuit: CKB records it and verifies nothing, and the reveal is
// checked by L2 nodes hashing two byte strings. Poseidon would buy
// zk-friendliness no one uses and charge for it — its inputs are BN254 field
// elements, so a 32-byte hash would have to be split in half and both layers
// would then have to agree on the split and on Poseidon's parameterisation.
// PoseidonCommit stays Poseidon for the opposite reason: the payment openings
// it commits to do go into the budget proof circuit.
//
// `randomHex` must be 64 hex characters.
func CommitBlockHash(blockHash common.Hash, randomHex string) (string, error) {
	random, err := decodeRandomBytes(randomHex)
	if err != nil {
		return "", err
	}

	raw := blockHash.Bytes()
	preimage := make([]byte, 0, len(raw)+len(random))
	preimage = append(preimage, raw...)
	preimage = append(preimage, random...)

	sum := sha256.Sum256(preimage)
	return hex.EncodeToString(sum[:]), nil
}

// NewRandomHex returns a fresh 32-byte blinding factor as 64 hex characters.
// A commitment is only hiding for as long as this value is unpredictable, so
// it comes from crypto/rand and is never derived from the block it hides.
func NewRandomHex() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("drawing a blinding factor: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

// decodeRandomBytes parses a 64-char hex blinding factor into its 32 raw
// bytes. Unlike decodeRandom it reduces nothing: this value is hashed as a
// byte string, not interpreted as a field element.
func decodeRandomBytes(randomHex string) ([]byte, error) {
	if len(randomHex) != RandomHexLen {
		return nil, fmt.Errorf("random must be %d hex chars, got %d", RandomHexLen, len(randomHex))
	}
	raw, err := hex.DecodeString(randomHex)
	if err != nil {
		return nil, fmt.Errorf("decoding random %q: %w", randomHex, err)
	}
	return raw, nil
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
