package consensus

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/vechain/go-ecvrf"
)

// vrfSuite is the ECVRF ciphersuite used by this chain:
// ECVRF-SECP256K1-SHA256-TAI (suite string 0xFE).
//
// It runs on secp256k1, the same curve as the miner's yu block-signing key
// and the miner's CKB L1 payment key, so a single keypair serves all three
// roles. Identity binding therefore costs nothing: the VRF public key *is*
// the block producer's public key, and blake160 of that same compressed key
// is the CKB lock args of the address that paid on L1.
var vrfSuite = ecvrf.Secp256k1Sha256Tai

// VRFOutputSize is the byte length of the VRF output (beta).
const VRFOutputSize = 32

// CompressedPubkeySize is the byte length of a compressed secp256k1 public key.
// It matches both yu's tendermint-backed secp256k1 keys and the format CKB
// hashes with blake160 to produce a lock's args.
const CompressedPubkeySize = 33

// vrfDomainTag separates VRF inputs from every other message a miner's key
// is asked to sign, so a block signature can never be replayed as a VRF input.
const vrfDomainTag = "invisibook-vrf-input:"

// VRFResult holds an ECVRF-SECP256K1-SHA256-TAI evaluation.
//
// The prover's public key is deliberately absent: verification uses the
// block's MinerPubkey instead. That binds the randomness to the block
// producer, so a miner cannot grind throwaway VRF keys to bias its output.
type VRFResult struct {
	// Output is the 32-byte pseudorandom VRF output (beta).
	Output []byte `json:"output"`
	// Proof is the ECVRF proof (pi) that Output was derived from the input
	// under the prover's key. Unlike a bare signature this proof is unique:
	// for a fixed (key, input) no second valid proof exists.
	Proof []byte `json:"proof"`
}

// VRFProve computes the VRF output and proof for `input` using the miner's
// secp256k1 private key. `privKey` must be on the secp256k1 curve; `input`
// is typically the previous block hash.
func VRFProve(privKey *ecdsa.PrivateKey, input []byte) (*VRFResult, error) {
	beta, pi, err := vrfSuite.Prove(privKey, vrfAlpha(input))
	if err != nil {
		return nil, fmt.Errorf("vrf prove: %w", err)
	}
	return &VRFResult{Output: beta, Proof: pi}, nil
}

// VRFVerify checks a VRF proof against the block producer's public key and
// the original input. `minerPubkey` must be a 33-byte compressed secp256k1
// public key — normally taken straight from block.MinerPubkey.
func VRFVerify(minerPubkey, input []byte, result *VRFResult) bool {
	if result == nil || len(result.Output) != VRFOutputSize {
		return false
	}
	pubKey, err := ParseMinerPubkey(minerPubkey)
	if err != nil {
		return false
	}
	beta, err := vrfSuite.Verify(pubKey, vrfAlpha(input), result.Proof)
	if err != nil {
		return false
	}
	// Accept only if the proof reproduces exactly the claimed output; a miner
	// must not be able to publish a valid proof next to a doctored output.
	return bytes.Equal(beta, result.Output)
}

// ParseMinerPubkey converts a compressed secp256k1 public key into an
// ecdsa.PublicKey on the secp256k1 curve.
// `compressed` must be a 33-byte compressed encoding.
func ParseMinerPubkey(compressed []byte) (*ecdsa.PublicKey, error) {
	if len(compressed) != CompressedPubkeySize {
		return nil, fmt.Errorf("miner pubkey must be %d bytes, got %d", CompressedPubkeySize, len(compressed))
	}
	pubKey, err := secp256k1.ParsePubKey(compressed)
	if err != nil {
		return nil, fmt.Errorf("parse miner pubkey: %w", err)
	}
	return pubKey.ToECDSA(), nil
}

// SecpPrivKeyToECDSA converts the raw scalar behind a yu secp256k1 private
// key into an ecdsa.PrivateKey, so the very same key that signs blocks also
// evaluates the VRF. `raw` must be exactly 32 bytes.
func SecpPrivKeyToECDSA(raw []byte) (*ecdsa.PrivateKey, error) {
	if len(raw) != secp256k1.PrivKeyBytesLen {
		return nil, fmt.Errorf("secp256k1 private key must be %d bytes, got %d", secp256k1.PrivKeyBytesLen, len(raw))
	}
	return secp256k1.PrivKeyFromBytes(raw).ToECDSA(), nil
}

// CompressedPubkey returns the 33-byte compressed encoding of an ecdsa
// public key on secp256k1. This is the exact byte string CKB hashes with
// blake160 to derive a secp256k1_blake160_sighash_all lock's args.
func CompressedPubkey(pubKey *ecdsa.PublicKey) []byte {
	var x, y secp256k1.FieldVal
	x.SetByteSlice(pubKey.X.Bytes())
	y.SetByteSlice(pubKey.Y.Bytes())
	return secp256k1.NewPublicKey(&x, &y).SerializeCompressed()
}

// CompressedPubkeyHex is CompressedPubkey rendered as a lowercase hex string.
func CompressedPubkeyHex(pubKey *ecdsa.PublicKey) string {
	return hex.EncodeToString(CompressedPubkey(pubKey))
}

// vrfAlpha builds the domain-separated VRF input from a raw input.
func vrfAlpha(input []byte) []byte {
	alpha := make([]byte, 0, len(vrfDomainTag)+len(input))
	alpha = append(alpha, vrfDomainTag...)
	return append(alpha, input...)
}
