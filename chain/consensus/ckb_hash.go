package consensus

import (
	"fmt"

	blake2b "github.com/minio/blake2b-simd"
)

// ckbHashPersonal is the personalization CKB's hash function is defined with.
//
// It is part of the definition, not a decoration: the same bytes under a
// different personalization produce a different digest, so getting this
// string wrong yields hashes that look fine and match nothing on chain.
const ckbHashPersonal = "ckb-default-hash"

// ckbHashSize is the digest size CKB hashes at.
const ckbHashSize = 32

// blake160Len is the length of the args in CKB's standard
// secp256k1_blake160 lock: the leading bytes of the key's CKB hash.
const blake160Len = 20

// Blake160 returns the CKB lock args for a public key — the first 20 bytes of
// CKB's blake2b-256 over it.
//
// The L2 side has to know this encoding because V7 compares identities across
// the two chains: the budget cell's lock args on CKB against the producer key
// inside an L2 block. There is no making that comparison without agreeing on
// how CKB derives the one from the other.
//
// `pubkey` is the compressed secp256k1 key, as block.MinerPubkey carries it.
func Blake160(pubkey []byte) ([]byte, error) {
	h, err := blake2b.New(&blake2b.Config{
		Size:   ckbHashSize,
		Person: []byte(ckbHashPersonal),
	})
	if err != nil {
		return nil, fmt.Errorf("initialising the CKB hash: %w", err)
	}
	if _, err := h.Write(pubkey); err != nil {
		return nil, fmt.Errorf("hashing the public key: %w", err)
	}
	return h.Sum(nil)[:blake160Len], nil
}
