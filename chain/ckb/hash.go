package ckb

import (
	"github.com/nervosnetwork/ckb-sdk-go/v2/crypto/blake2b"
)

// blake160 returns CKB's lock args for a public key: the first 20 bytes of
// its blake2b-256 under CKB's personalization.
//
// consensus.Blake160 computes the same thing for the comparison V7's first
// item makes. It stays there rather than being imported from here because
// that package must be able to make the comparison without a CKB client —
// this one is used while building transactions, where the SDK's own
// implementation is already at hand.
func blake160(pubkey []byte) []byte {
	return blake2b.Blake160(pubkey)
}
