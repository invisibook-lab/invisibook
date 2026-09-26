package consensus

import (
	"errors"
	"fmt"

	"github.com/yu-org/yu/common"
	"github.com/yu-org/yu/core/keypair"
	"github.com/yu-org/yu/core/types"
)

// A block makes three claims that have to be checked as one chain, because
// each link is only worth as much as the one before it:
//
//	Txns ──①──▶ TxnRoot ──②──▶ Hash ──③──▶ MinerSignature
//
// The producer's key signs only the hash; the hash covers only the header;
// the header pins the transactions only through their root. Check any link
// alone and the chain stays open at the other end: verify the signature
// without recomputing the hash, and a block's contents can be swapped under a
// signature that still verifies; recompute the hash without checking the
// root, and the transactions can be swapped under a hash that still matches.
//
// This carries more weight in PoB than in a chain with a fixed producer. A
// block's VRF proof is bound to `prev_hash` and its payment to
// `(amount, random)` — neither says anything about which transactions the
// block carries, and both become public at reveal time. Without the chain
// below, anyone could take a miner's published proof and payment, attach
// whatever transactions they liked, and get a block that clears every other
// check with the same `goal` as the original. Whoever buys a height would
// then not be the one deciding what goes in it.

var (
	// ErrTxnRootMismatch reports ①: the transactions carried are not the ones
	// the header's root commits to.
	ErrTxnRootMismatch = errors.New("transactions do not match the block's txn root")
	// ErrBlockHashMismatch reports ②: the hash is not the one the block's own
	// contents produce.
	ErrBlockHashMismatch = errors.New("block hash does not match the block's contents")
	// ErrBlockUnsigned reports ③: the producer's signature is absent or does
	// not verify against the block hash.
	ErrBlockUnsigned = errors.New("block signature does not verify against the producer's key")
)

// blockHashInput returns the bytes a block's hash is taken over.
//
// Exactly three things are left out, and each for its own reason:
//
//   - Hash, because it is the result. It is a field of the header and so goes
//     into Encode like any other, which means hashing a block that already
//     carries a hash would feed the old value back in. A producer never
//     notices — it hashes once, while the field is still zero — but a
//     verifier recomputing afterwards would get a different answer every
//     time, and no block would ever verify.
//   - MinerSignature, because it signs the result.
//   - Txns, which TxnRoot stands in for. That substitution is the whole
//     reason ① has to be checked separately.
//
// Everything else is in, MinerPubkey included: the producer's identity belongs
// under the signature, or a block could be relabelled with another miner's key
// without disturbing the hash at all.
//
// `block` is not modified — the copy is what gets stripped.
func blockHashInput(block *types.Block) ([]byte, error) {
	if block == nil || block.Header == nil {
		return nil, errors.New("block has no header")
	}
	// Block embeds *Header, so copying the block alone would still share the
	// header, and clearing a field would reach back into the caller's block.
	header := *block.Header
	header.Hash = common.Hash{}
	header.MinerSignature = nil

	return (&types.Block{Header: &header}).Encode()
}

// ComputeBlockHash returns the hash a block's contents imply.
//
// Producing and verifying both go through this one function, so the two
// cannot drift apart: what a producer hashes is by construction what a
// verifier recomputes. Leaving that agreement to the order of statements in
// the producer — which field happens to be set when — is what makes it fragile.
func ComputeBlockHash(block *types.Block) (common.Hash, error) {
	raw, err := blockHashInput(block)
	if err != nil {
		return common.Hash{}, err
	}
	return common.BytesToHash(common.Sha256(raw)), nil
}

// SealBlock fills in everything a block claims about itself and signs it: the
// root over `txns`, the consensus data in Extra, the producer's key, the hash
// over all of that, and the producer's signature over the hash.
//
// It is the exact counterpart of VerifyBlockIntegrity — what this writes is
// what that reads back — and the two live together so they cannot drift. The
// order these fields are set in decides what the hash ends up covering, which
// is a decision too easy to break silently to leave sitting in the middle of
// a block production routine.
//
// `block` needs its height and parent already set; everything else is written
// here.
func SealBlock(block *types.Block, txns types.SignedTxns, cdata *ConsensusData, pub keypair.PubKey, priv keypair.PrivKey) error {
	if block == nil || block.Header == nil {
		return errors.New("block has no header")
	}

	root, err := types.MakeTxnRoot(txns)
	if err != nil {
		return fmt.Errorf("making the txn root: %w", err)
	}
	block.TxnRoot = root

	extra, err := EncodeConsensusData(cdata)
	if err != nil {
		return fmt.Errorf("encoding consensus data: %w", err)
	}
	block.Extra = extra

	// Before the hash is taken: the signature has to cover who produced this
	// block, not merely what is in it.
	block.MinerPubkey = pub.Bytes()

	if block.Hash, err = ComputeBlockHash(block); err != nil {
		return fmt.Errorf("hashing the block: %w", err)
	}
	if block.MinerSignature, err = priv.SignData(block.Hash.Bytes()); err != nil {
		return fmt.Errorf("signing the block: %w", err)
	}

	// The transactions go on last, and only because the hash reaches them
	// through TxnRoot rather than directly — attaching them cannot disturb it.
	block.SetTxns(txns)
	return nil
}

// VerifyBlockIntegrity checks that a block's producer really authored the
// transactions the block carries: ① the transactions match the root, ② the
// hash matches the contents, ③ the producer signed that hash.
//
// It takes one block and nothing else — no chain, no store, no network — so
// any path that accepts a block from elsewhere can apply it, and it can be
// tested on its own.
func VerifyBlockIntegrity(block *types.Block) error {
	if block == nil || block.Header == nil {
		return errors.New("block has no header")
	}

	// ① Without this the entire header — hash and signature included — can be
	// lifted off a real block and reused over different transactions, because
	// the hash never covers the transactions themselves.
	root, err := types.MakeTxnRoot(block.Txns)
	if err != nil {
		return fmt.Errorf("recomputing the txn root: %w", err)
	}
	if root != block.TxnRoot {
		return fmt.Errorf("%w: the transactions give %s, the header claims %s",
			ErrTxnRootMismatch, root.String(), block.TxnRoot.String())
	}

	// ② The hash must be the one those contents produce.
	computed, err := ComputeBlockHash(block)
	if err != nil {
		return fmt.Errorf("recomputing the block hash: %w", err)
	}
	if computed != block.Hash {
		return fmt.Errorf("%w: the contents give %s, the header claims %s",
			ErrBlockHashMismatch, computed.String(), block.Hash.String())
	}

	// ③ The only step that ties an identity to the block's contents at all.
	//
	// PoB stores the producer's key as a bare 33-byte compressed secp256k1
	// point — the same encoding ParseMinerPubkey and the VRF check read.
	// keypair.PubKeyFromBytes cannot be used here: it reads the first byte as
	// a key-type tag, which a compressed point does not carry.
	//
	// Malformed keys need no separate guard. VerifySignature parses the point
	// itself and reports false when it cannot, so a key of the wrong length
	// is refused here like any other key that does not verify.
	pubkey := keypair.SecpPubkeyFromBytes(block.MinerPubkey)
	if !pubkey.VerifySignature(block.Hash.Bytes(), block.MinerSignature) {
		return fmt.Errorf("%w: producer %x", ErrBlockUnsigned, block.MinerPubkey)
	}
	return nil
}
