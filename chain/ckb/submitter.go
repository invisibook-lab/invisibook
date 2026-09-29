package ckb

import (
	"context"
	"encoding/hex"
	"fmt"

	ckbtypes "github.com/nervosnetwork/ckb-sdk-go/v2/types"

	"github.com/invisibook-lab/invisibook/consensus"
)

// SubmitCommitment creates one commit cell on L1 carrying `commitment` and
// nothing else, and returns the transaction's hash.
//
// Nothing else is what makes this worth doing. A transaction's data is as
// legible to the L1 block producer packing it as it is to anyone, so any
// field the L2 could put here — height, goal, producer — is a field a censor
// could sort on (proof_of_buy.md §9.6). What reaches L1 is 32 bytes that look
// like every other 32 bytes.
//
// The cell is locked to the miner's own key so that the capacity comes back
// once the height is decided (R5.2). Which key is not part of the protocol:
// anyone may anchor anyone's block, because a commitment binds its contents
// and the submitter has nothing to gain by lying about them (§8.1).
func (c *Client) SubmitCommitment(ctx context.Context, commitment *consensus.BlockCommitment) (string, error) {
	if commitment == nil {
		return "", fmt.Errorf("no commitment to submit")
	}
	data, err := hex.DecodeString(commitment.Commitment)
	if err != nil {
		return "", fmt.Errorf("decoding the commitment for height %d: %w", commitment.L2BlockHeight, err)
	}
	// R5.1 refuses anything else, and being turned away by the script costs a
	// round trip to learn what is knowable here.
	if len(data) != commitmentLen {
		return "", fmt.Errorf("commitment for height %d is %d bytes, want %d",
			commitment.L2BlockHeight, len(data), commitmentLen)
	}

	b, err := c.newBuilder(ctx)
	if err != nil {
		return "", err
	}
	output := &ckbtypes.CellOutput{Lock: c.minerLock(), Type: c.set.commitScript}
	// The cell holds the least capacity CKB will let it: this is a deposit
	// locked up for as long as the cell lives, and the miner takes it back
	// when it reclaims the cell, so anything above the floor is capital idle
	// for no reason.
	output.Capacity = output.OccupiedCapacity(data)
	b.AddOutput(output, data)
	b.AddCellDep(c.set.commitDep)

	txHash, err := c.send(ctx, b)
	if err != nil {
		return "", fmt.Errorf("anchoring L2 height %d: %w", commitment.L2BlockHeight, err)
	}
	return txHash, nil
}

// CommitmentOnChain reports where a submission landed, or nil when it is not
// on an L1 block at all.
//
// Nil is not an error: a submission that never made it out of the pool, and
// one an L1 reorg took back, are the same situation from here and have the
// same remedy — send it again. The caller does exactly that.
//
// The location is what a verifier needs to find this commitment later without
// scanning L1, and the block hash is what dates the anchoring. §8.2 turns on
// that date: a fork bought after the fact can only carry commitments anchored
// recently, which is what tells it apart from one that was really there.
func (c *Client) CommitmentOnChain(ctx context.Context, l1TxHash string) (*consensus.L1Location, error) {
	hash, err := parseHash(l1TxHash)
	if err != nil {
		return nil, fmt.Errorf("tx hash %q: %w", l1TxHash, err)
	}
	// Asked without the committed-only filter on purpose: a submission
	// waiting in the pool has to be told apart from one L1 has never heard
	// of, and that filter reports both as nothing.
	tx, err := c.rpc.GetTransaction(ctx, hash, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("fetching tx %s: %w", l1TxHash, err)
	}
	if tx == nil || tx.TxStatus == nil {
		return nil, nil
	}

	switch tx.TxStatus.Status {
	case ckbtypes.TransactionStatusCommitted:
	case ckbtypes.TransactionStatusPending, ckbtypes.TransactionStatusProposed:
		return nil, fmt.Errorf("%w: tx %s", consensus.ErrSubmissionPending, l1TxHash)
	default:
		// Rejected or unknown: this submission is not coming back, and the
		// caller is right to send another.
		return nil, nil
	}

	blockHash := tx.TxStatus.BlockHash
	if blockHash == nil || tx.Transaction == nil {
		return nil, nil
	}

	idx, err := c.txIndexIn(ctx, tx, *blockHash, l1TxHash)
	if err != nil {
		return nil, err
	}
	return &consensus.L1Location{BlockHash: blockHash.String(), TxIdx: idx}, nil
}

// txIndexIn returns the position of `tx` inside the block that committed it.
//
// A current node reports the index in the transaction's status and no further
// call is needed. Older ones leave it out, and then the block itself has to
// be read — worth the round trip rather than a hard requirement on the node's
// version, since without the index a verifier cannot locate the commitment at
// all.
func (c *Client) txIndexIn(ctx context.Context, tx *ckbtypes.TransactionWithStatus, blockHash ckbtypes.Hash, l1TxHash string) (uint32, error) {
	if tx.TxStatus.TxIndex != nil {
		return uint32(*tx.TxStatus.TxIndex), nil
	}

	block, err := c.rpc.GetBlock(ctx, blockHash)
	if err != nil {
		return 0, fmt.Errorf("locating tx %s inside L1 block %s: %w", l1TxHash, blockHash, err)
	}
	if block != nil {
		for i, blockTx := range block.Transactions {
			if blockTx.Hash == tx.Transaction.Hash {
				return uint32(i), nil
			}
		}
	}
	return 0, fmt.Errorf("tx %s is reported as committed in L1 block %s but is not in it",
		l1TxHash, blockHash)
}
