package ckb

import (
	"context"
	"fmt"

	ckbtypes "github.com/nervosnetwork/ckb-sdk-go/v2/types"

	"github.com/yu-org/yu/core/types"

	"github.com/invisibook-lab/invisibook/consensus"
)

// SubmitHeader creates one submit cell on L1 carrying `header` in full, and
// returns the transaction's hash.
//
// The header goes on chain in the clear, Extra included, so L1 by itself is a
// record of the chain: anyone reading the cell recomputes the block hash from
// it and knows which L2 block that L1 block dates (ckb_layout.md §5).
//
// The cell is locked to the miner's own key so that the capacity comes back
// once the height is decided (R5.2). Which key is not part of the protocol:
// anyone may anchor anyone's block, because the header is fixed by the block
// and the submitter cannot change what it says (§8.1).
func (c *Client) SubmitHeader(ctx context.Context, header *types.Header) (string, error) {
	// EncodeHeader enforces R5.1's length cap, and being turned away by the
	// script costs a round trip to learn what is knowable here.
	data, err := consensus.EncodeHeader(header)
	if err != nil {
		return "", err
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
		return "", fmt.Errorf("anchoring L2 height %d: %w", header.Height, err)
	}
	return txHash, nil
}

// HeaderOnChain reports whether a submission is in a block on L1's canonical
// chain.
//
// False is not an error: a submission that never made it out of the pool, and
// one an L1 reorg took back, are the same situation from here and have the
// same remedy — send it again. The caller does exactly that.
func (c *Client) HeaderOnChain(ctx context.Context, l1TxHash string) (bool, error) {
	hash, err := parseHash(l1TxHash)
	if err != nil {
		return false, fmt.Errorf("tx hash %q: %w", l1TxHash, err)
	}
	// Asked without the committed-only filter on purpose: a submission
	// waiting in the pool has to be told apart from one L1 has never heard
	// of, and that filter reports both as nothing.
	tx, err := c.rpc.GetTransaction(ctx, hash, nil, nil)
	if err != nil {
		return false, fmt.Errorf("fetching tx %s: %w", l1TxHash, err)
	}
	if tx == nil || tx.TxStatus == nil {
		return false, nil
	}

	switch tx.TxStatus.Status {
	case ckbtypes.TransactionStatusCommitted:
		return true, nil
	case ckbtypes.TransactionStatusPending, ckbtypes.TransactionStatusProposed:
		return false, fmt.Errorf("%w: tx %s", consensus.ErrSubmissionPending, l1TxHash)
	default:
		// Rejected or unknown: this submission is not coming back, and the
		// caller is right to send another.
		return false, nil
	}
}
