package ckb

import (
	"context"
	"encoding/hex"
	"fmt"

	ckbtypes "github.com/nervosnetwork/ckb-sdk-go/v2/types"

	"github.com/invisibook-lab/invisibook/consensus"
)

// CommitmentAt returns the commitment anchored at `loc`, and the height of
// the L1 block holding it.
//
// It implements V1 of ckb_layout.md §6: locate the L1 block by hash, take the
// transaction at the given index, and read the 32 bytes out of the commit
// cell it created.
//
// The block is named by hash and checked against L1's canonical chain, which
// is the whole reason a reveal carries a hash rather than a height. A height
// would still resolve after a reorg — to whatever block replaced the original
// — and a commitment that went away with the old block would appear to stand.
func (c *Client) CommitmentAt(ctx context.Context, loc *consensus.L1Location) (*consensus.AnchoredCommitment, error) {
	if loc == nil {
		return nil, fmt.Errorf("no location to read")
	}
	blockHash, err := parseHash(loc.BlockHash)
	if err != nil {
		return nil, fmt.Errorf("L1 block hash %q: %w", loc.BlockHash, err)
	}

	block, err := c.rpc.GetBlock(ctx, blockHash)
	if err != nil {
		return nil, fmt.Errorf("fetching L1 block %s: %w", loc.BlockHash, err)
	}
	if block == nil || block.Header == nil {
		return nil, fmt.Errorf("%w: L1 does not know block %s", consensus.ErrNotOnChain, loc.BlockHash)
	}

	// Knowing a block is not the same as following it: a node keeps blocks
	// from abandoned forks. Asking L1 which block it has at this height, and
	// requiring the answer to be this one, is what turns "known" into "on the
	// chain L1 currently follows".
	canonical, err := c.rpc.GetBlockHash(ctx, block.Header.Number)
	if err != nil {
		return nil, fmt.Errorf("checking whether L1 block %s is canonical: %w", loc.BlockHash, err)
	}
	if canonical == nil || *canonical != blockHash {
		return nil, fmt.Errorf("%w: block %s at height %d was replaced",
			consensus.ErrNotOnChain, loc.BlockHash, block.Header.Number)
	}

	if int(loc.TxIdx) >= len(block.Transactions) {
		return nil, fmt.Errorf("L1 block %s holds %d transactions, none at index %d",
			loc.BlockHash, len(block.Transactions), loc.TxIdx)
	}
	tx := block.Transactions[loc.TxIdx]

	// One transaction may create several commit cells, so locating the
	// transaction is not the end of it — hence the scan over its outputs.
	// It is a handful of comparisons, which is why §5 declines to spend a
	// field on an output index.
	idx := findCellByType(tx, c.set.commitScript)
	if idx < 0 {
		return nil, fmt.Errorf("transaction %d in L1 block %s creates no commit cell",
			loc.TxIdx, loc.BlockHash)
	}
	data := tx.OutputsData[idx]
	if len(data) != commitmentLen {
		return nil, fmt.Errorf("commit cell in L1 block %s carries %d bytes, want %d",
			loc.BlockHash, len(data), commitmentLen)
	}

	return &consensus.AnchoredCommitment{
		Commitment: hex.EncodeToString(data),
		L1Height:   block.Header.Number,
	}, nil
}

// BudgetOwner returns the lock args of the budget cell `txHash` created.
//
// It implements the lookup behind V7's first item. The args are returned raw:
// CKB's standard lock carries the blake160 of a public key rather than the
// key, so the comparison against a block's producer belongs to the caller,
// which has the key to hash.
func (c *Client) BudgetOwner(ctx context.Context, txHash string) ([]byte, error) {
	_, output, _, err := c.budgetCell(ctx, txHash)
	if err != nil {
		return nil, err
	}
	return output.Lock.Args, nil
}

// budgetCell locates the budget cell a transaction created, returning the
// transaction's block number, the cell itself and its decoded data.
//
// It is the one lookup behind every read of a prepayment: the owner check,
// the total and the per-height allocation all come out of the same cell, and
// doing it once here keeps them from disagreeing about which cell that is.
//
// A transaction that created no budget cell is reported as ErrPaymentNotFound
// rather than as a failure — a miner naming a transaction that holds no
// prepayment is making a claim that is simply untrue, not breaking anything.
func (c *Client) budgetCell(ctx context.Context, txHash string) (uint64, *ckbtypes.CellOutput, *BudgetData, error) {
	tx, err := c.fetchTx(ctx, txHash)
	if err != nil {
		return 0, nil, nil, err
	}
	if tx == nil {
		return 0, nil, nil, fmt.Errorf("%w: tx_hash=%s is not committed on L1",
			consensus.ErrPaymentNotFound, txHash)
	}

	idx := findCellByType(tx.Transaction, c.set.budgetScript)
	if idx < 0 {
		return 0, nil, nil, fmt.Errorf("%w: no budget cell in tx_hash=%s",
			consensus.ErrPaymentNotFound, txHash)
	}

	data, err := DecodeBudgetData(tx.Transaction.OutputsData[idx])
	if err != nil {
		return 0, nil, nil, fmt.Errorf("reading the budget cell in tx_hash=%s: %w", txHash, err)
	}

	var blockNumber uint64
	if tx.TxStatus.BlockNumber != nil {
		blockNumber = *tx.TxStatus.BlockNumber
	}
	return blockNumber, tx.Transaction.Outputs[idx], data, nil
}
