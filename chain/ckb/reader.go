package ckb

import (
	"context"
	"fmt"

	ckbtypes "github.com/nervosnetwork/ckb-sdk-go/v2/types"

	"github.com/invisibook-lab/invisibook/consensus"
)

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
