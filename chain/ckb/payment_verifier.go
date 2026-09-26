package ckb

import (
	"bytes"
	"context"
	"fmt"
	"math/big"

	"github.com/yu-org/yu/common"

	"github.com/invisibook-lab/invisibook/consensus"
)

// FetchPrepayment returns the plaintext total the miner moved into the mining
// addr in `txHash`.
//
// Plaintext because a capacity transfer is public on CKB and there is nothing
// to gain by hiding what anyone can add up (ckb_layout.md §3). What stays
// hidden is how that total is divided among heights, and that is what
// FetchAllocation reads.
//
// `minerPubkey` is not merely the key this answer is filed under: the budget
// cell's lock is checked against it, so a miner cannot point at somebody
// else's prepayment and bid with it.
func (c *Client) FetchPrepayment(ctx context.Context, txHash, minerPubkey string) (*big.Int, error) {
	_, data, err := c.ownedBudget(ctx, txHash, minerPubkey)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetUint64(data.Prepaid), nil
}

// FetchAllocation returns the commitment the miner posted for `height`, and
// the L1 block the allocation table was written in.
//
// The block number is what V4 measures: an allocation has to predate the
// anchoring of the block spending it by PaymentLeadBlocks, and since the
// whole table is written in one transaction that never changes afterwards
// (R3.1), the transaction's own block dates every entry in it.
func (c *Client) FetchAllocation(ctx context.Context, txHash, minerPubkey string, height common.BlockNum) (*consensus.Allocation, error) {
	blockNumber, data, err := c.ownedBudget(ctx, txHash, minerPubkey)
	if err != nil {
		return nil, err
	}

	// The conversion is exact, not a narrowing: yu's BlockNum is a uint32 and
	// so is the height field in the allocation table, which is why the table
	// can encode every height the L2 will ever have.
	commitment, ok := data.Lookup(uint32(height))
	if !ok {
		return nil, fmt.Errorf("%w: tx_hash=%s height=%d", consensus.ErrPaymentNotFound, txHash, height)
	}

	return &consensus.Allocation{
		Commitment:    commitment,
		L1BlockNumber: blockNumber,
	}, nil
}

// ownedBudget reads the budget cell `txHash` created and confirms it belongs
// to `minerPubkey`, returning the L1 block it was written in and its table.
//
// The ownership check is the foundation of the whole payment path, not a
// refinement of it. Both public methods here are *told* which miner to look
// up, so without it a miner that names itself gets back a commitment it chose
// — it would invent a commitment, supply an opening that matches, and V3
// would compare the miner's own story against itself while `amount`, and with
// it `goal`, grew to whatever it liked.
//
// `minerPubkey` is the hex-encoded compressed secp256k1 key.
func (c *Client) ownedBudget(ctx context.Context, txHash, minerPubkey string) (uint64, *BudgetData, error) {
	pubkey, err := parseBytes(minerPubkey)
	if err != nil {
		return 0, nil, fmt.Errorf("miner pubkey %q: %w", minerPubkey, err)
	}
	want, err := consensus.Blake160(pubkey)
	if err != nil {
		return 0, nil, err
	}

	blockNumber, output, data, err := c.budgetCell(ctx, txHash)
	if err != nil {
		return 0, nil, err
	}

	// R3.5 guarantees the lock is the standard sighash lock, which is what
	// makes "the args are a public key's blake160" a safe reading. The script
	// would have refused the cell's creation otherwise, but this node is the
	// one about to act on the answer, so it checks rather than assumes.
	if output.Lock.CodeHash != c.set.sighashCodeHash {
		return 0, nil, fmt.Errorf("%w: the budget cell in tx_hash=%s is not under the standard sighash lock",
			consensus.ErrPaymentNotFound, txHash)
	}
	if !bytes.Equal(output.Lock.Args, want) {
		return 0, nil, fmt.Errorf("%w: the budget cell in tx_hash=%s is owned by %x, not by %s",
			consensus.ErrPaymentNotFound, txHash, output.Lock.Args, minerPubkey)
	}
	return blockNumber, data, nil
}
