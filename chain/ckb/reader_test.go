package ckb

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	ckbtypes "github.com/nervosnetwork/ckb-sdk-go/v2/types"

	"github.com/invisibook-lab/invisibook/consensus"
)

// commitTx builds a transaction whose output `idx` is a commit cell holding
// `commitment`, with a decoy cell in front of it so that locating the
// transaction is visibly not the same as locating the cell.
func commitTx(c *Client, commitment []byte) *ckbtypes.Transaction {
	return &ckbtypes.Transaction{
		Hash: ckbtypes.HexToHash(hashOf(0x55)),
		Outputs: []*ckbtypes.CellOutput{
			{Capacity: 100, Lock: c.minerLock()},
			{Capacity: 200, Lock: c.minerLock(), Type: c.set.commitScript},
		},
		OutputsData: [][]byte{nil, commitment},
	}
}

// blockWith wraps transactions in a block at `number`.
func blockWith(number uint64, fill byte, txs ...*ckbtypes.Transaction) *ckbtypes.Block {
	return &ckbtypes.Block{
		Header:       &ckbtypes.Header{Hash: ckbtypes.HexToHash(hashOf(fill)), Number: number},
		Transactions: txs,
	}
}

func TestCommitmentAt(t *testing.T) {
	node := newFakeNode()
	client := testClient(t, node)

	commitment := bytes32(0xab)
	block := blockWith(4200, 0x71, &ckbtypes.Transaction{Hash: ckbtypes.HexToHash(hashOf(0x01))}, commitTx(client, commitment))
	hash := node.addBlock(block, true)

	got, err := client.CommitmentAt(context.Background(), &consensus.L1Location{BlockHash: hash.String(), TxIdx: 1})
	if err != nil {
		t.Fatalf("reading the anchored commitment: %v", err)
	}
	if got.Commitment != hex.EncodeToString(commitment) {
		t.Fatalf("commitment reads back as %s, want %s", got.Commitment, hex.EncodeToString(commitment))
	}
	// The height is as much the point as the commitment: §8.2 tells a fork
	// that was really there from one bought later by when it was anchored.
	if got.L1Height != 4200 {
		t.Fatalf("anchored at L1 height %d, want 4200", got.L1Height)
	}
}

// A node keeps blocks from forks it no longer follows. This is why a reveal
// names the L1 block by hash: a height would resolve to whatever replaced it
// and the commitment would appear to stand.
func TestCommitmentAtRejectsOrphanedBlock(t *testing.T) {
	node := newFakeNode()
	client := testClient(t, node)

	orphan := blockWith(4200, 0x71, commitTx(client, bytes32(0xab)))
	hash := node.addBlock(orphan, false)
	// Something else is what L1 follows at that height now.
	node.canonical[4200] = ckbtypes.HexToHash(hashOf(0x72))

	_, err := client.CommitmentAt(context.Background(), &consensus.L1Location{BlockHash: hash.String(), TxIdx: 0})
	if !errors.Is(err, consensus.ErrNotOnChain) {
		t.Fatalf("orphaned block gave %v, want ErrNotOnChain", err)
	}
}

func TestCommitmentAtRejectsUnknownBlock(t *testing.T) {
	client := testClient(t, newFakeNode())

	_, err := client.CommitmentAt(context.Background(), &consensus.L1Location{BlockHash: hashOf(0x99), TxIdx: 0})
	if !errors.Is(err, consensus.ErrNotOnChain) {
		t.Fatalf("unknown block gave %v, want ErrNotOnChain", err)
	}
}

func TestCommitmentAtRejectsMalformedAnchor(t *testing.T) {
	node := newFakeNode()
	client := testClient(t, node)

	plain := &ckbtypes.Transaction{
		Hash:        ckbtypes.HexToHash(hashOf(0x02)),
		Outputs:     []*ckbtypes.CellOutput{{Capacity: 100, Lock: client.minerLock()}},
		OutputsData: [][]byte{nil},
	}
	short := &ckbtypes.Transaction{
		Hash:        ckbtypes.HexToHash(hashOf(0x03)),
		Outputs:     []*ckbtypes.CellOutput{{Capacity: 100, Lock: client.minerLock(), Type: client.set.commitScript}},
		OutputsData: [][]byte{{1, 2, 3}},
	}
	hash := node.addBlock(blockWith(7, 0x73, plain, short), true)

	cases := map[string]uint32{
		"no commit cell in the transaction": 0,
		"commit cell is not 32 bytes":       1,
		"no transaction at that index":      9,
	}
	for name, idx := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := client.CommitmentAt(context.Background(),
				&consensus.L1Location{BlockHash: hash.String(), TxIdx: idx})
			if err == nil {
				t.Fatal("accepted an anchor that is not there")
			}
			if errors.Is(err, consensus.ErrNotOnChain) {
				t.Fatalf("reported a present-but-malformed anchor as off chain: %v", err)
			}
		})
	}
}

func TestBudgetOwner(t *testing.T) {
	node := newFakeNode()
	client := testClient(t, node)

	tx := budgetTx(t, client, 61_00000000, nil)
	node.addCommittedTx(tx, ckbtypes.HexToHash(hashOf(0x74)), 900, 0)

	args, err := client.BudgetOwner(context.Background(), tx.Hash.String())
	if err != nil {
		t.Fatalf("reading the budget cell's owner: %v", err)
	}
	// V7's first item compares this against the block producer's key. The
	// args are the key's blake160, not the key, so the check only works if
	// what comes back is the raw args.
	want, err := consensus.Blake160(mustPubkey(t))
	if err != nil {
		t.Fatalf("hashing the miner key: %v", err)
	}
	if hex.EncodeToString(args) != hex.EncodeToString(want) {
		t.Fatalf("lock args are %x, want %x", args, want)
	}
}

func TestBudgetOwnerRejectsTransactionWithoutBudgetCell(t *testing.T) {
	node := newFakeNode()
	client := testClient(t, node)

	tx := commitTx(client, bytes32(0xab))
	node.addCommittedTx(tx, ckbtypes.HexToHash(hashOf(0x75)), 901, 0)

	_, err := client.BudgetOwner(context.Background(), tx.Hash.String())
	if !errors.Is(err, consensus.ErrPaymentNotFound) {
		t.Fatalf("a transaction with no budget cell gave %v, want ErrPaymentNotFound", err)
	}
	if !strings.Contains(err.Error(), tx.Hash.String()) {
		t.Fatalf("error does not name the transaction: %v", err)
	}
}

// bytes32 renders 32 bytes of one value, standing in for a commitment.
func bytes32(fill byte) []byte {
	out := make([]byte, commitmentLen)
	for i := range out {
		out[i] = fill
	}
	return out
}
