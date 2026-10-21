package ckb

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/nervosnetwork/ckb-sdk-go/v2/indexer"
	ckbtypes "github.com/nervosnetwork/ckb-sdk-go/v2/types"

	"github.com/yu-org/yu/common"
	"github.com/yu-org/yu/core/types"

	"github.com/invisibook-lab/invisibook/consensus"
)

// testHeader returns an L2 header at `height` whose Hash is the one its
// contents imply, the way a sealed block's would be.
func testHeader(t *testing.T, height common.BlockNum) *types.Header {
	t.Helper()

	header := &types.Header{
		Height:   height,
		PrevHash: common.BytesToHash([]byte("parent")),
		Extra:    []byte(`{"block_score":"1"}`),
	}
	hash, err := consensus.ComputeBlockHash(&types.Block{Header: header})
	if err != nil {
		t.Fatalf("hashing the test header: %v", err)
	}
	header.Hash = hash
	return header
}

// submitTx builds a transaction whose second output is a submit cell holding
// `data`, with a decoy cell in front of it so that locating the transaction
// is visibly not the same as locating the cell.
func submitTx(c *Client, fill byte, data []byte) *ckbtypes.Transaction {
	return &ckbtypes.Transaction{
		Hash: ckbtypes.HexToHash(hashOf(fill)),
		Outputs: []*ckbtypes.CellOutput{
			{Capacity: 100, Lock: c.minerLock()},
			{Capacity: 200, Lock: c.minerLock(), Type: c.set.commitScript},
		},
		OutputsData: [][]byte{nil, data},
	}
}

// landSubmission records `tx` as committed at L1 height `number` and lists
// its submit cell for the indexer.
func landSubmission(node *fakeNode, tx *ckbtypes.Transaction, number uint64) {
	node.addCommittedTx(tx, ckbtypes.HexToHash(hashOf(byte(number))), number, 0)
	node.listed = append(node.listed, &indexer.TxWithCell{
		BlockNumber: number,
		IoIndex:     1,
		IoType:      indexer.IOTypeOut,
		TxHash:      tx.Hash,
	})
	if number > node.tip {
		node.tip = number
	}
}

// encodedHeader encodes `header` the way SubmitHeader does.
func encodedHeader(t *testing.T, header *types.Header) []byte {
	t.Helper()
	raw, err := consensus.EncodeHeader(header)
	if err != nil {
		t.Fatalf("encoding the test header: %v", err)
	}
	return raw
}

// A window read returns every header submitted inside it, each dated by the
// L1 block it landed in, and nothing from outside it.
func TestAnchoredInReadsTheWindow(t *testing.T) {
	node := newFakeNode()
	client := testClient(t, node)
	early, inside, late := testHeader(t, 6), testHeader(t, 7), testHeader(t, 8)

	landSubmission(node, submitTx(client, 0x51, encodedHeader(t, early)), 4199)
	landSubmission(node, submitTx(client, 0x52, encodedHeader(t, inside)), 4200)
	landSubmission(node, submitTx(client, 0x53, encodedHeader(t, late)), 4225)

	got, err := client.AnchoredIn(context.Background(), 4200, 4224)
	if err != nil {
		t.Fatalf("AnchoredIn: %v", err)
	}
	if len(got) != 1 || got[0].Header.Hash != inside.Hash || got[0].L1Height != 4200 {
		t.Fatalf("window read %+v, want only height 7 at L1 4200", got)
	}
}

// The indexer may still list a submission a reorg took away. It is re-read
// with the committed-only filter, and left out when L1 no longer has it.
func TestAnchoredInSkipsASubmissionLostToAReorg(t *testing.T) {
	node := newFakeNode()
	client := testClient(t, node)
	tx := submitTx(client, 0x51, encodedHeader(t, testHeader(t, 7)))
	landSubmission(node, tx, 4200)
	delete(node.txs, tx.Hash)

	got, err := client.AnchoredIn(context.Background(), 4200, 4224)
	if err != nil {
		t.Fatalf("AnchoredIn: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("read %d headers from a reorged-away submission, want 0", len(got))
	}
}

// Submit cells only have their length checked on chain, so anyone can fill
// one with garbage. It is skipped, not an error that stops the window read.
func TestAnchoredInSkipsCellsThatHoldNoHeader(t *testing.T) {
	node := newFakeNode()
	client := testClient(t, node)
	header := testHeader(t, 7)

	landSubmission(node, submitTx(client, 0x51, []byte{0xff, 0xff}), 4200)
	landSubmission(node, submitTx(client, 0x52, encodedHeader(t, header)), 4201)

	got, err := client.AnchoredIn(context.Background(), 4200, 4224)
	if err != nil {
		t.Fatalf("AnchoredIn: %v", err)
	}
	if len(got) != 1 || got[0].Header.Hash != header.Hash {
		t.Fatalf("read %+v, want only the real header", got)
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
	if string(args) != string(want) {
		t.Fatalf("lock args are %x, want %x", args, want)
	}
}

func TestBudgetOwnerRejectsTransactionWithoutBudgetCell(t *testing.T) {
	node := newFakeNode()
	client := testClient(t, node)

	tx := submitTx(client, 0x55, []byte{1})
	node.addCommittedTx(tx, ckbtypes.HexToHash(hashOf(0x75)), 901, 0)

	_, err := client.BudgetOwner(context.Background(), tx.Hash.String())
	if !errors.Is(err, consensus.ErrPaymentNotFound) {
		t.Fatalf("a transaction with no budget cell gave %v, want ErrPaymentNotFound", err)
	}
	if !strings.Contains(err.Error(), tx.Hash.String()) {
		t.Fatalf("error does not name the transaction: %v", err)
	}
}

// bytes32 renders 32 bytes of one value.
func bytes32(fill byte) []byte {
	out := make([]byte, commitmentLen)
	for i := range out {
		out[i] = fill
	}
	return out
}
