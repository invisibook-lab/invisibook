package ckb

import (
	"context"
	"errors"
	"testing"

	"github.com/nervosnetwork/ckb-sdk-go/v2/indexer"
	ckbtypes "github.com/nervosnetwork/ckb-sdk-go/v2/types"

	"github.com/invisibook-lab/invisibook/consensus"
)

// fund gives the miner one plain cell big enough to pay for anything these
// tests build.
func fund(c *Client, node *fakeNode, capacity uint64) {
	node.cells = append(node.cells, &indexer.LiveCell{
		BlockNumber: 1,
		OutPoint:    &ckbtypes.OutPoint{TxHash: ckbtypes.HexToHash(hashOf(0x90)), Index: uint32(len(node.cells))},
		Output:      &ckbtypes.CellOutput{Capacity: capacity, Lock: c.minerLock()},
	})
}

func TestSubmitHeader(t *testing.T) {
	node := newFakeNode()
	client := testClient(t, node)
	fund(client, node, 10_000_00000000)
	header := testHeader(t, 77)

	txHash, err := client.SubmitHeader(context.Background(), header)
	if err != nil {
		t.Fatalf("submitting the header: %v", err)
	}
	if txHash == "" {
		t.Fatal("submitted without a transaction hash")
	}
	if len(node.sent) != 1 {
		t.Fatalf("broadcast %d transactions, want 1", len(node.sent))
	}
	tx := node.sent[0]

	var found int
	for i, output := range tx.Outputs {
		if output.Type == nil {
			continue
		}
		if output.Type.Hash() != client.set.commitScript.Hash() {
			t.Fatalf("output %d carries an unexpected type script", i)
		}
		found++
		// What lands on L1 has to resolve back to the block it was
		// submitted for, or no node can date that block by it.
		got, err := consensus.DecodeAnchoredHeader(tx.OutputsData[i])
		if err != nil {
			t.Fatalf("decoding the submitted header: %v", err)
		}
		if got.Hash != header.Hash {
			t.Fatalf("submit cell resolves to %s, want %s", got.Hash, header.Hash)
		}
		// Locked to the miner so the capacity comes back once the height is
		// decided (R5.2).
		if output.Lock.Hash() != client.minerLock().Hash() {
			t.Fatal("submit cell is not locked to the miner that created it")
		}
	}
	if found != 1 {
		t.Fatalf("created %d submit cells, want 1", found)
	}

	// The script has to be findable, or the node rejects the transaction.
	if !hasDep(tx, client.set.commitDep) {
		t.Fatal("the submit script's cell dep is missing")
	}
	if !hasDep(tx, client.set.sighashDep) {
		t.Fatal("the sighash lock's cell dep is missing")
	}
	// An unsigned witness would be rejected by the node with an error about
	// the lock and nothing about the cause.
	if len(tx.Witnesses) == 0 || len(tx.Witnesses[0]) == 0 {
		t.Fatal("the transaction went out unsigned")
	}
}

// R5.1 caps the data length on chain; a header over it is refused before a
// transaction is built.
func TestSubmitHeaderRejectsAnOversizedHeader(t *testing.T) {
	node := newFakeNode()
	client := testClient(t, node)
	fund(client, node, 10_000_00000000)

	header := testHeader(t, 1)
	header.Extra = make([]byte, consensus.MaxHeaderLen)

	if _, err := client.SubmitHeader(context.Background(), header); !errors.Is(err, consensus.ErrHeaderTooLarge) {
		t.Fatalf("expected ErrHeaderTooLarge, got %v", err)
	}
	if len(node.sent) != 0 {
		t.Fatal("broadcast a transaction that could not be valid")
	}
}

func TestHeaderOnChain(t *testing.T) {
	node := newFakeNode()
	client := testClient(t, node)

	tx := submitTx(client, 0x55, []byte{1})
	node.addCommittedTx(tx, ckbtypes.HexToHash(hashOf(0x7a)), 555, 3)

	onChain, err := client.HeaderOnChain(context.Background(), tx.Hash.String())
	if err != nil {
		t.Fatalf("checking the submission: %v", err)
	}
	if !onChain {
		t.Fatal("a committed submission reported as not on chain")
	}
}

// A submission waiting in the pool is not a lost one, and the difference
// decides what the caller does. Re-sending a pending submission rebuilds the
// identical transaction, which the node refuses as a duplicate, so reporting
// "pending" as "absent" turns every block's ordinary wait into a resubmission
// loop that can never succeed.
func TestHeaderOnChainDistinguishesPendingFromLost(t *testing.T) {
	node := newFakeNode()
	client := testClient(t, node)

	for _, status := range []ckbtypes.TransactionStatus{
		ckbtypes.TransactionStatusPending,
		ckbtypes.TransactionStatusProposed,
	} {
		tx := submitTx(client, 0x55, []byte{1})
		node.txs[tx.Hash] = &ckbtypes.TransactionWithStatus{
			Transaction: tx,
			TxStatus:    &ckbtypes.TxStatus{Status: status},
		}

		onChain, err := client.HeaderOnChain(context.Background(), tx.Hash.String())
		if !errors.Is(err, consensus.ErrSubmissionPending) {
			t.Fatalf("a %s submission gave %v, want ErrSubmissionPending", status, err)
		}
		if onChain {
			t.Fatalf("a %s submission reported as on chain", status)
		}
	}

	// One L1 has never heard of really is lost, and has to be sent again.
	onChain, err := client.HeaderOnChain(context.Background(), hashOf(0x98))
	if err != nil {
		t.Fatalf("checking an unknown submission: %v", err)
	}
	if onChain {
		t.Fatal("an unknown submission reported as on chain")
	}

	// So is one the node rejected.
	rejected := submitTx(client, 0x97, []byte{1})
	node.txs[rejected.Hash] = &ckbtypes.TransactionWithStatus{
		Transaction: rejected,
		TxStatus:    &ckbtypes.TxStatus{Status: ckbtypes.TransactionStatusRejected},
	}
	onChain, err = client.HeaderOnChain(context.Background(), rejected.Hash.String())
	if err != nil {
		t.Fatalf("checking a rejected submission: %v", err)
	}
	if onChain {
		t.Fatal("a rejected submission reported as on chain")
	}
}

// hasDep reports whether `tx` carries `want` among its cell deps.
func hasDep(tx *ckbtypes.Transaction, want *ckbtypes.CellDep) bool {
	for _, dep := range tx.CellDeps {
		if dep.OutPoint.TxHash == want.OutPoint.TxHash &&
			dep.OutPoint.Index == want.OutPoint.Index &&
			dep.DepType == want.DepType {
			return true
		}
	}
	return false
}
