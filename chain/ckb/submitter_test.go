package ckb

import (
	"context"
	"encoding/hex"
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

func TestSubmitCommitment(t *testing.T) {
	node := newFakeNode()
	client := testClient(t, node)
	fund(client, node, 10_000_00000000)

	commitment := hex.EncodeToString(bytes32(0xcd))
	txHash, err := client.SubmitCommitment(context.Background(), &consensus.BlockCommitment{
		L2BlockHeight: 77,
		Commitment:    commitment,
	})
	if err != nil {
		t.Fatalf("submitting the commitment: %v", err)
	}
	if txHash == "" {
		t.Fatal("submitted without a transaction hash")
	}
	if len(node.sent) != 1 {
		t.Fatalf("broadcast %d transactions, want 1", len(node.sent))
	}
	tx := node.sent[0]

	// The one output this call is about, and what it carries. A commit cell
	// holding anything but 32 bytes is refused on chain by R5.1.
	var found int
	for i, output := range tx.Outputs {
		if output.Type == nil {
			continue
		}
		if output.Type.Hash() != client.set.commitScript.Hash() {
			t.Fatalf("output %d carries an unexpected type script", i)
		}
		found++
		if got := hex.EncodeToString(tx.OutputsData[i]); got != commitment {
			t.Fatalf("commit cell carries %s, want %s", got, commitment)
		}
		// Locked to the miner so the capacity comes back once the height is
		// decided (R5.2).
		if output.Lock.Hash() != client.minerLock().Hash() {
			t.Fatal("commit cell is not locked to the miner that created it")
		}
	}
	if found != 1 {
		t.Fatalf("created %d commit cells, want 1", found)
	}

	// Nothing about the bid may reach L1 in the clear: whatever an L1 block
	// producer can read, it can censor on (§9.6).
	for i, data := range tx.OutputsData {
		if i < len(tx.Outputs) && tx.Outputs[i].Type != nil {
			continue
		}
		if len(data) != 0 {
			t.Fatalf("output %d carries %d bytes beside the commitment", i, len(data))
		}
	}

	// The script has to be findable, or the node rejects the transaction.
	if !hasDep(tx, client.set.commitDep) {
		t.Fatal("the commit script's cell dep is missing")
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

func TestSubmitCommitmentRejectsMalformedCommitment(t *testing.T) {
	node := newFakeNode()
	client := testClient(t, node)
	fund(client, node, 10_000_00000000)

	cases := map[string]string{
		"not 32 bytes": "abcd",
		"not hex":      "zz" + hex.EncodeToString(bytes32(0xcd))[2:],
	}
	for name, commitment := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := client.SubmitCommitment(context.Background(),
				&consensus.BlockCommitment{L2BlockHeight: 1, Commitment: commitment})
			if err == nil {
				t.Fatal("submitted a commitment R5.1 would refuse")
			}
			if len(node.sent) != 0 {
				t.Fatal("broadcast a transaction that could not be valid")
			}
		})
	}
}

func TestCommitmentOnChain(t *testing.T) {
	node := newFakeNode()
	client := testClient(t, node)

	tx := commitTx(client, bytes32(0xab))
	blockHash := ckbtypes.HexToHash(hashOf(0x7a))
	node.addCommittedTx(tx, blockHash, 555, 3)

	loc, err := client.CommitmentOnChain(context.Background(), tx.Hash.String())
	if err != nil {
		t.Fatalf("checking the submission: %v", err)
	}
	if loc == nil {
		t.Fatal("a committed submission reported as not on chain")
	}
	if loc.BlockHash != blockHash.String() || loc.TxIdx != 3 {
		t.Fatalf("located at %s/%d, want %s/3", loc.BlockHash, loc.TxIdx, blockHash)
	}
}

// Without the index a verifier cannot find the commitment, so a node that
// does not report one is worth a second round trip rather than a hard
// requirement on its version.
func TestCommitmentOnChainFallsBackToScanningTheBlock(t *testing.T) {
	node := newFakeNode()
	client := testClient(t, node)

	tx := commitTx(client, bytes32(0xab))
	other := &ckbtypes.Transaction{Hash: ckbtypes.HexToHash(hashOf(0x04))}
	block := blockWith(556, 0x7b, other, tx)
	blockHash := node.addBlock(block, true)

	node.txs[tx.Hash] = &ckbtypes.TransactionWithStatus{
		Transaction: tx,
		TxStatus: &ckbtypes.TxStatus{
			Status:    ckbtypes.TransactionStatusCommitted,
			BlockHash: &blockHash,
		},
	}

	loc, err := client.CommitmentOnChain(context.Background(), tx.Hash.String())
	if err != nil {
		t.Fatalf("checking the submission: %v", err)
	}
	if loc == nil || loc.TxIdx != 1 {
		t.Fatalf("located at %+v, want index 1", loc)
	}
}

// A submission waiting in the pool is not a lost one, and the difference
// decides what the caller does. Re-sending a pending commitment rebuilds the
// identical transaction — same opening, same inputs — which the node refuses
// as a duplicate, so reporting "pending" as "absent" turns every block's
// ordinary wait into a resubmission loop that can never succeed.
func TestCommitmentOnChainDistinguishesPendingFromLost(t *testing.T) {
	node := newFakeNode()
	client := testClient(t, node)

	for _, status := range []ckbtypes.TransactionStatus{
		ckbtypes.TransactionStatusPending,
		ckbtypes.TransactionStatusProposed,
	} {
		tx := commitTx(client, bytes32(0xab))
		node.txs[tx.Hash] = &ckbtypes.TransactionWithStatus{
			Transaction: tx,
			TxStatus:    &ckbtypes.TxStatus{Status: status},
		}

		loc, err := client.CommitmentOnChain(context.Background(), tx.Hash.String())
		if !errors.Is(err, consensus.ErrSubmissionPending) {
			t.Fatalf("a %s submission gave %v, want ErrSubmissionPending", status, err)
		}
		if loc != nil {
			t.Fatalf("a %s submission located at %+v, want nil", status, loc)
		}
	}

	// One L1 has never heard of really is lost, and has to be sent again.
	loc, err := client.CommitmentOnChain(context.Background(), hashOf(0x98))
	if err != nil {
		t.Fatalf("checking an unknown submission: %v", err)
	}
	if loc != nil {
		t.Fatalf("an unknown submission located at %+v, want nil", loc)
	}

	// So is one the node rejected.
	rejected := commitTx(client, bytes32(0xac))
	rejected.Hash = ckbtypes.HexToHash(hashOf(0x97))
	node.txs[rejected.Hash] = &ckbtypes.TransactionWithStatus{
		Transaction: rejected,
		TxStatus:    &ckbtypes.TxStatus{Status: ckbtypes.TransactionStatusRejected},
	}
	loc, err = client.CommitmentOnChain(context.Background(), rejected.Hash.String())
	if err != nil {
		t.Fatalf("checking a rejected submission: %v", err)
	}
	if loc != nil {
		t.Fatalf("a rejected submission located at %+v, want nil", loc)
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
