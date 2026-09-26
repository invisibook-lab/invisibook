package ckb

import (
	"context"
	"errors"
	"math/big"
	"testing"

	"github.com/nervosnetwork/ckb-sdk-go/v2/crypto/secp256k1"
	ckbtypes "github.com/nervosnetwork/ckb-sdk-go/v2/types"
	"github.com/yu-org/yu/common"

	"github.com/invisibook-lab/invisibook/consensus"
)

// budgetTx builds a transaction creating a budget cell owned by the test
// miner, declaring `prepaid` and carrying `allocations`.
func budgetTx(t *testing.T, c *Client, prepaid uint64, allocations []BudgetEntry) *ckbtypes.Transaction {
	t.Helper()

	data, err := (&BudgetData{Prepaid: prepaid, Allocations: allocations}).Encode()
	if err != nil {
		t.Fatalf("encoding the budget data: %v", err)
	}
	return &ckbtypes.Transaction{
		Hash: ckbtypes.HexToHash(hashOf(0x66)),
		Outputs: []*ckbtypes.CellOutput{
			{Capacity: prepaid, Lock: c.set.miningAddrLock, Type: c.set.vaultScript},
			{Capacity: 200_00000000, Lock: c.minerLock(), Type: c.set.budgetScript},
		},
		OutputsData: [][]byte{nil, data},
	}
}

// mustPubkey returns the test miner's compressed public key.
func mustPubkey(t *testing.T) []byte {
	t.Helper()

	key, err := secp256k1.HexToKey(minerSecret)
	if err != nil {
		t.Fatalf("loading the test miner key: %v", err)
	}
	return key.PubKey()
}

func TestFetchPrepaymentAndAllocation(t *testing.T) {
	node := newFakeNode()
	client := testClient(t, node)

	first, err := Allocate(10, big.NewInt(700_00000000), "11"+repeatHex("00", 31))
	if err != nil {
		t.Fatalf("committing to an allocation: %v", err)
	}
	second, err := Allocate(11, big.NewInt(300_00000000), "22"+repeatHex("00", 31))
	if err != nil {
		t.Fatalf("committing to an allocation: %v", err)
	}

	const prepaid = 1000_00000000
	tx := budgetTx(t, client, prepaid, []BudgetEntry{first, second})
	node.addCommittedTx(tx, ckbtypes.HexToHash(hashOf(0x76)), 1234, 2)

	pubkey := minerPubkeyHex(t)
	total, err := client.FetchPrepayment(context.Background(), tx.Hash.String(), pubkey)
	if err != nil {
		t.Fatalf("reading the prepayment: %v", err)
	}
	if total.Cmp(big.NewInt(prepaid)) != 0 {
		t.Fatalf("prepaid reads back as %s, want %d", total, uint64(prepaid))
	}

	allocation, err := client.FetchAllocation(context.Background(), tx.Hash.String(), pubkey, 11)
	if err != nil {
		t.Fatalf("reading the allocation: %v", err)
	}
	if allocation.Commitment != second.Commitment {
		t.Fatalf("allocation for height 11 is %s, want %s", allocation.Commitment, second.Commitment)
	}
	// V4 measures the lead from here. The whole table is written in one
	// transaction that never changes afterwards, so that transaction's block
	// dates every entry in it.
	if allocation.L1BlockNumber != 1234 {
		t.Fatalf("allocation dated to L1 block %d, want 1234", allocation.L1BlockNumber)
	}
}

// The ownership check is the ground the payment path stands on. Both lookups
// are told which miner to look up, so without it a miner would be handed back
// a commitment it chose itself and V3 would compare its story to its story.
func TestFetchRejectsSomebodyElsesBudget(t *testing.T) {
	node := newFakeNode()
	client := testClient(t, node)

	tx := budgetTx(t, client, 1000_00000000, nil)
	// Same cell, a different owner: the args no longer hash from this key.
	tx.Outputs[1].Lock = &ckbtypes.Script{
		CodeHash: client.set.sighashCodeHash,
		HashType: ckbtypes.HashTypeType,
		Args:     bytes32(0x44)[:20],
	}
	node.addCommittedTx(tx, ckbtypes.HexToHash(hashOf(0x77)), 1234, 0)

	_, err := client.FetchPrepayment(context.Background(), tx.Hash.String(), minerPubkeyHex(t))
	if !errors.Is(err, consensus.ErrPaymentNotFound) {
		t.Fatalf("another miner's budget cell gave %v, want ErrPaymentNotFound", err)
	}
}

// R3.5 pins the budget cell's lock to the standard sighash lock, which is
// what makes "the args are a key's blake160" safe to read. A cell under
// anything else is not one this node can attribute to a miner.
func TestFetchRejectsNonSighashLock(t *testing.T) {
	node := newFakeNode()
	client := testClient(t, node)

	tx := budgetTx(t, client, 1000_00000000, nil)
	tx.Outputs[1].Lock.CodeHash = ckbtypes.HexToHash(hashOf(0x45))
	node.addCommittedTx(tx, ckbtypes.HexToHash(hashOf(0x78)), 1234, 0)

	_, err := client.FetchPrepayment(context.Background(), tx.Hash.String(), minerPubkeyHex(t))
	if !errors.Is(err, consensus.ErrPaymentNotFound) {
		t.Fatalf("a budget cell under a non-standard lock gave %v, want ErrPaymentNotFound", err)
	}
}

func TestFetchAllocationMisses(t *testing.T) {
	node := newFakeNode()
	client := testClient(t, node)

	bid, err := Allocate(10, big.NewInt(700_00000000), repeatHex("11", 32))
	if err != nil {
		t.Fatalf("committing to an allocation: %v", err)
	}
	tx := budgetTx(t, client, 1000_00000000, []BudgetEntry{bid})
	node.addCommittedTx(tx, ckbtypes.HexToHash(hashOf(0x79)), 1234, 0)

	pubkey := minerPubkeyHex(t)
	// A height nobody bid on is an ordinary answer, not a failure: a table
	// covers the heights its owner chose and says nothing about the rest.
	for _, height := range []common.BlockNum{0, 9, 11, 99} {
		_, err := client.FetchAllocation(context.Background(), tx.Hash.String(), pubkey, height)
		if !errors.Is(err, consensus.ErrPaymentNotFound) {
			t.Fatalf("height %d gave %v, want ErrPaymentNotFound", height, err)
		}
	}
	if _, err := client.FetchAllocation(context.Background(), tx.Hash.String(), pubkey, 10); err != nil {
		t.Fatalf("the one height that was bid on gave %v", err)
	}
}

// A transaction still in the pool is evidence that can still disappear, and
// the whole payment path treats it as no evidence at all.
func TestFetchRejectsUncommittedTransaction(t *testing.T) {
	node := newFakeNode()
	client := testClient(t, node)

	tx := budgetTx(t, client, 1000_00000000, nil)
	node.txs[tx.Hash] = &ckbtypes.TransactionWithStatus{
		Transaction: tx,
		TxStatus:    &ckbtypes.TxStatus{Status: ckbtypes.TransactionStatusPending},
	}

	_, err := client.FetchPrepayment(context.Background(), tx.Hash.String(), minerPubkeyHex(t))
	if !errors.Is(err, consensus.ErrPaymentNotFound) {
		t.Fatalf("a pending prepayment gave %v, want ErrPaymentNotFound", err)
	}
}

// The two sides of V7's comparison are computed by different libraries — the
// consensus package hashes with minio's blake2b, the CKB SDK with its own —
// so a drift between them would silently reject every honest miner.
func TestBlake160AgreesWithConsensus(t *testing.T) {
	pubkey := mustPubkey(t)

	want, err := consensus.Blake160(pubkey)
	if err != nil {
		t.Fatalf("hashing with the consensus package: %v", err)
	}
	if got := blake160(pubkey); string(got) != string(want) {
		t.Fatalf("the SDK hashes the key to %x, the consensus package to %x", got, want)
	}
}

// repeatHex renders `times` copies of a two-character hex byte.
func repeatHex(b string, times int) string {
	out := ""
	for i := 0; i < times; i++ {
		out += b
	}
	return out
}
