package ckb

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/nervosnetwork/ckb-sdk-go/v2/address"
	"github.com/nervosnetwork/ckb-sdk-go/v2/crypto/secp256k1"
	"github.com/nervosnetwork/ckb-sdk-go/v2/indexer"
	ckbtypes "github.com/nervosnetwork/ckb-sdk-go/v2/types"
)

// minerSecret is the key every test in this package mines with. Any 32 bytes
// below the curve order do; this one is a constant so that the address and
// lock args derived from it are stable across runs.
const minerSecret = "0101010101010101010101010101010101010101010101010101010101010101"

// fakeNode is a CKB node made of maps: what it was told to hold, and nothing
// else. It stands in for nodeRPC so the read paths can be exercised without a
// chain behind them.
type fakeNode struct {
	// blocks and canonical are separate on purpose. A node keeps blocks from
	// forks it no longer follows, and the difference between the two maps is
	// exactly the case CommitmentAt has to catch.
	blocks    map[ckbtypes.Hash]*ckbtypes.Block
	canonical map[uint64]ckbtypes.Hash
	txs       map[ckbtypes.Hash]*ckbtypes.TransactionWithStatus

	// sent records what was broadcast, so a builder test can look at it.
	sent []*ckbtypes.Transaction
	// cells is what the indexer hands cell collection.
	cells []*indexer.LiveCell
}

func newFakeNode() *fakeNode {
	return &fakeNode{
		blocks:    map[ckbtypes.Hash]*ckbtypes.Block{},
		canonical: map[uint64]ckbtypes.Hash{},
		txs:       map[ckbtypes.Hash]*ckbtypes.TransactionWithStatus{},
	}
}

func (f *fakeNode) GetBlock(_ context.Context, hash ckbtypes.Hash) (*ckbtypes.Block, error) {
	return f.blocks[hash], nil
}

func (f *fakeNode) GetBlockHash(_ context.Context, number uint64) (*ckbtypes.Hash, error) {
	hash, ok := f.canonical[number]
	if !ok {
		return nil, nil
	}
	return &hash, nil
}

func (f *fakeNode) GetTransaction(_ context.Context, hash ckbtypes.Hash, _ *uint32, _ *bool) (*ckbtypes.TransactionWithStatus, error) {
	return f.txs[hash], nil
}

func (f *fakeNode) GetCells(_ context.Context, _ *indexer.SearchKey, _ indexer.SearchOrder, _ uint64, cursor string) (*indexer.LiveCells, error) {
	if cursor != "" {
		return &indexer.LiveCells{Objects: nil, LastCursor: ""}, nil
	}
	return &indexer.LiveCells{Objects: f.cells, LastCursor: "end"}, nil
}

func (f *fakeNode) SendTransaction(_ context.Context, tx *ckbtypes.Transaction) (*ckbtypes.Hash, error) {
	f.sent = append(f.sent, tx)
	hash := tx.ComputeHash()
	return &hash, nil
}

// addBlock records a block as known, and optionally as the one the node
// currently follows at its height.
func (f *fakeNode) addBlock(block *ckbtypes.Block, canonical bool) ckbtypes.Hash {
	hash := block.Header.Hash
	f.blocks[hash] = block
	if canonical {
		f.canonical[block.Header.Number] = hash
	}
	return hash
}

// addCommittedTx records a transaction as committed at a position in a block.
func (f *fakeNode) addCommittedTx(tx *ckbtypes.Transaction, blockHash ckbtypes.Hash, number uint64, idx uint) {
	f.txs[tx.Hash] = &ckbtypes.TransactionWithStatus{
		Transaction: tx,
		TxStatus: &ckbtypes.TxStatus{
			Status:      ckbtypes.TransactionStatusCommitted,
			BlockHash:   &blockHash,
			BlockNumber: &number,
			TxIndex:     &idx,
		},
	}
}

// testClient builds a client over `node` with a deployment whose script
// hashes are arbitrary but internally consistent.
func testClient(t *testing.T, node *fakeNode) *Client {
	t.Helper()

	key, err := secp256k1.HexToKey(minerSecret)
	if err != nil {
		t.Fatalf("loading the test miner key: %v", err)
	}
	set := testSettings(t)
	return &Client{wallet: wallet{
		rpc:             node,
		key:             key,
		inflight:        newInFlight(),
		network:         set.network,
		feeRate:         set.feeRate,
		sighashDep:      set.sighashDep,
		sighashCodeHash: set.sighashCodeHash,
	}, set: set}
}

// testSettings resolves a deployment good enough to exercise every code path:
// four distinct script code hashes, and a mining addr nobody holds the key
// for, which is what a mining addr is.
func testSettings(t *testing.T) *settings {
	t.Helper()

	cfg := &Config{
		Enabled:          true,
		Network:          "devnet",
		SighashDepTxHash: hashOf(0x11),
		MiningAddr:       testMiningAddr(t),
		FeeRate:          1000,
		Budget:           testScript(0x21),
		Commit:           testScript(0x22),
		Vault:            testScript(0x23),
		Spent:            testScript(0x24),
	}
	set, err := cfg.resolve()
	if err != nil {
		t.Fatalf("resolving the test config: %v", err)
	}
	return set
}

// testScript names a deployed script by a single filler byte, so that two
// scripts in a test are visibly different.
func testScript(fill byte) ScriptConfig {
	return ScriptConfig{
		CodeHash:  hashOf(fill),
		HashType:  "type",
		DepTxHash: hashOf(fill ^ 0xff),
		DepIndex:  0,
		DepType:   "code",
	}
}

// hashOf renders a 32-byte hash of one repeated byte.
func hashOf(fill byte) string {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = fill
	}
	return "0x" + hex.EncodeToString(raw)
}

// testMiningAddr is an address under the standard lock whose key nobody in
// this package holds — the mining addr is the operator's, not a miner's.
func testMiningAddr(t *testing.T) string {
	t.Helper()

	args := make([]byte, 20)
	for i := range args {
		args[i] = 0x33
	}
	addr, err := address.Address{
		Script: &ckbtypes.Script{
			CodeHash: ckbtypes.HexToHash("0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8"),
			HashType: ckbtypes.HashTypeType,
			Args:     args,
		},
		Network: ckbtypes.NetworkTest,
	}.Encode()
	if err != nil {
		t.Fatalf("encoding the test mining addr: %v", err)
	}
	return addr
}

// minerPubkeyHex is the compressed public key of the test miner, in the form
// a block's MinerPubkey field carries.
func minerPubkeyHex(t *testing.T) string {
	t.Helper()

	key, err := secp256k1.HexToKey(minerSecret)
	if err != nil {
		t.Fatalf("loading the test miner key: %v", err)
	}
	return hex.EncodeToString(key.PubKey())
}
