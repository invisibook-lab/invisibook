package ckb

import (
	"context"
	"errors"
	"fmt"

	"github.com/nervosnetwork/ckb-sdk-go/v2/crypto/secp256k1"
	"github.com/nervosnetwork/ckb-sdk-go/v2/indexer"
	"github.com/nervosnetwork/ckb-sdk-go/v2/rpc"
	ckbtypes "github.com/nervosnetwork/ckb-sdk-go/v2/types"

	"github.com/invisibook-lab/invisibook/consensus"
)

// Client is the CKB node this chain reads and writes L1 through.
//
// One type implements all three of the consensus package's L1 interfaces —
// L1Reader, L1PaymentVerifier and L1CommitmentSubmitter — because on CKB they
// are three views of the same two cells. Splitting them would mean three
// connections, three copies of the script configuration, and three chances
// for those copies to disagree about which chain this node is on.
type Client struct {
	// wallet is everything needed to spend on CKB, with no knowledge of
	// what PoB's cells mean. It is separate because deployment needs exactly
	// that and nothing else: the tool that publishes the four scripts has to
	// build and sign transactions before any of their code hashes exist.
	wallet
	set *settings
}

// Verify at compile time that this really is the client the consensus package
// asks for. Getting a method signature subtly wrong would otherwise surface
// as main.go failing to wire up, far from the method itself.
var (
	_ consensus.L1Reader              = (*Client)(nil)
	_ consensus.L1PaymentVerifier     = (*Client)(nil)
	_ consensus.L1CommitmentSubmitter = (*Client)(nil)
)

// nodeRPC is the slice of a CKB node this package actually uses.
//
// Narrow on purpose, and for the same reason the reveal syncer takes a narrow
// store: rpc.Client is a hundred-odd methods wide, and depending on all of it
// would mean the only way to exercise a read path is to run a CKB node.
// Against five methods, a test supplies a struct.
type nodeRPC interface {
	// GetBlock returns a block by hash, or nil when the node does not know it.
	GetBlock(ctx context.Context, hash ckbtypes.Hash) (*ckbtypes.Block, error)
	// GetBlockHash returns the hash of the canonical block at `number`.
	GetBlockHash(ctx context.Context, number uint64) (*ckbtypes.Hash, error)
	// GetTransaction returns a transaction and its status.
	GetTransaction(ctx context.Context, hash ckbtypes.Hash, verbosity *uint32, onlyCommitted *bool) (*ckbtypes.TransactionWithStatus, error)
	// GetCells is the indexer query cell collection runs on.
	GetCells(ctx context.Context, searchKey *indexer.SearchKey, order indexer.SearchOrder, limit uint64, afterCursor string) (*indexer.LiveCells, error)
	// SendTransaction broadcasts a signed transaction.
	SendTransaction(ctx context.Context, tx *ckbtypes.Transaction) (*ckbtypes.Hash, error)
}

// rpc.Client is the production nodeRPC; checked here so that a signature
// drifting in the SDK shows up at compile time rather than at Dial.
var _ nodeRPC = (rpc.Client)(nil)

// New dials the configured CKB node and returns a client bound to `privKey`.
//
// `cfg` must have Enabled set — a disabled section means the caller wanted
// the mock L1 and should not have got here. `privKey` is the miner's raw
// 32-byte secp256k1 secret, the same one the VRF and the L2 block signature
// use.
func New(cfg *Config, privKey []byte) (*Client, error) {
	if cfg == nil || !cfg.Enabled {
		return nil, errors.New("ckb: the [ckb] section is not enabled")
	}
	set, err := cfg.resolve()
	if err != nil {
		return nil, err
	}
	key, err := secp256k1.ToKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("ckb: loading the miner key: %w", err)
	}
	client, err := rpc.Dial(cfg.RPCURL)
	if err != nil {
		return nil, fmt.Errorf("ckb: dialing %s: %w", cfg.RPCURL, err)
	}
	return &Client{wallet: wallet{
		rpc:             client,
		key:             key,
		inflight:        newInFlight(),
		network:         set.network,
		feeRate:         set.feeRate,
		sighashDep:      set.sighashDep,
		sighashCodeHash: set.sighashCodeHash,
	}, set: set}, nil
}

// fetchTx returns a committed transaction by hash, along with the block it
// was committed in.
//
// A transaction that is only in the pool is reported as not found. Everything
// this package reads out of L1 is evidence — a prepayment, an allocation
// table, an anchoring — and evidence that can still disappear from the pool
// is no evidence at all.
func (c *Client) fetchTx(ctx context.Context, txHash string) (*ckbtypes.TransactionWithStatus, error) {
	hash, err := parseHash(txHash)
	if err != nil {
		return nil, fmt.Errorf("tx hash %q: %w", txHash, err)
	}
	onlyCommitted := true
	tx, err := c.rpc.GetTransaction(ctx, hash, nil, &onlyCommitted)
	if err != nil {
		return nil, fmt.Errorf("fetching tx %s: %w", txHash, err)
	}
	if tx == nil || tx.Transaction == nil || tx.TxStatus == nil ||
		tx.TxStatus.Status != ckbtypes.TransactionStatusCommitted {
		return nil, nil
	}
	return tx, nil
}

// findCellByType returns the index of the first output guarded by `script`,
// or -1 when the transaction creates none.
//
// Matching is by script hash rather than field by field, so that args are
// part of the comparison: two cells running the same code with different args
// are different cells.
//
// An output whose data the transaction does not carry is skipped. CKB keeps
// the two lists the same length, so this only arises from a node answering
// with something malformed — and every caller here goes straight on to read
// that data.
func findCellByType(tx *ckbtypes.Transaction, script *ckbtypes.Script) int {
	want := script.Hash()
	for i, output := range tx.Outputs {
		if output.Type == nil || i >= len(tx.OutputsData) {
			continue
		}
		if output.Type.Hash() == want {
			return i
		}
	}
	return -1
}
