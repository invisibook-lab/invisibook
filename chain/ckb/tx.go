package ckb

import (
	"context"
	"fmt"
	"time"

	"github.com/nervosnetwork/ckb-sdk-go/v2/address"
	"github.com/nervosnetwork/ckb-sdk-go/v2/collector"
	"github.com/nervosnetwork/ckb-sdk-go/v2/collector/builder"
	"github.com/nervosnetwork/ckb-sdk-go/v2/collector/handler"
	"github.com/nervosnetwork/ckb-sdk-go/v2/crypto/secp256k1"
	"github.com/nervosnetwork/ckb-sdk-go/v2/indexer"
	"github.com/nervosnetwork/ckb-sdk-go/v2/transaction"
	"github.com/nervosnetwork/ckb-sdk-go/v2/transaction/signer"
	ckbtypes "github.com/nervosnetwork/ckb-sdk-go/v2/types"
)

// cellPageSize is how many live cells one indexer round trip asks for. It
// matches the SDK's own default: large enough that a well-funded miner is
// covered in one call, small enough not to pull a whole wallet in to pay a
// transaction fee.
const cellPageSize = 100

// awaitPollInterval is how often AwaitCommitted asks whether a transaction
// has landed. CKB's block time is seconds, so anything faster is just load.
const awaitPollInterval = time.Second

// wallet is the part of this package that can spend on CKB: a node to talk
// to, a key to sign with, and the standard lock that key owns.
//
// It knows nothing about budget cells, commit cells or the mining addr. That
// separation is what lets the deployment tool reuse this machinery, since it
// has to build and sign a transaction at a moment when none of PoB's scripts
// exist yet.
type wallet struct {
	rpc nodeRPC

	// key signs everything this node sends to L1. For a miner it is the
	// block key: the same secp256k1 scalar that signs L2 blocks and
	// evaluates the VRF, which is what makes the identity binding of
	// proof_of_buy.md §6.2 true by construction rather than by checking.
	key *secp256k1.Secp256k1Key

	network         ckbtypes.Network
	feeRate         uint64
	sighashDep      *ckbtypes.CellDep
	sighashCodeHash ckbtypes.Hash

	// inflight keeps the wallet's own unconfirmed transactions from
	// colliding with each other; see inFlight.
	inflight *inFlight
}

// minerLock is the standard sighash lock owning every cell this wallet
// creates.
//
// Its args are the blake160 of the key's public half, which is the same
// comparison V7's first item makes from the other side: a budget cell created
// here is one this node can later prove it owns.
func (w *wallet) minerLock() *ckbtypes.Script {
	return &ckbtypes.Script{
		CodeHash: w.sighashCodeHash,
		HashType: ckbtypes.HashTypeType,
		Args:     blake160(w.key.PubKey()),
	}
}

// newBuilder starts a transaction funded from this wallet's own plain cells,
// with the change going back to it.
//
// The SDK's per-network constructor is not used. It hands back nil for
// anything but the public networks, and its cell deps are baked in — whereas
// a devnet's system scripts sit in that chain's own genesis transaction. The
// one handler registered here carries the dep the config resolved, so the
// same code path serves mainnet, testnet and a local devnet.
func (w *wallet) newBuilder(ctx context.Context) (*builder.CkbTransactionBuilder, error) {
	lock := w.minerLock()
	minerAddr, err := address.Address{Script: lock, Network: w.network}.Encode()
	if err != nil {
		return nil, fmt.Errorf("encoding the miner address: %w", err)
	}

	// Built by hand rather than through collector.NewLiveCellIterator so the
	// caller's context reaches the indexer calls: that constructor falls back
	// to context.Background(), which would leave cell collection running
	// after the block that wanted it has moved on.
	iterator := &collector.LiveCellIterator{
		LiveCellGetter: cellGetter{rpc: w.rpc, ctx: ctx},
		SearchKey: &indexer.SearchKey{
			Script:           lock,
			ScriptType:       ckbtypes.ScriptTypeLock,
			ScriptSearchMode: ckbtypes.ScriptSearchModeExact,
			WithData:         true,
		},
		SearchOrder: indexer.SearchOrderAsc,
		Limit:       cellPageSize,
	}

	b := builder.NewCkbTransactionBuilder(ckbtypes.NetworkTest,
		&plainCells{inner: iterator, inflight: w.inflight})
	b.ScriptHandlers = []collector.ScriptHandler{
		&handler.Secp256k1Blake160SighashAllScriptHandler{
			CellDep:  w.sighashDep,
			CodeHash: w.sighashCodeHash,
		},
	}
	b.FeeRate = uint(w.feeRate)
	if err := b.AddChangeOutputByAddress(minerAddr); err != nil {
		return nil, fmt.Errorf("adding the change output: %w", err)
	}
	return b, nil
}

// send builds, signs and broadcasts a transaction, returning its hash.
func (w *wallet) send(ctx context.Context, b *builder.CkbTransactionBuilder) (string, error) {
	tx, err := b.Build()
	if err != nil {
		return "", fmt.Errorf("building the transaction: %w", err)
	}

	signed, err := signer.GetTransactionSignerInstance(w.network).
		SignTransaction(tx, &transaction.Context{Key: w.key})
	if err != nil {
		return "", fmt.Errorf("signing the transaction: %w", err)
	}
	if err := allLocksSigned(tx, signed); err != nil {
		return "", err
	}

	hash, err := w.rpc.SendTransaction(ctx, tx.TxView)
	if err != nil {
		return "", fmt.Errorf("sending the transaction: %w", err)
	}
	// Recorded only once the node has taken it: a transaction that was
	// refused has spent nothing, and treating its inputs as gone would strand
	// the wallet's capacity until the next restart.
	if w.inflight != nil {
		w.inflight.record(tx.TxView, w.minerLock())
	}
	return hash.String(), nil
}

// allLocksSigned checks that every lock this transaction spends under was
// actually signed.
//
// Only lock groups are counted. A type script forms a script group too — the
// commit and budget scripts each do — but it is code the chain runs, not
// something with a signature to give, so comparing against the group count
// outright would reject every transaction this package builds.
//
// The check earns its place by naming the cause. An unsigned lock comes back
// from the node as a script failure with a code and an index, which says
// nothing about why; here the reason is always the same, and always the
// miner's own doing: an input it does not hold the key for.
func allLocksSigned(tx *transaction.TransactionWithScriptGroups, signed []int) error {
	done := make(map[int]bool, len(signed))
	for _, i := range signed {
		done[i] = true
	}
	for i, group := range tx.ScriptGroups {
		if group.GroupType != ckbtypes.ScriptTypeLock || done[i] {
			continue
		}
		return fmt.Errorf("the lock on script group %d went unsigned; "+
			"an input is not owned by the miner key", i)
	}
	return nil
}

// cellGetter adapts this package's narrow view of a CKB node to the getter
// the SDK's iterator expects, and carries the caller's context into it.
type cellGetter struct {
	rpc nodeRPC
	ctx context.Context
}

// GetCells runs one page of the indexer query.
func (g cellGetter) GetCells(searchKey *indexer.SearchKey, order indexer.SearchOrder, limit uint64, afterCursor string) (*indexer.LiveCells, error) {
	return g.rpc.GetCells(g.ctx, searchKey, order, limit, afterCursor)
}

// plainCells is a cell iterator that yields only bare capacity: cells with no
// type script and no data.
//
// It exists to keep three different mistakes from happening, all of which
// look the same from here — an input that drags rules of its own into a
// transaction that was not built to satisfy them:
//
//   - A token marked by `spent_type_script` must not fund a prepayment
//     (R3.4), and once spent it must keep its mark and stay away from the
//     mining addr (R4.1, R4.2), none of which the transactions built here do.
//   - This miner's own budget cell lives under the same lock. Swept up as
//     change it would be destroyed, taking an allocation table that cannot be
//     rewritten with it (R3.1).
//   - So do its commit cells. Reclaiming one is deliberate and belongs to a
//     transaction of its own, not to whichever bid happens to need capacity.
//
// Filtering on the absence of a type script covers all three at once and
// stays correct as scripts are added, which a list of known type hashes would
// not.
type plainCells struct {
	inner    collector.CellIterator
	inflight *inFlight
	next     *ckbtypes.TransactionInput

	// live records what the indexer reported this pass, so the in-flight
	// bookkeeping can be pruned against it once the pass is over.
	live map[ckbtypes.OutPoint]bool
	// offChain is this wallet's own unconfirmed change, handed out after the
	// indexer's cells are exhausted.
	offChain []*ckbtypes.TransactionInput
	drained  bool
}

// HasNext advances past anything this wallet must not spend, and reports
// whether a usable cell remains.
//
// Three things are stepped over: cells carrying a type script or data, cells
// already committed to a transaction of this wallet's that has not been mined
// yet, and — once the indexer is exhausted — nothing, because what follows is
// this wallet's own unconfirmed change, which the indexer cannot know about.
func (p *plainCells) HasNext() bool {
	if p.live == nil {
		p.live = map[ckbtypes.OutPoint]bool{}
	}

	for p.next == nil && p.inner.HasNext() {
		cell := p.inner.Next()
		if cell == nil || cell.Output == nil {
			continue
		}
		if cell.OutPoint != nil {
			p.live[*cell.OutPoint] = true
		}
		if cell.Output.Type != nil || len(cell.OutputData) > 0 {
			continue
		}
		if p.inflight != nil && p.inflight.isSpent(cell.OutPoint) {
			continue
		}
		p.next = cell
	}
	if p.next != nil {
		return true
	}

	// The indexer has nothing more. Everything it reported is accounted for,
	// so this is the moment the in-flight bookkeeping can be pruned — and the
	// moment the change it is holding has to be offered, since a wallet that
	// has just spent its only cell has nothing else left to build with.
	if !p.drained {
		p.drained = true
		if p.inflight != nil {
			p.inflight.settle(p.live)
			p.offChain = p.inflight.offChain()
		}
	}
	for len(p.offChain) > 0 {
		cell := p.offChain[0]
		p.offChain = p.offChain[1:]
		if cell != nil && cell.Output != nil {
			p.next = cell
			return true
		}
	}
	return false
}

// Next returns the cell HasNext found. Callers must call HasNext first, which
// is how the SDK's own iterators are used.
func (p *plainCells) Next() *ckbtypes.TransactionInput {
	if !p.HasNext() {
		return nil
	}
	cell := p.next
	p.next = nil
	return cell
}

// AwaitCommitted blocks until `txHash` is in an L1 block, and returns the
// number of the block holding it.
//
// Anything that depends on a transaction's outputs has to wait for this, and
// not only for the hash. A cell dep pointing into the pool is refused outright
// ("new Tx contains cell deps from conflicts"), and a prepayment is not
// evidence of anything until it is committed — the whole payment path reads
// only committed transactions for exactly that reason.
//
// It polls rather than subscribing: one transaction, once, at the speed L1
// produces blocks. `ctx` bounds the wait; without a deadline on it this waits
// forever, which is the right behaviour for a chain that has merely stalled
// and the wrong one for a transaction that was dropped.
func (w *wallet) AwaitCommitted(ctx context.Context, txHash string) (uint64, error) {
	hash, err := parseHash(txHash)
	if err != nil {
		return 0, fmt.Errorf("tx hash %q: %w", txHash, err)
	}
	onlyCommitted := true

	ticker := time.NewTicker(awaitPollInterval)
	defer ticker.Stop()
	for {
		tx, err := w.rpc.GetTransaction(ctx, hash, nil, &onlyCommitted)
		if err != nil {
			return 0, fmt.Errorf("asking L1 about %s: %w", txHash, err)
		}
		if tx != nil && tx.TxStatus != nil &&
			tx.TxStatus.Status == ckbtypes.TransactionStatusCommitted &&
			tx.TxStatus.BlockNumber != nil {
			return *tx.TxStatus.BlockNumber, nil
		}

		select {
		case <-ctx.Done():
			return 0, fmt.Errorf("waiting for %s to be committed: %w", txHash, ctx.Err())
		case <-ticker.C:
		}
	}
}
