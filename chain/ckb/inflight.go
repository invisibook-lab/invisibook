package ckb

import (
	"sync"

	ckbtypes "github.com/nervosnetwork/ckb-sdk-go/v2/types"
)

// inFlight remembers what this wallet's own unconfirmed transactions did, so
// the next one it builds does not contradict them.
//
// The indexer only knows what is on chain. A transaction that has been sent
// but not yet mined leaves it still reporting the cell that transaction
// spends as live, and not yet reporting the change it creates. Build the next
// transaction from that view and it picks the same input — which CKB reads
// not as a second transaction but as an attempt to replace the first, and
// refuses: "RBF rejected: Tx's current fee is …, expect it to >= … to replace
// old txs".
//
// That is not an edge case here. A block is anchored every few seconds and
// CKB's blocks are slower, so consecutive commitments are in flight together
// by default; without this, every second one fails.
type inFlight struct {
	mu sync.Mutex
	// spent holds the outputs consumed by transactions not yet mined.
	spent map[ckbtypes.OutPoint]bool
	// created holds the plain change those transactions produced, which is
	// what the next transaction has to spend instead.
	created map[ckbtypes.OutPoint]*ckbtypes.TransactionInput
}

func newInFlight() *inFlight {
	return &inFlight{
		spent:   map[ckbtypes.OutPoint]bool{},
		created: map[ckbtypes.OutPoint]*ckbtypes.TransactionInput{},
	}
}

// record takes note of a transaction that has just been sent.
//
// `lock` is the wallet's own lock: only change coming back to it is worth
// remembering, since only that is available to spend next.
func (f *inFlight) record(tx *ckbtypes.Transaction, lock *ckbtypes.Script) {
	if tx == nil {
		return
	}
	hash := tx.ComputeHash()
	lockHash := lock.Hash()

	f.mu.Lock()
	defer f.mu.Unlock()

	for _, input := range tx.Inputs {
		if input == nil || input.PreviousOutput == nil {
			continue
		}
		f.spent[*input.PreviousOutput] = true
		// A cell this wallet created and has now spent is of no further use
		// to anyone, including the bookkeeping.
		delete(f.created, *input.PreviousOutput)
	}

	for i, output := range tx.Outputs {
		// Only plain change: a cell with a type script carries rules this
		// wallet's transactions are not built to satisfy, which is the same
		// reason plainCells skips them on the way in.
		if output == nil || output.Type != nil || output.Lock.Hash() != lockHash {
			continue
		}
		if i < len(tx.OutputsData) && len(tx.OutputsData[i]) > 0 {
			continue
		}
		outPoint := ckbtypes.OutPoint{TxHash: hash, Index: uint32(i)}
		f.created[outPoint] = &ckbtypes.TransactionInput{
			OutPoint: &outPoint,
			Output:   output,
		}
	}
}

// offChain returns the change this wallet is still waiting to see on chain.
func (f *inFlight) offChain() []*ckbtypes.TransactionInput {
	f.mu.Lock()
	defer f.mu.Unlock()

	out := make([]*ckbtypes.TransactionInput, 0, len(f.created))
	for _, cell := range f.created {
		out = append(out, cell)
	}
	return out
}

// isSpent reports whether a live cell has already been committed to a
// transaction of this wallet's that has not been mined yet.
func (f *inFlight) isSpent(outPoint *ckbtypes.OutPoint) bool {
	if outPoint == nil {
		return false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.spent[*outPoint]
}

// settle drops the bookkeeping the chain has caught up with.
//
// `live` is every cell the indexer just reported. An input recorded as spent
// that the indexer no longer lists has had its transaction mined, and
// remembering it buys nothing; change that the indexer now lists is on chain
// and will be found the ordinary way. Pruning against the live set is what
// keeps this from growing for the life of the node, and it needs no notion of
// confirmation depth to do it.
func (f *inFlight) settle(live map[ckbtypes.OutPoint]bool) {
	f.mu.Lock()
	defer f.mu.Unlock()

	for outPoint := range f.spent {
		if !live[outPoint] {
			delete(f.spent, outPoint)
		}
	}
	for outPoint := range f.created {
		if live[outPoint] {
			delete(f.created, outPoint)
		}
	}
}
