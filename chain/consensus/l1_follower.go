package consensus

import (
	"context"
	"fmt"
	"sync"

	"github.com/sirupsen/logrus"

	"github.com/yu-org/yu/common"
)

// CanonicalL2Block is L1's ruling for one L2 height: of all the blocks miners
// submitted for it, this is the one L1 picked by max(goal).
type CanonicalL2Block struct {
	// Height is the L2 block height this ruling covers.
	Height common.BlockNum `json:"l2_block_height"`
	// Hash is the L2 block L1 settled on for that height.
	Hash common.Hash `json:"l2_block_hash"`
	// Goal is the winning score, as a decimal string.
	Goal string `json:"goal"`
}

// L1Verdict reads back the rulings L1 has made.
//
// Fork choice does not happen on L2: miners submit `(header, goal)` and the L1
// contract picks the highest goal at each height. This interface is the other
// half of that arrangement — the L2 node's way of learning what was decided.
type L1Verdict interface {
	// FetchVerdict returns L1's ruling for every L2 height settled by the L1
	// block that included `l1TxHash`, in ascending height order.
	//
	// That set is the L1 slot: the L2 blocks produced while one L1 block was
	// being mined, all decided together the moment it landed.
	FetchVerdict(ctx context.Context, l1TxHash string) ([]CanonicalL2Block, error)
}

// VerdictOutcome is what comparing one local block against L1's ruling yields.
type VerdictOutcome int

const (
	// Agreed means L1 settled on this node's own block for that height.
	Agreed VerdictOutcome = iota
	// Orphaned means L1 settled on a different block: a rival outbid this
	// node, and the local block at that height is off the canonical chain.
	Orphaned
	// Unsettled means L1 has not ruled on that height yet.
	Unsettled
)

// String renders the outcome for logs.
func (o VerdictOutcome) String() string {
	switch o {
	case Agreed:
		return "agreed"
	case Orphaned:
		return "orphaned"
	default:
		return "unsettled"
	}
}

// CompareVerdict reports how the local block at `height` with hash `localHash`
// fares against `verdict`.
//
// `verdict` is L1's ruling for one slot and need not be sorted or complete: a
// height missing from it is Unsettled, not orphaned. Treating "absent" as
// orphaned would discard perfectly good blocks whenever a verdict arrives
// partial.
func CompareVerdict(verdict []CanonicalL2Block, height common.BlockNum, localHash common.Hash) VerdictOutcome {
	for _, ruling := range verdict {
		if ruling.Height != height {
			continue
		}
		if ruling.Hash == localHash {
			return Agreed
		}
		return Orphaned
	}
	return Unsettled
}

// canonicalHashAt returns the block L1 settled on at `height` within `verdict`.
func canonicalHashAt(verdict []CanonicalL2Block, height common.BlockNum) common.Hash {
	for _, ruling := range verdict {
		if ruling.Height == height {
			return ruling.Hash
		}
	}
	return common.Hash{}
}

// MockL1Verdict stands in for a real L1 client. Rulings are registered per L1
// transaction, so a test can describe exactly which slot each submission fell
// into and what L1 decided for it.
type MockL1Verdict struct {
	mu sync.Mutex
	// bySlot maps an L1 tx hash to the ruling of the L1 block it landed in.
	bySlot map[string][]CanonicalL2Block
	// followLocal, when true, makes an unregistered submission come back as a
	// verdict agreeing with whatever was submitted. It keeps single-node
	// development running without every block having to be registered.
	followLocal bool
}

// NewMockL1Verdict builds a mock. With `followLocal` set, any submission this
// mock has not been told about is reported as having won its height, which is
// the only sane default for a node that is the sole miner.
func NewMockL1Verdict(followLocal bool) *MockL1Verdict {
	return &MockL1Verdict{bySlot: make(map[string][]CanonicalL2Block), followLocal: followLocal}
}

// Rule registers L1's ruling for the slot that `l1TxHash` landed in.
func (m *MockL1Verdict) Rule(l1TxHash string, verdict []CanonicalL2Block) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bySlot[l1TxHash] = verdict
}

// FetchVerdict returns the registered ruling, or an empty one.
func (m *MockL1Verdict) FetchVerdict(_ context.Context, l1TxHash string) ([]CanonicalL2Block, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if verdict, ok := m.bySlot[l1TxHash]; ok {
		return verdict, nil
	}
	if m.followLocal {
		return nil, nil
	}
	return nil, fmt.Errorf("no verdict recorded for l1_tx=%s", l1TxHash)
}

// followVerdict asks L1 what it settled on at this block's height and reports
// the answer. It only decides — acting on an Orphaned verdict is the caller's
// job, which keeps the reading of a ruling separate from the destruction it
// triggers.
//
// `pf` must already be confirmed on L1. The returned hash is the block L1 chose
// and is meaningful only alongside Orphaned.
func (p *ProofOfBuy) followVerdict(pf *pendingFinalization) (VerdictOutcome, common.Hash) {
	if p.l1Verdict == nil {
		// No verdict source wired: fall back to trusting confirmation alone.
		return Agreed, common.Hash{}
	}

	verdict, err := p.l1Verdict.FetchVerdict(context.Background(), pf.l1TxHash)
	if err != nil {
		logrus.Errorf("PoB: reading L1 verdict for height=%d (l1_tx=%s): %v",
			pf.block.Height, pf.l1TxHash, err)
		return Unsettled, common.Hash{}
	}

	switch outcome := CompareVerdict(verdict, pf.block.Height, pf.block.Hash); outcome {
	case Agreed:
		return Agreed, pf.block.Hash

	case Orphaned:
		canonical := canonicalHashAt(verdict, pf.block.Height)
		logrus.Warnf("PoB: L1 settled height=%d on %s, local block %s is orphaned",
			pf.block.Height, canonical.String(), pf.block.Hash.String())
		return Orphaned, canonical

	default:
		logrus.Infof("PoB: L1 has not ruled on height=%d yet, holding finalization", pf.block.Height)
		return Unsettled, common.Hash{}
	}
}

// dropOrphanedBlocks discards every local block from `height` upwards and
// restores the chain to the last block L1 has not overruled.
//
// Only that stretch goes: it is the L2 blocks produced while the deciding L1
// block was being mined. The one at `height` lost to a rival, and everything
// above it chains from a parent L1 did not accept. Heights below are untouched
// — they are either finalized already or still awaiting their own ruling.
//
// `PruneAfter` deletes only un-finalized blocks, so a block L1 already ruled
// for can never be dropped by a later divergence, and it clears the in-memory
// head when the head itself is pruned so the tip reloads from what survives.
// The pruned blocks' transactions stay in the tx store: they may well belong
// to the canonical block at the same height.
//
// `canonical` is what L1 settled on at `height`, recorded so this node accepts
// only that block when it rebuilds the height instead of racing to produce a
// second orphan.
func (p *ProofOfBuy) dropOrphanedBlocks(height common.BlockNum, canonical common.Hash) {
	p.pinToCanonical(height, canonical)

	// Prune takes its boundary from the chain itself rather than from this
	// height: everything above the last finalized block goes. The two agree
	// here — the finality worker rules on heights in order and stops at the
	// first one L1 has not settled, so by the time it sees an orphan every
	// height below has been finalized already.
	err := p.Chain.Prune()
	if err != nil {
		// The orphans are still on disk and the tip still points into them.
		// Stop producing rather than pile more blocks onto a chain that is
		// known bad and could not be cleaned up.
		logrus.Errorf("PoB: pruning orphaned blocks from height=%d failed: %v — halting production", height, err)
		p.halt()
		return
	}

	// Their writes go with them. Nothing in the main tables came from an
	// unsettled block, so only the staging layer has anything to undo.
	if err := p.pending.DropFrom(height); err != nil {
		logrus.Errorf("PoB: dropping staged writes from height=%d: %v — halting production", height, err)
		p.halt()
		return
	}

	logrus.Warnf("PoB: dropped local blocks from height=%d, rebuilding on L1's block %s",
		height, canonical.String())
}

// pinToCanonical records the block L1 settled on at `height`, the only one
// this node will accept when it rebuilds that height.
func (p *ProofOfBuy) pinToCanonical(height common.BlockNum, canonical common.Hash) {
	p.divergedMu.Lock()
	defer p.divergedMu.Unlock()
	p.canonicalAt[height] = canonical
}

// halt stops this node from producing any further block.
func (p *ProofOfBuy) halt() {
	p.divergedMu.Lock()
	defer p.divergedMu.Unlock()
	p.halted = true
}

// expectedBlock returns the block hash L1 settled on at `height`, if this node
// has been told of one. A height with a ruling accepts nothing else.
func (p *ProofOfBuy) expectedBlock(height common.BlockNum) (common.Hash, bool) {
	p.divergedMu.Lock()
	defer p.divergedMu.Unlock()
	hash, ok := p.canonicalAt[height]
	return hash, ok
}

// forgetExpectedBlock drops the recorded ruling for `height` once the chain has
// moved past it, so the map cannot grow without bound.
func (p *ProofOfBuy) forgetExpectedBlock(height common.BlockNum) {
	p.divergedMu.Lock()
	defer p.divergedMu.Unlock()
	delete(p.canonicalAt, height)
}

// halting reports whether this node has stopped producing because it could not
// clean up after a divergence.
func (p *ProofOfBuy) halting() bool {
	p.divergedMu.Lock()
	defer p.divergedMu.Unlock()
	return p.halted
}
