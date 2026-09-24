package consensus

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"

	"github.com/sirupsen/logrus"

	"github.com/yu-org/yu/core/types"

	"github.com/invisibook-lab/invisibook/store"
)

// vrfGoalBytes is how many bytes of the VRF output the goal is derived from.
// CalcBlockScore slices exactly this many, so anything shorter has to be
// turned away before it gets there rather than panicking inside it.
const vrfGoalBytes = 8

// ChooseFork returns the canonical branch among `forks`, or nil when none of
// them can be weighed.
//
// `forks` is what the chain's CandidateForks hands back: every branch off the
// last finalized block, one per tip, each ordered from the finalized block's
// child upwards. Fetching them is the caller's business — taking them as data
// leaves this a function of its argument alone, with no chain behind it, no
// error path of its own, and nothing to stub out in a test.
//
// The rule is the whitepaper's §8.1: among the branches off the last
// finalized block, take the one whose cumulative goal is largest. Both halves
// of that carry weight. **Cumulative**, because comparing a single height's
// goal would let an attacker redirect the canonical chain by outbidding at
// one point, instead of having to buy every height after it — "to rewrite
// history you have to buy history again". **Continuous**, so that nobody can
// staple together the best-scoring block from each height into a branch they
// never actually won.
//
// Continuity needs no pass of its own here. yu builds each branch by walking
// prev_hash down from the finalized block, so a gap is not even
// representable: a block at h+2 has nothing to point at when h+1 is missing.
// What a block can still lie about is its own Height field, and that is what
// branchScore checks.
//
// Nothing here verifies a block. Whether a block is well-formed, paid for and
// signed by its producer is decided elsewhere (VerifyBlockIntegrity, the V1–V8
// checks); this function only weighs branches made of blocks that got that
// far.
func ChooseFork(forks []*types.Fork) *types.Fork {
	var (
		best      *types.Fork
		bestScore *big.Int
	)
	for _, fork := range forks {
		if fork == nil || len(fork.Blocks) == 0 {
			continue
		}

		score, err := branchScore(fork.Blocks)
		if err != nil {
			// Out of the running, not scored as zero: a branch holding a
			// block whose goal cannot be established is not a candidate at
			// all. Scoring it would invite an attacker to improve his
			// standing by including something unreadable.
			logrus.Warnf("PoB: discarding a fork ending at %s: %v",
				fork.Blocks[len(fork.Blocks)-1].Hash, err)
			continue
		}

		if best == nil || score.Cmp(bestScore) > 0 {
			best, bestScore = fork, score
			continue
		}
		// Equal cumulative goals are vanishingly unlikely but need a settled
		// answer all the same, or two honest nodes could follow different
		// chains forever.
		if score.Cmp(bestScore) == 0 && hashOrderWins(fork.Blocks, best.Blocks) {
			best, bestScore = fork, score
		}
	}
	return best
}

// FinalizableCount returns how many blocks at the start of `canonical` are
// settled, and so may be written down for good.
//
// The test is the protocol's, and scores play no part in it: a block is
// settled once its commitment sits in an L1 block and its opening has gone
// out on the L2 network. How far any rival trails does not enter into it.
//
// That is what the L1 backup is for (§8.2). A commitment that reached an L1
// block carries that block's height with it, while a branch bought after the
// fact can only carry commitments that reached L1 recently — so the question
// is never who scored higher, but whose history was actually there at the
// time. A later branch cannot unseat a block already anchored and opened,
// however much it spends. Cumulative goal decides which branch to follow;
// L1's timestamps decide when following it becomes irreversible.
//
// `opened` holds the hashes of blocks this node has openings for, its own
// included — broadcastReveal stores a reveal before sending it. Holding a
// reveal is itself the evidence that the commitment is on L1: it names the L1
// block and transaction the commitment landed in, and the protocol forbids
// revealing before that (§9.6).
//
// The run stops at the first unsettled block rather than stepping over it.
// Promotion applies staged state in height order, so skipping one would write
// a later block's changes on top of state its predecessor never laid down.
func FinalizableCount(canonical []*types.Block, opened map[string]bool) int {
	for i, block := range canonical {
		if block == nil || block.Header == nil || !opened[block.Hash.String()] {
			return i
		}
	}
	return len(canonical)
}

// settledBlocks returns the leading run of `fork` that is settled, given as
// both the blocks themselves and the staging layer's view of them.
//
// The pair is built here rather than by the caller so the two lists cannot
// drift apart. They are consumed by different things — one finalizes blocks
// on the chain, the other promotes their staged writes — and a mismatch
// between them would durably record one branch's state under another
// branch's blocks, with no way back.
func settledBlocks(fork *types.Fork, opened map[string]bool) ([]*types.Block, []store.Block) {
	if fork == nil {
		return nil, nil
	}
	n := FinalizableCount(fork.Blocks, opened)
	if n == 0 {
		return nil, nil
	}

	settled := fork.Blocks[:n]
	staged := make([]store.Block, n)
	for i, block := range settled {
		staged[i] = store.Block{Height: block.Height, Hash: block.Hash.String()}
	}
	return settled, staged
}

// branchScore sums the goals along one branch.
//
// `blocks` must be ordered from the finalized block's child upwards, which is
// how CandidateForks builds them.
func branchScore(blocks []*types.Block) (*big.Int, error) {
	total := new(big.Int)
	for i, block := range blocks {
		if block == nil || block.Header == nil {
			return nil, errors.New("branch holds a block with no header")
		}
		// The structure already guarantees each block hangs off the one
		// before it; the Height field is separate data and can disagree with
		// that. A branch whose heights do not step by one is not the
		// continuous run it presents itself as.
		if i > 0 && block.Height != blocks[i-1].Height+1 {
			return nil, fmt.Errorf("block %s claims height %d after height %d",
				block.Hash, block.Height, blocks[i-1].Height)
		}

		goal, err := blockGoal(block)
		if err != nil {
			return nil, fmt.Errorf("block %s: %w", block.Hash, err)
		}
		total.Add(total, goal)
	}
	return total, nil
}

// blockGoal recomputes a block's goal from its own consensus data.
//
// The BlockScore the producer wrote is deliberately ignored. Reading it would
// mean taking a miner's word for its own standing, and a miner that could
// name its own goal would need no payment at all. verifyCandidate has always
// recomputed rather than trusted that field; this does the same.
func blockGoal(block *types.Block) (*big.Int, error) {
	cdata, err := DecodeConsensusData(block.Extra)
	if err != nil {
		return nil, fmt.Errorf("decoding consensus data: %w", err)
	}
	if cdata.L1Payment == nil || cdata.L1Payment.Amount == nil {
		return nil, errors.New("carries no payment to score")
	}
	if cdata.VRFResult == nil || len(cdata.VRFResult.Output) < vrfGoalBytes {
		return nil, fmt.Errorf("carries no usable VRF output (need %d bytes)", vrfGoalBytes)
	}
	return CalcBlockScore(cdata.L1Payment.Amount, cdata.VRFResult.Output), nil
}

// hashOrderWins reports whether branch `a` beats `b` on the tie-break: at the
// first position where the two differ, a's block hash is the smaller.
//
// Comparing only the first block would not settle it. Two branches can share
// a prefix and part company further up, and there their first blocks are the
// same block — the fork point that matters is wherever they actually diverge.
func hashOrderWins(a, b []*types.Block) bool {
	for i := 0; i < len(a) && i < len(b); i++ {
		if cmp := bytes.Compare(a[i].Hash.Bytes(), b[i].Hash.Bytes()); cmp != 0 {
			return cmp < 0
		}
	}
	// One is a prefix of the other, which CandidateForks does not produce —
	// it returns one branch per tip, and a prefix has a child. Settled anyway
	// so the comparison is total.
	return len(a) < len(b)
}
