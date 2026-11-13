package consensus

import (
	"bytes"
	"math/big"

	"github.com/yu-org/yu/common"
	"github.com/yu-org/yu/core/types"
)

// vrfGoalBytes is how many bytes of the VRF output the goal is derived from.
// CalcBlockScore slices exactly this many, so anything shorter has to be
// turned away before it gets there rather than panicking inside it.
const vrfGoalBytes = 8

// ScoredHeader is a header that passed VerifyAnchoredHeader, with its goal.
type ScoredHeader struct {
	Header *types.Header
	Goal   *big.Int
}

// ChooseBatch returns the canonical run of one batch: `size` headers at
// heights `first` through `first+size-1`, each hanging off the one before and
// the first off `parent`, with the largest cumulative goal among all such runs
// in `candidates`. It returns nil when `candidates` hold no complete run.
//
// Only complete runs compete. A run missing a height is not a smaller
// candidate but no candidate: k is chosen so that an honest L1 producer packs
// the batch inside its window, so an incomplete run is one the network did
// not finish, not one that lost.
//
// Continuity is what stops a run being stapled together out of the
// best-scoring header at each height: every header must name the previous one
// as its parent. Equal totals — vanishingly unlikely — go to the run whose
// hash is smaller at the first height where the runs differ, so every node
// settles them the same way.
//
// `candidates` must already be verified; duplicates of one header are fine.
// It is a pure function of its arguments so it can be tested on its own.
func ChooseBatch(parent common.Hash, first common.BlockNum, size uint64, candidates []*ScoredHeader) []*types.Header {
	// Children by parent hash, each header once.
	children := make(map[common.Hash][]*ScoredHeader)
	seen := make(map[common.Hash]bool)
	for _, c := range candidates {
		if c == nil || c.Header == nil || seen[c.Header.Hash] {
			continue
		}
		seen[c.Header.Hash] = true
		children[c.Header.PrevHash] = append(children[c.Header.PrevHash], c)
	}

	var (
		best      []*types.Header
		bestScore *big.Int
		run       = make([]*types.Header, 0, size)
	)
	// walk extends `run` from the header whose hash is `tip`, at offset
	// `depth` into the batch, recording every complete run it reaches.
	var walk func(tip common.Hash, depth uint64, total *big.Int)
	walk = func(tip common.Hash, depth uint64, total *big.Int) {
		if depth == size {
			if best == nil || total.Cmp(bestScore) > 0 ||
				(total.Cmp(bestScore) == 0 && hashOrderWins(run, best)) {
				best = append([]*types.Header(nil), run...)
				bestScore = new(big.Int).Set(total)
			}
			return
		}
		want := first + common.BlockNum(depth)
		for _, c := range children[tip] {
			if c.Header.Height != want {
				continue
			}
			run = append(run, c.Header)
			walk(c.Header.Hash, depth+1, new(big.Int).Add(total, c.Goal))
			run = run[:len(run)-1]
		}
	}
	walk(parent, 0, new(big.Int))
	return best
}

// hashOrderWins reports whether run `a` beats `b` on the tie-break: at the
// first position where the two differ, a's hash is the smaller.
func hashOrderWins(a, b []*types.Header) bool {
	for i := 0; i < len(a) && i < len(b); i++ {
		if cmp := bytes.Compare(a[i].Hash.Bytes(), b[i].Hash.Bytes()); cmp != 0 {
			return cmp < 0
		}
	}
	return false
}
