package consensus

import (
	"math/big"
	"testing"

	"github.com/yu-org/yu/common"
	"github.com/yu-org/yu/core/types"
)

// blockHash names a test block by a readable string.
//
// HexToHash will not do here: a name like "0xs1" is not valid hex, so it
// decodes to the zero hash — and every other invalid name decodes to the same
// zero hash. Assertions comparing two such names hold whichever block the
// code actually picked, which is no assertion at all.
func blockHash(name string) common.Hash {
	return common.BytesToHash([]byte(name))
}

// scored builds a verified header named `name` at `height`, hanging off the
// block named `parent`, worth `goal`.
func scored(name, parent string, height common.BlockNum, goal int64) *ScoredHeader {
	return &ScoredHeader{
		Header: &types.Header{Hash: blockHash(name), PrevHash: blockHash(parent), Height: height},
		Goal:   big.NewInt(goal),
	}
}

// assertRun checks that a chosen run is exactly the named headers, in order.
func assertRun(t *testing.T, got []*types.Header, want ...string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("chose %d headers, want %v", len(got), want)
	}
	for i, name := range want {
		if got[i].Hash != blockHash(name) {
			t.Fatalf("position %d is %s, want %s", i, got[i].Hash, name)
		}
	}
}

// The run with the largest sum wins, even though a rival beats it at every
// height taken on its own:
//
//	A: 40 + 45 + 35 = 120      B: 50 + 20 + 40 = 110
//
// A's first, last and best single header all lose to B's, so this fails if
// the sum degrades into reading any one of them.
func TestChooseBatchPrefersTheLargestCumulativeGoal(t *testing.T) {
	candidates := []*ScoredHeader{
		scored("a1", "tip", 4, 40), scored("a2", "a1", 5, 45), scored("a3", "a2", 6, 35),
		scored("b1", "tip", 4, 50), scored("b2", "b1", 5, 20), scored("b3", "b2", 6, 40),
	}

	assertRun(t, ChooseBatch(blockHash("tip"), 4, 3, candidates), "a1", "a2", "a3")
}

// Only complete runs compete. A run that stops short of the batch's last
// height is no candidate at all, however much it scored.
func TestChooseBatchRequiresACompleteBatch(t *testing.T) {
	candidates := []*ScoredHeader{
		scored("a1", "tip", 4, 1), scored("a2", "a1", 5, 1), scored("a3", "a2", 6, 1),
		scored("b1", "tip", 4, 1000), scored("b2", "b1", 5, 1000),
	}

	assertRun(t, ChooseBatch(blockHash("tip"), 4, 3, candidates), "a1", "a2", "a3")
}

// A run must hang off the last decided block and be linked header to header.
// Splicing the best header at each height out of different runs is exactly
// what continuity forbids.
func TestChooseBatchRequiresContinuity(t *testing.T) {
	candidates := []*ScoredHeader{
		scored("a1", "tip", 4, 10), scored("a2", "a1", 5, 10), scored("a3", "a2", 6, 10),
		// High scorers that do not link: b1 hangs off another parent, and c2
		// names a parent nobody has.
		scored("b1", "elsewhere", 4, 1000), scored("b2", "b1", 5, 1000), scored("b3", "b2", 6, 1000),
		scored("c2", "missing", 5, 1000),
	}

	assertRun(t, ChooseBatch(blockHash("tip"), 4, 3, candidates), "a1", "a2", "a3")
}

// A header claiming the wrong height for its position does not extend a run.
func TestChooseBatchRejectsLyingHeights(t *testing.T) {
	candidates := []*ScoredHeader{
		scored("a1", "tip", 4, 10), scored("a2", "a1", 7, 10), scored("a3", "a2", 6, 10),
	}

	if got := ChooseBatch(blockHash("tip"), 4, 3, candidates); got != nil {
		t.Fatalf("chose %v from a run with a wrong height", got)
	}
}

// Equal totals need a settled answer, or two honest nodes could decide
// differently: the smaller hash at the first differing position wins, and
// that position is where the runs actually part, not their first header.
func TestChooseBatchBreaksTiesAtTheRealDivergence(t *testing.T) {
	candidates := []*ScoredHeader{
		scored("s1", "tip", 4, 10),
		scored("z2", "s1", 5, 10), scored("z3", "z2", 6, 10),
		scored("b2", "s1", 5, 10), scored("b3", "b2", 6, 10),
	}

	assertRun(t, ChooseBatch(blockHash("tip"), 4, 3, candidates), "s1", "b2", "b3")
}

// The same header may be submitted by several parties; it counts once.
func TestChooseBatchCountsADuplicateOnce(t *testing.T) {
	candidates := []*ScoredHeader{
		scored("a1", "tip", 4, 10), scored("a1", "tip", 4, 10), scored("a2", "a1", 5, 10),
	}

	assertRun(t, ChooseBatch(blockHash("tip"), 4, 2, candidates), "a1", "a2")
}

func TestChooseBatchWithNothingToChoose(t *testing.T) {
	if got := ChooseBatch(blockHash("tip"), 4, 3, nil); got != nil {
		t.Fatalf("chose %v from nothing", got)
	}
}
