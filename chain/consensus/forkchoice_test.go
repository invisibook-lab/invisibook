package consensus

import (
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/yu-org/yu/common"
	"github.com/yu-org/yu/core/types"
)

// goalBlock builds a block whose recomputed goal is exactly `goal`.
//
// The VRF factor is pinned to 1 so that goal == amount, which keeps the
// arithmetic in these tests readable: CalcBlockScore multiplies the payment
// by the first 8 bytes of the VRF output.
func goalBlock(t *testing.T, hash string, height common.BlockNum, goal int64) *types.Block {
	t.Helper()

	vrfOutput := make([]byte, 32)
	binary.BigEndian.PutUint64(vrfOutput[:8], 1)

	extra, err := EncodeConsensusData(&ConsensusData{
		VRFResult: &VRFResult{Output: vrfOutput, Proof: []byte("proof")},
		L1Payment: NewL1Payment("0xprepay", big.NewInt(goal), randA, "minerA", ""),
		// Deliberately inconsistent with the real goal: nothing may read it.
		BlockScore: "999999999",
	})
	if err != nil {
		t.Fatalf("encoding consensus data: %v", err)
	}

	return &types.Block{Header: &types.Header{
		Hash:   blockHash(hash),
		Height: height,
		Extra:  extra,
	}}
}

// branch assembles one fork out of blocks.
func branch(blocks ...*types.Block) *types.Fork {
	return &types.Fork{Blocks: blocks}
}

// The rule the whole design rests on: the branch with the largest sum wins,
// even though a rival beats it at every height taken on its own. Choosing per
// height would let an attacker redirect the chain by outbidding at one point
// instead of buying every height after it.
//
// The numbers are picked so that A wins on the sum and on nothing else:
//
//	A: 40 + 45 + 35 = 120      B: 50 + 20 + 40 = 110
//
// A's first block (40 < 50), last block (35 < 40) and best single block
// (45 < 50) all lose to B's. So this test fails not only if the sum is
// dropped, but if it degrades into reading the first block, the last one, or
// the highest one — each of which would hand the branch to B.
func TestChooseForkPrefersTheLargestCumulativeGoal(t *testing.T) {
	a := branch(
		goalBlock(t, "0xa1", 1, 40),
		goalBlock(t, "0xa2", 2, 45),
		goalBlock(t, "0xa3", 3, 35),
	)
	b := branch(
		goalBlock(t, "0xb1", 1, 50),
		goalBlock(t, "0xb2", 2, 20),
		goalBlock(t, "0xb3", 3, 40),
	)

	got := ChooseFork([]*types.Fork{b, a})

	if len(got.Blocks) != 3 || got.Blocks[0].Hash != blockHash("0xa1") {
		t.Fatalf("chose the branch starting %v, want the one starting 0xa1", got.Blocks[0].Hash)
	}
}

// A longer branch does not win on length alone.
func TestChooseForkIgnoresLength(t *testing.T) {
	short := branch(goalBlock(t, "0xs1", 1, 1000))
	long := branch(
		goalBlock(t, "0xl1", 1, 10),
		goalBlock(t, "0xl2", 2, 10),
		goalBlock(t, "0xl3", 3, 10),
	)

	got := ChooseFork([]*types.Fork{long, short})

	if len(got.Blocks) != 1 || got.Blocks[0].Hash != blockHash("0xs1") {
		t.Fatal("the shorter branch with the larger cumulative goal must win")
	}
}

// The producer's own BlockScore is not evidence. A block claiming an enormous
// score must score exactly what its payment and VRF output imply.
func TestChooseForkIgnoresTheClaimedBlockScore(t *testing.T) {
	// Both carry BlockScore 999999999; only the real goals differ.
	weak := branch(goalBlock(t, "0xw1", 1, 10))
	strong := branch(goalBlock(t, "0xs1", 1, 20))

	got := ChooseFork([]*types.Fork{weak, strong})

	if got.Blocks[0].Hash != blockHash("0xs1") {
		t.Fatal("scoring must come from the payment and VRF output, not the claimed field")
	}
}

// Equal sums need a settled answer, or two honest nodes could follow
// different chains indefinitely.
func TestChooseForkBreaksTiesByHash(t *testing.T) {
	high := branch(goalBlock(t, "0xff", 1, 100))
	low := branch(goalBlock(t, "0x11", 1, 100))

	got := ChooseFork([]*types.Fork{high, low})
	if got.Blocks[0].Hash != blockHash("0x11") {
		t.Fatalf("tie went to %s, want the smaller hash 0x11", got.Blocks[0].Hash)
	}

	// Order of enumeration must not change the outcome.
	got = ChooseFork([]*types.Fork{low, high})
	if got.Blocks[0].Hash != blockHash("0x11") {
		t.Fatal("the tie-break must not depend on enumeration order")
	}
}

// Two branches can share a prefix and diverge later. Comparing only the first
// block would compare a block with itself and settle nothing.
func TestChooseForkBreaksTiesAtTheRealDivergence(t *testing.T) {
	shared := goalBlock(t, "0xaa", 1, 100)
	high := branch(shared, goalBlock(t, "0xff", 2, 50))
	low := branch(shared, goalBlock(t, "0x11", 2, 50))

	got := ChooseFork([]*types.Fork{high, low})

	if len(got.Blocks) != 2 || got.Blocks[1].Hash != blockHash("0x11") {
		t.Fatalf("tie broke at %s, want the smaller hash at the point of divergence",
			got.Blocks[len(got.Blocks)-1].Hash)
	}
}

// A branch whose heights do not step by one is not the continuous run it
// presents itself as — the structure links the blocks, but the Height field
// is separate data and can disagree.
func TestChooseForkRejectsABranchWithLyingHeights(t *testing.T) {
	liar := branch(
		goalBlock(t, "0xl1", 1, 1000),
		goalBlock(t, "0xl2", 7, 1000), // claims 7, sits after 1
	)
	honest := branch(goalBlock(t, "0xh1", 1, 1))

	got := ChooseFork([]*types.Fork{liar, honest})

	if len(got.Blocks) != 1 || got.Blocks[0].Hash != blockHash("0xh1") {
		t.Fatal("a branch with non-consecutive heights must be discarded, however high it scores")
	}
}

// An unscoreable block takes its whole branch out of the running rather than
// counting as zero — otherwise including something unreadable could never
// hurt, and might help.
func TestChooseForkDiscardsBranchesItCannotScore(t *testing.T) {
	cases := []struct {
		name  string
		spoil func(*types.Block)
	}{
		{"unreadable extra", func(b *types.Block) { b.Extra = []byte("not json") }},
		{"no payment", func(b *types.Block) {
			extra, err := EncodeConsensusData(&ConsensusData{
				VRFResult: &VRFResult{Output: make([]byte, 32)},
			})
			if err != nil {
				t.Fatalf("encoding: %v", err)
			}
			b.Extra = extra
		}},
		{"short vrf output", func(b *types.Block) {
			extra, err := EncodeConsensusData(&ConsensusData{
				VRFResult: &VRFResult{Output: []byte{1, 2, 3}},
				L1Payment: NewL1Payment("0xprepay", big.NewInt(10), randA, "minerA", ""),
			})
			if err != nil {
				t.Fatalf("encoding: %v", err)
			}
			b.Extra = extra
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bad := goalBlock(t, "0xbad", 1, 1000000)
			tc.spoil(bad)
			honest := branch(goalBlock(t, "0xgood", 1, 1))

			got := ChooseFork([]*types.Fork{branch(bad), honest})

			if len(got.Blocks) != 1 || got.Blocks[0].Hash != blockHash("0xgood") {
				t.Fatal("a branch that cannot be scored must be out of the running")
			}
		})
	}
}

// A short VRF output must not reach CalcBlockScore, which slices 8 bytes
// unconditionally.
func TestChooseForkSurvivesAShortVRFOutput(t *testing.T) {
	extra, err := EncodeConsensusData(&ConsensusData{
		VRFResult: &VRFResult{Output: []byte{1}},
		L1Payment: NewL1Payment("0xprepay", big.NewInt(10), randA, "minerA", ""),
	})
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}
	block := goalBlock(t, "0xshort", 1, 1)
	block.Extra = extra

	// The assertion is that this returns at all rather than panicking.
	if got := ChooseFork([]*types.Fork{branch(block)}); got != nil {
		t.Fatalf("got %v, want nil for a branch that cannot be scored", got)
	}
}

func TestChooseForkWithNothingToChoose(t *testing.T) {
	for _, tc := range []struct {
		name  string
		forks []*types.Fork
	}{
		{"no forks at all", nil},
		{"an empty branch", []*types.Fork{branch()}},
		{"a nil branch", []*types.Fork{nil}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ChooseFork(tc.forks); got != nil {
				t.Fatalf("got %v, want nil", got)
			}
		})
	}
}

// Settled means anchored on L1 and opened on the L2 network — nothing to do
// with how far any rival trails.
func TestFinalizableCountCountsOpenedBlocks(t *testing.T) {
	canonical := []*types.Block{
		goalBlock(t, "0xa1", 1, 10),
		goalBlock(t, "0xa2", 2, 10),
	}
	opened := map[string]bool{
		canonical[0].Hash.String(): true,
		canonical[1].Hash.String(): true,
	}

	if got := FinalizableCount(canonical, opened); got != 2 {
		t.Fatalf("finalizable = %d, want 2", got)
	}
}

// Promotion applies staged state in height order, so the run has to stop at
// the first unopened block instead of stepping over it: writing a later
// block's changes on top of state its predecessor never laid down would
// corrupt the tables it touches.
func TestFinalizableCountStopsAtTheFirstUnopenedBlock(t *testing.T) {
	canonical := []*types.Block{
		goalBlock(t, "0xa1", 1, 10),
		goalBlock(t, "0xa2", 2, 10),
		goalBlock(t, "0xa3", 3, 10),
	}
	// The middle block has no opening; the one after it does.
	opened := map[string]bool{
		canonical[0].Hash.String(): true,
		canonical[2].Hash.String(): true,
	}

	if got := FinalizableCount(canonical, opened); got != 1 {
		t.Fatalf("finalizable = %d, want 1 — the run stops at the unopened block", got)
	}
}

func TestFinalizableCountWithNothingOpened(t *testing.T) {
	canonical := []*types.Block{goalBlock(t, "0xa1", 1, 10)}

	if got := FinalizableCount(canonical, nil); got != 0 {
		t.Fatalf("finalizable = %d with no openings at all, want 0", got)
	}
	if got := FinalizableCount(nil, map[string]bool{}); got != 0 {
		t.Fatalf("finalizable = %d for an empty branch, want 0", got)
	}
}

// canonical arrives from the chain, and Block embeds *Header — a nil entry or
// a headerless one would panic on Hash and take the node down with it. The
// run ends there instead.
func TestFinalizableCountStopsAtAnUnusableBlock(t *testing.T) {
	good := goalBlock(t, "0xa1", 1, 10)
	opened := map[string]bool{good.Hash.String(): true}

	for _, tc := range []struct {
		name  string
		blunt *types.Block
	}{
		{"a nil block", nil},
		{"a block with no header", &types.Block{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := FinalizableCount([]*types.Block{good, tc.blunt}, opened)
			if got != 1 {
				t.Fatalf("finalizable = %d, want 1 — the run ends at an unusable block", got)
			}
		})
	}
}

// The two lists must describe the same run of blocks. One finalizes blocks on
// the chain, the other promotes their staged writes, and a mismatch would
// record one branch's state under another branch's blocks — durably, with no
// way back.
func TestSettledBlocksPairsTheTwoViewsOfTheSameRun(t *testing.T) {
	blocks := []*types.Block{
		goalBlock(t, "0xa1", 1, 10),
		goalBlock(t, "0xa2", 2, 10),
		goalBlock(t, "0xa3", 3, 10),
	}
	// The third block has no opening, so the run stops at two.
	opened := map[string]bool{
		blocks[0].Hash.String(): true,
		blocks[1].Hash.String(): true,
	}

	settled, staged := settledBlocks(&types.Fork{Blocks: blocks}, opened)

	if len(settled) != 2 || len(staged) != 2 {
		t.Fatalf("settled=%d staged=%d, want 2 and 2", len(settled), len(staged))
	}
	for i := range settled {
		if staged[i].Hash != settled[i].Hash.String() {
			t.Fatalf("staged[%d].Hash = %s, want the block's own %s",
				i, staged[i].Hash, settled[i].Hash)
		}
		if staged[i].Height != settled[i].Height {
			t.Fatalf("staged[%d].Height = %d, want the block's own %d",
				i, staged[i].Height, settled[i].Height)
		}
	}
}

func TestSettledBlocksWithNothingSettled(t *testing.T) {
	blocks := []*types.Block{goalBlock(t, "0xa1", 1, 10)}

	if settled, staged := settledBlocks(&types.Fork{Blocks: blocks}, nil); settled != nil || staged != nil {
		t.Fatalf("settled=%v staged=%v, want nothing settled with no openings", settled, staged)
	}
	if settled, staged := settledBlocks(nil, nil); settled != nil || staged != nil {
		t.Fatal("a nil fork must settle nothing")
	}
}

// blockHash builds a distinct hash from a name.
//
// HexToHash will not do here: a name like "0xs1" is not valid hex, so it
// decodes to the zero hash — and every other invalid name decodes to the same
// zero hash. Assertions comparing two such names hold whichever block the
// code actually picked, which is no assertion at all.
func blockHash(name string) common.Hash {
	return common.BytesToHash([]byte(name))
}

// opened builds the eligibility set out of the blocks that are in the record.
func openedSet(blocks ...*types.Block) map[string]bool {
	out := make(map[string]bool, len(blocks))
	for _, block := range blocks {
		out[block.Hash.String()] = true
	}
	return out
}

// The regression this whole two-step split exists for: filtering has to
// happen before the comparison, not after it.
//
// Branch A carries one anchored block and then two that L1 can vouch for
// nothing about — a branch bought after the fact can only look like this,
// since its commitments could not have reached L1 at the time. On raw totals
// A wins:
//
//	A: 10 + 500 + 500 = 1010      B: 40 + 45 = 85
//
// but only A's first block is in the record, so the branches actually being
// compared are A: 10 and B: 85, and B is the main fork. Score first and A
// takes it, and the node then promotes A's block at height 1 over B's —
// irreversibly, on the strength of two blocks nobody ever paid L1 for.
func TestEligibleForksFiltersBeforeScoring(t *testing.T) {
	a1 := goalBlock(t, "0xa1", 1, 10)
	a2 := goalBlock(t, "0xa2", 2, 500)
	a3 := goalBlock(t, "0xa3", 3, 500)
	b1 := goalBlock(t, "0xb1", 1, 40)
	b2 := goalBlock(t, "0xb2", 2, 45)

	a, b := branch(a1, a2, a3), branch(b1, b2)
	// Everything on B is anchored and revealed; on A only the first block is.
	opened := openedSet(a1, b1, b2)

	// Scoring the branches as they stand gives the wrong answer, which is
	// what makes the order load-bearing rather than cosmetic.
	if got := ChooseFork([]*types.Fork{a, b}); got != a {
		t.Fatal("expected the unfiltered comparison to favour A; the test no longer shows what it is for")
	}

	got := ChooseFork(eligibleForks([]*types.Fork{a, b}, opened))
	if got == nil {
		t.Fatal("no branch chosen")
	}
	if len(got.Blocks) != 2 || got.Blocks[0] != b1 {
		t.Fatalf("chose the branch ending at %s, want B's anchored run", got.Blocks[len(got.Blocks)-1].Hash)
	}
}

// Truncation keeps a branch a branch: the run that survives starts at the
// fork point and has no gaps, so ChooseFork still compares continuous chains
// rather than a selection of blocks.
func TestEligibleForksTruncatesToTheLeadingRun(t *testing.T) {
	b1 := goalBlock(t, "0xb1", 1, 40)
	b2 := goalBlock(t, "0xb2", 2, 45)
	b3 := goalBlock(t, "0xb3", 3, 35)

	// b2 is missing from the record, so b3 cannot count either even though it
	// is in: a branch with a hole is not a branch.
	got := eligibleForks([]*types.Fork{branch(b1, b2, b3)}, openedSet(b1, b3))
	if len(got) != 1 {
		t.Fatalf("got %d branches, want 1", len(got))
	}
	if len(got[0].Blocks) != 1 || got[0].Blocks[0] != b1 {
		t.Fatalf("truncated to %d blocks, want just the leading run", len(got[0].Blocks))
	}
}

// A branch with nothing in the record is not a contender, and must not reach
// the comparison as an empty one either.
func TestEligibleForksDropsBranchesWithNothingAnchored(t *testing.T) {
	a1 := goalBlock(t, "0xa1", 1, 10)
	b1 := goalBlock(t, "0xb1", 1, 40)

	got := eligibleForks([]*types.Fork{branch(a1), branch(b1), nil}, openedSet(b1))
	if len(got) != 1 {
		t.Fatalf("got %d branches, want only the one with an anchored block", len(got))
	}
	if got[0].Blocks[0] != b1 {
		t.Fatal("kept the wrong branch")
	}
	if ChooseFork(eligibleForks([]*types.Fork{branch(a1)}, nil)) != nil {
		t.Fatal("chose a branch none of whose blocks are in the record")
	}
}
