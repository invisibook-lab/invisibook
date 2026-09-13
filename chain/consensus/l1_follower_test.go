package consensus

import (
	"context"
	"testing"

	"github.com/yu-org/yu/common"
	"github.com/yu-org/yu/core/types"
)

func hashOf(s string) common.Hash { return common.BytesToHash([]byte(s)) }

// newFollowerUnderTest builds the slice of ProofOfBuy that reads rulings.
// No chain is needed: followVerdict decides, it does not prune.
func newFollowerUnderTest(verdict L1Verdict) *ProofOfBuy {
	return &ProofOfBuy{
		l1Verdict:   verdict,
		canonicalAt: make(map[common.BlockNum]common.Hash),
	}
}

// blockAt builds a block carrying just the height and hash the follower reads.
func blockAt(height common.BlockNum, hash common.Hash) *types.Block {
	block := &types.Block{Header: &types.Header{}}
	block.Height = height
	block.Hash = hash
	return block
}

func TestCompareVerdict(t *testing.T) {
	mine := hashOf("mine")
	theirs := hashOf("theirs")
	verdict := []CanonicalL2Block{
		{Height: 10, Hash: mine, Goal: "500"},
		{Height: 11, Hash: theirs, Goal: "900"},
	}

	cases := []struct {
		name   string
		height common.BlockNum
		local  common.Hash
		want   VerdictOutcome
	}{
		{"L1 kept our block", 10, mine, Agreed},
		{"a rival outbid us", 11, mine, Orphaned},
		{"L1 has not ruled on this height", 12, mine, Unsettled},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := CompareVerdict(verdict, tc.height, tc.local); got != tc.want {
				t.Fatalf("CompareVerdict = %s, want %s", got, tc.want)
			}
		})
	}
}

// TestCompareVerdictTreatsAbsenceAsUnsettled pins the distinction that decides
// whether good blocks get thrown away: a height missing from a partial verdict
// is not the same as a height L1 ruled against.
func TestCompareVerdictTreatsAbsenceAsUnsettled(t *testing.T) {
	if got := CompareVerdict(nil, 10, hashOf("mine")); got != Unsettled {
		t.Fatalf("an empty verdict must leave the height unsettled, got %s", got)
	}
}

func TestMockL1VerdictRecordsPerSlot(t *testing.T) {
	mock := NewMockL1Verdict(false)
	ruling := []CanonicalL2Block{{Height: 7, Hash: hashOf("winner"), Goal: "900"}}
	mock.Rule("0xslot", ruling)

	got, err := mock.FetchVerdict(context.Background(), "0xslot")
	if err != nil {
		t.Fatalf("FetchVerdict: %v", err)
	}
	if len(got) != 1 || got[0].Height != 7 || got[0].Hash != hashOf("winner") {
		t.Fatalf("FetchVerdict = %+v, want the registered ruling", got)
	}

	if _, err := mock.FetchVerdict(context.Background(), "0xunknown"); err == nil {
		t.Fatal("an unregistered slot must report an error rather than an empty ruling")
	}
}

func TestMockL1VerdictFollowLocal(t *testing.T) {
	mock := NewMockL1Verdict(true)
	got, err := mock.FetchVerdict(context.Background(), "0xanything")
	if err != nil {
		t.Fatalf("followLocal must not error on unknown slots, got %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("followLocal must return an empty ruling, got %+v", got)
	}
}

// TestFollowVerdictReportsTheWinningBlock: on divergence the caller needs to
// know not just that it lost, but which block L1 chose, so it can rebuild the
// height with that one instead of racing to produce a second orphan.
func TestFollowVerdictReportsTheWinningBlock(t *testing.T) {
	mock := NewMockL1Verdict(false)
	pob := newFollowerUnderTest(mock)

	rival := hashOf("rival")
	pf := &pendingFinalization{block: blockAt(12, hashOf("ours")), l1TxHash: "0xslot"}
	mock.Rule("0xslot", []CanonicalL2Block{{Height: 12, Hash: rival, Goal: "900"}})

	outcome, canonical := pob.followVerdict(pf)
	if outcome != Orphaned {
		t.Fatalf("followVerdict = %s, want orphaned", outcome)
	}
	if canonical != rival {
		t.Fatalf("canonical = %s, want %s", canonical.String(), rival.String())
	}
}

func TestFollowVerdictKeepsAgreedBlocks(t *testing.T) {
	mock := NewMockL1Verdict(false)
	pob := newFollowerUnderTest(mock)

	local := hashOf("ours")
	pf := &pendingFinalization{block: blockAt(12, local), l1TxHash: "0xslot"}
	mock.Rule("0xslot", []CanonicalL2Block{{Height: 12, Hash: local, Goal: "900"}})

	if outcome, _ := pob.followVerdict(pf); outcome != Agreed {
		t.Fatalf("followVerdict = %s, want agreed", outcome)
	}
	if _, ruled := pob.expectedBlock(12); ruled {
		t.Fatal("a height this node won must not be pinned to a canonical hash")
	}
}

// TestExpectedBlockBookkeeping: a height L1 ruled on is pinned to that block
// until the chain refills it, then forgotten so the map cannot grow unbounded.
func TestExpectedBlockBookkeeping(t *testing.T) {
	pob := newFollowerUnderTest(nil)
	rival := hashOf("rival")

	if _, ruled := pob.expectedBlock(12); ruled {
		t.Fatal("an untouched height must not be pinned")
	}

	pob.pinToCanonical(12, rival)
	got, ruled := pob.expectedBlock(12)
	if !ruled || got != rival {
		t.Fatalf("expectedBlock(12) = %s/%v, want %s/true", got.String(), ruled, rival.String())
	}

	pob.forgetExpectedBlock(12)
	if _, ruled := pob.expectedBlock(12); ruled {
		t.Fatal("the ruling must be dropped once the height is refilled")
	}
}

// fakeChain records whether Chain.Finalize was reached, standing in for the
// parts of the chain the finality worker touches.
type fakeChain struct {
	finalized []common.BlockNum
}

func (f *fakeChain) Finalize(block *types.Block) error {
	f.finalized = append(f.finalized, block.Height)
	return nil
}

// TestOrphanedBlockIsNeverFinalized is the invariant the whole follower exists
// to protect: a block L1 ruled against must not reach finalization on either
// the chain or the state, no matter that its submission was confirmed.
func TestOrphanedBlockIsNeverFinalized(t *testing.T) {
	mock := NewMockL1Verdict(false)
	pob := newFollowerUnderTest(mock)
	chain := &fakeChain{}

	pf := &pendingFinalization{block: blockAt(12, hashOf("ours")), l1TxHash: "0xslot"}
	mock.Rule("0xslot", []CanonicalL2Block{{Height: 12, Hash: hashOf("rival"), Goal: "900"}})

	// Mirrors the worker's decision: finalize only on Agreed.
	if outcome, _ := pob.followVerdict(pf); outcome == Agreed {
		_ = chain.Finalize(pf.block)
	}

	if len(chain.finalized) != 0 {
		t.Fatalf("orphaned block reached finalization at heights %v", chain.finalized)
	}
}

// TestUnsettledBlockIsNeverFinalized covers the other half: L1 confirming the
// submission is not L1 ruling on the height, and a block must wait for the
// ruling rather than for the confirmation.
func TestUnsettledBlockIsNeverFinalized(t *testing.T) {
	mock := NewMockL1Verdict(false)
	pob := newFollowerUnderTest(mock)
	chain := &fakeChain{}

	pf := &pendingFinalization{block: blockAt(12, hashOf("ours")), l1TxHash: "0xslot"}
	// The slot landed, but L1 has ruled on other heights only.
	mock.Rule("0xslot", []CanonicalL2Block{{Height: 11, Hash: hashOf("other"), Goal: "700"}})

	outcome, _ := pob.followVerdict(pf)
	if outcome != Unsettled {
		t.Fatalf("followVerdict = %s, want unsettled", outcome)
	}
	if outcome == Agreed {
		_ = chain.Finalize(pf.block)
	}
	if len(chain.finalized) != 0 {
		t.Fatalf("unsettled block reached finalization at heights %v", chain.finalized)
	}
	if _, ruled := pob.expectedBlock(12); ruled {
		t.Fatal("an unsettled height must not be pinned to a canonical hash")
	}
}
