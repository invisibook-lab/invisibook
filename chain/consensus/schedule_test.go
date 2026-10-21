package consensus

import (
	"testing"

	"github.com/yu-org/yu/common"
)

// testSchedule is n=100, b=3, k=24, d=24.
func testSchedule() AnchorSchedule {
	return AnchorSchedule{GenesisL1Height: 100, BatchSize: 3, Window: 24, ConfirmDepth: 24}
}

func TestScheduleGroupsHeightsIntoBatches(t *testing.T) {
	s := testSchedule()
	cases := map[common.BlockNum]uint64{1: 0, 3: 0, 4: 1, 6: 1, 7: 2}
	for height, want := range cases {
		if got := s.BatchOf(height); got != want {
			t.Fatalf("height %d is in batch %d, want %d", height, got, want)
		}
	}
	if got := s.FirstHeight(1); got != 4 {
		t.Fatalf("batch 1 starts at %d, want 4", got)
	}
}

// Windows overlap: batch i opens at n+i and closes k blocks later.
func TestScheduleWindowsOverlap(t *testing.T) {
	s := testSchedule()
	for batch, want := range map[uint64][2]uint64{0: {100, 124}, 1: {101, 125}, 5: {105, 129}} {
		from, to := s.WindowOf(batch)
		if from != want[0] || to != want[1] {
			t.Fatalf("batch %d window = [%d, %d], want %v", batch, from, to, want)
		}
	}
}

// A batch is decided only once L1 is d blocks past the window's end, so a
// reorg cannot change what the window held after the decision.
func TestScheduleDecidesOnlyBelowTheConfirmDepth(t *testing.T) {
	s := testSchedule()
	if s.Decidable(0, 147) {
		t.Fatal("batch 0 decidable one block early")
	}
	if !s.Decidable(0, 148) {
		t.Fatal("batch 0 not decidable at 124 + 24")
	}
	if s.WindowClosed(0, 123) || !s.WindowClosed(0, 124) {
		t.Fatal("window 0 must close once L1 reaches its last block")
	}
	// A submission lands at the tip's successor at the earliest, so the
	// window counts as open one block before it starts.
	if s.WindowOpen(0, 98) || !s.WindowOpen(0, 99) {
		t.Fatal("window 0 must open once a submission can land at L1 100")
	}
}

func TestScheduleRefusesAZeroBatchSize(t *testing.T) {
	if _, err := NewAnchorSchedule(&Config{}); err == nil {
		t.Fatal("a zero batch size must be refused")
	}
}
