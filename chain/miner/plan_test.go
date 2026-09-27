package miner

import (
	"bytes"
	"math/big"
	"testing"
)

// zeroSource is a deterministic reader: every random draw comes out as zero.
type zeroSource struct{}

func (zeroSource) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

// seededSource is a repeatable, non-constant reader.
func seededSource() *bytes.Reader {
	buf := make([]byte, 1<<16)
	for i := range buf {
		buf[i] = byte(i*131 + i/7)
	}
	return bytes.NewReader(buf)
}

// TestEvenPlanSumsExactly checks that a total not divisible by the count is
// still handed out to the last shannon.
func TestEvenPlanSumsExactly(t *testing.T) {
	plan, err := BuildPlan(PlanRequest{Mode: ModeEven, From: 10, Count: 7, Total: big.NewInt(100)}, zeroSource{})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan) != 7 || plan[0].Height != 10 || plan[6].Height != 16 {
		t.Fatalf("heights wrong: %+v", plan)
	}
	if got := PlanTotal(plan); got.Cmp(big.NewInt(100)) != 0 {
		t.Fatalf("sum = %s, want 100", got)
	}
	// 100 / 7 = 14 remainder 2: two heights get one extra shannon.
	for _, a := range plan {
		if a.Amount.Int64() < 14 || a.Amount.Int64() > 15 {
			t.Errorf("height %d got %s, want 14 or 15", a.Height, a.Amount)
		}
	}
}

// TestRandomPlanSumsExactlyAndStaysInSpread checks the two properties that
// matter: the table balances, and no share strays past the requested spread.
func TestRandomPlanSumsExactlyAndStaysInSpread(t *testing.T) {
	total := big.NewInt(1_000_000_007)
	plan, err := BuildPlan(PlanRequest{
		Mode: ModeRandom, From: 1, Count: 100, Total: total, SpreadBps: 3000,
	}, seededSource())
	if err != nil {
		t.Fatal(err)
	}
	if got := PlanTotal(plan); got.Cmp(total) != 0 {
		t.Fatalf("sum = %s, want %s", got, total)
	}

	// Weights lie in [7000, 13000] around 10000, so a share is at most
	// 13000/7000 of another and never below 7000/13000 of the mean.
	mean := new(big.Int).Div(total, big.NewInt(100)).Int64()
	distinct := map[string]bool{}
	for _, a := range plan {
		distinct[a.Amount.String()] = true
		if a.Amount.Int64() < mean*7/13-1 || a.Amount.Int64() > mean*13/7+1 {
			t.Errorf("height %d got %s, outside the spread around mean %d", a.Height, a.Amount, mean)
		}
	}
	if len(distinct) < 50 {
		t.Errorf("only %d distinct shares out of 100: not random", len(distinct))
	}
}

// TestPlanRejectsBadRequests covers the inputs that must never reach L1.
func TestPlanRejectsBadRequests(t *testing.T) {
	cases := map[string]PlanRequest{
		"unknown mode":      {Mode: "weird", From: 1, Count: 1, Total: big.NewInt(10)},
		"no heights":        {Mode: ModeEven, From: 1, Count: 0, Total: big.NewInt(10)},
		"too many heights":  {Mode: ModeEven, From: 1, Count: MaxAllocations + 1, Total: big.NewInt(1 << 40)},
		"genesis height":    {Mode: ModeEven, From: 0, Count: 1, Total: big.NewInt(10)},
		"height overflow":   {Mode: ModeEven, From: 4294967295, Count: 5, Total: big.NewInt(100)},
		"no total":          {Mode: ModeEven, From: 1, Count: 3},
		"total below count": {Mode: ModeEven, From: 1, Count: 10, Total: big.NewInt(9)},
		"spread too wide":   {Mode: ModeRandom, From: 1, Count: 3, Total: big.NewInt(100), SpreadBps: 10000},
	}
	for name, req := range cases {
		if _, err := BuildPlan(req, seededSource()); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

// TestManualPlan checks a hand-made table is sorted, and that duplicates and
// non-positive amounts are refused.
func TestManualPlan(t *testing.T) {
	plan, err := BuildPlan(PlanRequest{Mode: ModeManual, Manual: []Allocation{
		{Height: 30, Amount: big.NewInt(5)},
		{Height: 10, Amount: big.NewInt(7)},
	}}, zeroSource{})
	if err != nil {
		t.Fatal(err)
	}
	if plan[0].Height != 10 || plan[1].Height != 30 {
		t.Errorf("not ascending: %+v", plan)
	}

	bad := map[string][]Allocation{
		"empty":     nil,
		"duplicate": {{Height: 1, Amount: big.NewInt(1)}, {Height: 1, Amount: big.NewInt(2)}},
		"zero":      {{Height: 1, Amount: big.NewInt(0)}},
		"nil":       {{Height: 1}},
		"genesis":   {{Height: 0, Amount: big.NewInt(1)}},
	}
	for name, table := range bad {
		if _, err := BuildPlan(PlanRequest{Mode: ModeManual, Manual: table}, zeroSource{}); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

// TestSealKeepsOpeningsAndCommitments checks each bid gets its own blinding
// factor and one commitment goes to L1 per height.
func TestSealKeepsOpeningsAndCommitments(t *testing.T) {
	plan := []Allocation{{Height: 5, Amount: big.NewInt(100)}, {Height: 6, Amount: big.NewInt(100)}}
	bids, entries, err := Seal(plan, seededSource())
	if err != nil {
		t.Fatal(err)
	}
	if len(bids) != 2 || len(entries) != 2 {
		t.Fatalf("got %d bids, %d entries", len(bids), len(entries))
	}
	if bids[0].Random == bids[1].Random {
		t.Error("two heights share a blinding factor")
	}
	if entries[0].Commitment == entries[1].Commitment {
		t.Error("equal amounts must still commit differently")
	}
	if bids[0].Height != entries[0].Height || len(bids[0].Random) != 64 {
		t.Errorf("bid/entry mismatch: %+v %+v", bids[0], entries[0])
	}
}
