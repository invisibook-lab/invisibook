package consensus

import (
	"math/big"
	"strings"
	"testing"

	"github.com/yu-org/yu/common"
)

func TestCalcBlockReward(t *testing.T) {
	got := CalcBlockReward(big.NewInt(1000), big.NewInt(37))
	if got.Cmp(big.NewInt(1037)) != 0 {
		t.Fatalf("CalcBlockReward(1000, 37) = %s, want 1037", got)
	}
}

// TestRewardRandomHexIsDeterministic guards the property consensus depends on:
// every node executing the same block must derive the same blinding factor, or
// they would write different cash records and fork the state.
func TestRewardRandomHexIsDeterministic(t *testing.T) {
	hash := common.BytesToHash([]byte("block-one"))
	first := RewardRandomHex(hash)
	if first != RewardRandomHex(hash) {
		t.Fatal("the same block hash must derive the same blinding factor")
	}
	if len(first) != RandomHexLen {
		t.Fatalf("blinding factor length = %d, want %d", len(first), RandomHexLen)
	}

	other := RewardRandomHex(common.BytesToHash([]byte("block-two")))
	if other == first {
		t.Fatal("different blocks must derive different blinding factors")
	}
}

func TestCheckBudgetCeiling(t *testing.T) {
	// Spending 300 of a 1000 prepayment, then bidding 700, exactly fits.
	if err := CheckBudgetCeiling(big.NewInt(300), big.NewInt(700), big.NewInt(1000)); err != nil {
		t.Fatalf("a bid that exactly exhausts the prepayment must pass, got %v", err)
	}
	// One more overspends it.
	if err := CheckBudgetCeiling(big.NewInt(300), big.NewInt(701), big.NewInt(1000)); err == nil {
		t.Fatal("a bid past the prepaid total must be rejected")
	}
}

func TestVerifyAllocationBudgetRejectsMissingInputs(t *testing.T) {
	payment := NewL1Payment("0xprepay", big.NewInt(500), strings.Repeat("a1", 32), "minerA", "")

	if err := VerifyAllocationBudget("", "", payment); err == nil {
		t.Fatal("a missing prepayment commitment must be rejected")
	}
	if err := VerifyAllocationBudget("deadbeef", "", nil); err == nil {
		t.Fatal("a missing allocation must be rejected")
	}
}
