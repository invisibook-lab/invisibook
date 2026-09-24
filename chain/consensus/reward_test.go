package consensus

import (
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/yu-org/yu/common"
	"github.com/yu-org/yu/core/types"

	"github.com/invisibook-lab/invisibook/core"
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

	if err := VerifyAllocationBudget(nil, "", payment); err == nil {
		t.Fatal("a missing prepaid total must be rejected")
	}
	// Zero funds nothing, so it is refused rather than read as "no ceiling".
	if err := VerifyAllocationBudget(big.NewInt(0), "", payment); err == nil {
		t.Fatal("a prepaid total of zero must be rejected")
	}
	if err := VerifyAllocationBudget(big.NewInt(1000), "", nil); err == nil {
		t.Fatal("a missing allocation must be rejected")
	}
}

// sendOrderTxn builds a signed SendOrder writing carrying `fees`.
func sendOrderTxn(t *testing.T, fees []string) *types.SignedTxn {
	t.Helper()
	params, err := json.Marshal(core.SendOrderRequest{HandlingFee: fees})
	if err != nil {
		t.Fatalf("marshalling params: %v", err)
	}
	return &types.SignedTxn{
		Raw: &types.UnsignedTxn{
			WrCall: &common.WrCall{
				TripodName: core.OrderBookTripodName,
				FuncName:   core.SendOrderFuncName,
				Params:     string(params),
			},
		},
	}
}

// otherTxn builds a writing that carries no handling fee.
func otherTxn(tripod, fn string) *types.SignedTxn {
	return &types.SignedTxn{
		Raw: &types.UnsignedTxn{
			WrCall: &common.WrCall{TripodName: tripod, FuncName: fn, Params: "{}"},
		},
	}
}

func blockWith(txns ...*types.SignedTxn) *types.Block {
	block := &types.Block{}
	block.SetTxns(txns)
	return block
}

func TestHandlingFeesSumsSendOrderWritings(t *testing.T) {
	got, err := handlingFees(blockWith(
		sendOrderTxn(t, []string{"10", "5"}),
		sendOrderTxn(t, []string{"7"}),
	))
	if err != nil {
		t.Fatalf("handlingFees: %v", err)
	}
	if got.Cmp(big.NewInt(22)) != 0 {
		t.Fatalf("handlingFees = %s, want 22", got)
	}
}

// TestHandlingFeesIgnoresOtherWritings pins the filter: only the writing that
// actually declares a fee contributes, so an unrelated call cannot inflate a
// miner's reward.
func TestHandlingFeesIgnoresOtherWritings(t *testing.T) {
	got, err := handlingFees(blockWith(
		sendOrderTxn(t, []string{"10"}),
		otherTxn(core.OrderBookTripodName, "SettleOrders"),
		otherTxn("account", "Deposit"),
	))
	if err != nil {
		t.Fatalf("handlingFees: %v", err)
	}
	if got.Cmp(big.NewInt(10)) != 0 {
		t.Fatalf("handlingFees = %s, want 10", got)
	}
}

func TestHandlingFeesOnEmptyBlock(t *testing.T) {
	got, err := handlingFees(blockWith())
	if err != nil {
		t.Fatalf("handlingFees: %v", err)
	}
	if got.Sign() != 0 {
		t.Fatalf("handlingFees = %s, want 0", got)
	}
}

// TestHandlingFeesReportsUndecodableParams makes sure a malformed writing is
// surfaced rather than silently counted as zero.
func TestHandlingFeesReportsUndecodableParams(t *testing.T) {
	bad := &types.SignedTxn{
		Raw: &types.UnsignedTxn{
			WrCall: &common.WrCall{
				TripodName: core.OrderBookTripodName,
				FuncName:   core.SendOrderFuncName,
				Params:     "not json",
			},
		},
	}
	if _, err := handlingFees(blockWith(bad)); err == nil {
		t.Fatal("undecodable SendOrder params must be reported")
	}
}
