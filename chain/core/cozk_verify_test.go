package core

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

// settleFixture mirrors `lib/chain/examples/dump_pool_fixture.rs`'s settle
// output (/tmp/pool_fixture_settle.json): one matched pair (A sells 80 ETH
// at 3, B buys 60) through the comparison proof and both single-prover
// settle proofs, with placeholder order ids baked into the binds.
// Locked-only model: each order carries ONE collateral commitment.
type settleFixture struct {
	ChainID   uint64          `json:"chain_id"`
	Price     uint64          `json:"price"`
	AIsSeller bool            `json:"a_is_seller"`
	LockedA   string          `json:"locked_a"`
	LockedB   string          `json:"locked_b"`
	Cmp       cmpFixtureLeg   `json:"cmp"`
	Small     smallFixtureLeg `json:"small"`
	Large     largeFixtureLeg `json:"large"`
}

type cmpFixtureLeg struct {
	Cmp        int             `json:"cmp"`
	ProofJSON  json.RawMessage `json:"proof_json"`
	PublicJSON []string        `json:"public_json"`
	VKPath     string          `json:"vk_path"`
}

type smallFixtureLeg struct {
	OrderID      string          `json:"order_id"`
	MatchOrderID string          `json:"match_order_id"`
	CmNoteOut    string          `json:"cm_note_out"`
	ProofJSON    json.RawMessage `json:"proof_json"`
	PublicJSON   []string        `json:"public_json"`
	VKPath       string          `json:"vk_path"`
}

type largeFixtureLeg struct {
	OrderID          string          `json:"order_id"`
	MatchOrderID     string          `json:"match_order_id"`
	CmLockedResidual string          `json:"cm_locked_residual"`
	CmNoteOut        string          `json:"cm_note_out"`
	ProofJSON        json.RawMessage `json:"proof_json"`
	PublicJSON       []string        `json:"public_json"`
	VKPath           string          `json:"vk_path"`
}

func loadSettleFixture(t *testing.T) settleFixture {
	t.Helper()
	const path = "/tmp/pool_fixture_settle.json"
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("fixture not found at %s — run `cargo run -p invisibook-lib --example dump_pool_fixture -- /tmp/pool_fixture.json`", path)
	}
	var f settleFixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("decoding fixture: %v", err)
	}
	return f
}

func mustDec(t *testing.T, hex string) string {
	t.Helper()
	d, err := HexToDecimal(hex)
	if err != nil {
		t.Fatalf("hex→dec: %v", err)
	}
	return d
}

// bool01 renders a boolean as the "0"/"1" decimal signal the circuits take.
func bool01(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// The compare statement rebuild [cmp, locked_a, locked_b, price,
// a_is_seller] must match the prover's publics and verify; a flipped cmp
// must fail.
func TestVerifySettleCmpProof(t *testing.T) {
	fx := loadSettleFixture(t)
	vk, err := LoadVK("settle_cozk", fx.Cmp.VKPath)
	if err != nil {
		t.Fatalf("loading VK: %v", err)
	}
	cmpDec, err := cmpToFrDecimal(fx.Cmp.Cmp)
	if err != nil {
		t.Fatal(err)
	}
	signals := []string{cmpDec, mustDec(t, fx.LockedA), mustDec(t, fx.LockedB),
		fmt.Sprintf("%d", fx.Price), bool01(fx.AIsSeller)}
	if len(signals) != len(fx.Cmp.PublicJSON) {
		t.Fatalf("compare publics: %d != %d", len(signals), len(fx.Cmp.PublicJSON))
	}
	for i := range signals {
		if signals[i] != fx.Cmp.PublicJSON[i] {
			t.Fatalf("compare public[%d]: chain %s != prover %s", i, signals[i], fx.Cmp.PublicJSON[i])
		}
	}
	if err := VerifyGroth16(vk, string(fx.Cmp.ProofJSON), signals); err != nil {
		t.Fatalf("valid compare proof must verify: %v", err)
	}

	lied, _ := cmpToFrDecimal(-fx.Cmp.Cmp)
	tampered := append([]string{}, signals...)
	tampered[0] = lied
	if err := VerifyGroth16(vk, string(fx.Cmp.ProofJSON), tampered); err == nil {
		t.Fatal("flipped cmp must be rejected")
	}
}

// The settle_small statement rebuild — including the bind transcript —
// must match the prover byte-for-byte and verify.
func TestVerifySettleSmallProof(t *testing.T) {
	fx := loadSettleFixture(t)
	vk, err := LoadVK("settle_small", fx.Small.VKPath)
	if err != nil {
		t.Fatalf("loading VK: %v", err)
	}
	req := &SettleSmallRequest{
		OrderID:      OrderID(fx.Small.OrderID),
		MatchOrderID: OrderID(fx.Small.MatchOrderID),
		CmNoteOut:    fx.Small.CmNoteOut,
	}
	// B is the buyer: side = 0, pays USDT.
	payAsset, err := AssetID("USDT")
	if err != nil {
		t.Fatal(err)
	}
	bind := settleSmallBind(fx.ChainID, req)
	signals := []string{
		mustDec(t, fx.LockedB),
		fmt.Sprintf("%d", fx.Price), "0",
		payAsset.String(),
		mustDec(t, req.CmNoteOut),
		bind.String(),
	}
	for i := range signals {
		if signals[i] != fx.Small.PublicJSON[i] {
			t.Fatalf("small public[%d]: chain %s != prover %s", i, signals[i], fx.Small.PublicJSON[i])
		}
	}
	if err := VerifyGroth16(vk, string(fx.Small.ProofJSON), signals); err != nil {
		t.Fatalf("valid settle_small proof must verify: %v", err)
	}

	// A different pair id changes bind — replay against another pair fails.
	other := &SettleSmallRequest{
		OrderID:      "order-x",
		MatchOrderID: req.MatchOrderID,
		CmNoteOut:    req.CmNoteOut,
	}
	tampered := append([]string{}, signals...)
	tampered[5] = settleSmallBind(fx.ChainID, other).String()
	if err := VerifyGroth16(vk, string(fx.Small.ProofJSON), tampered); err == nil {
		t.Fatal("cross-pair replay must be rejected")
	}
}

// The settle_large statement rebuild must match and verify; growing the
// payout note must fail.
func TestVerifySettleLargeProof(t *testing.T) {
	fx := loadSettleFixture(t)
	vk, err := LoadVK("settle_large", fx.Large.VKPath)
	if err != nil {
		t.Fatalf("loading VK: %v", err)
	}
	req := &SettleLargeRequest{
		OrderID:          OrderID(fx.Large.OrderID),
		MatchOrderID:     OrderID(fx.Large.MatchOrderID),
		CmLockedResidual: fx.Large.CmLockedResidual,
		CmNoteOut:        fx.Large.CmNoteOut,
	}
	// A is the seller: side = 1, pays ETH. locked_ctr is B's row commitment.
	payAsset, err := AssetID("ETH")
	if err != nil {
		t.Fatal(err)
	}
	bind := settleLargeBind(fx.ChainID, req)
	signals := []string{
		mustDec(t, fx.LockedA), mustDec(t, fx.LockedB),
		fmt.Sprintf("%d", fx.Price), "1",
		mustDec(t, req.CmLockedResidual),
		payAsset.String(),
		mustDec(t, req.CmNoteOut),
		bind.String(),
	}
	for i := range signals {
		if signals[i] != fx.Large.PublicJSON[i] {
			t.Fatalf("large public[%d]: chain %s != prover %s", i, signals[i], fx.Large.PublicJSON[i])
		}
	}
	if err := VerifyGroth16(vk, string(fx.Large.ProofJSON), signals); err != nil {
		t.Fatalf("valid settle_large proof must verify: %v", err)
	}

	tampered := append([]string{}, signals...)
	tampered[6] = bumpLastDigit(tampered[6])
	if err := VerifyGroth16(vk, string(fx.Large.ProofJSON), tampered); err == nil {
		t.Fatal("tampered payout note must be rejected")
	}
}
