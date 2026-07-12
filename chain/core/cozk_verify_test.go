package core

import (
	"encoding/json"
	"os"
	"strconv"
	"testing"
)

// cozkFixture mirrors `lib/cozk/examples/dump_settle_cozk_fixture.rs` output.
// The proof inside was generated COLLABORATIVELY by three in-process REP3
// nodes, so these tests cover exactly what production settlement submits.
type cozkFixture struct {
	Price                    uint64          `json:"price"`
	AIsSeller                bool            `json:"a_is_seller"`
	Cmp                      int             `json:"cmp"`
	OrderACommitmentHex      string          `json:"order_a_commitment_hex"`
	OrderBCommitmentHex      string          `json:"order_b_commitment_hex"`
	LockedAHashesHex         []string        `json:"locked_a_hashes_hex"`
	LockedBHashesHex         []string        `json:"locked_b_hashes_hex"`
	NewOrderACommitmentHex   string          `json:"new_order_a_commitment_hex"`
	NewOrderBCommitmentHex   string          `json:"new_order_b_commitment_hex"`
	NewLockedACommitmentHex  string          `json:"new_locked_a_commitment_hex"`
	NewLockedBCommitmentHex  string          `json:"new_locked_b_commitment_hex"`
	RecvACommitmentHex       string          `json:"recv_a_commitment_hex"`
	RecvBCommitmentHex       string          `json:"recv_b_commitment_hex"`
	ProofJSON                json.RawMessage `json:"proof_json"`
	PublicJSON               []string        `json:"public_json"`
	VKPath                   string          `json:"vk_path"`
}

func loadCoZkFixture(t *testing.T) cozkFixture {
	t.Helper()
	const path = "/tmp/settle_cozk_fixture.json"
	bytes, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("fixture not found at %s — run `cargo run -p cozk --example dump_settle_cozk_fixture -- %s`", path, path)
	}
	var f cozkFixture
	if err := json.Unmarshal(bytes, &f); err != nil {
		t.Fatalf("decoding fixture: %v", err)
	}
	return f
}

// rebuildCoZkSignals lays out the 15 public signals from the fixture's fields
// the same way SettleOrdersCoZk does from a request + on-chain state.
func rebuildCoZkSignals(t *testing.T, fx cozkFixture) []string {
	t.Helper()
	cmpDec, err := cmpToFrDecimal(fx.Cmp)
	if err != nil {
		t.Fatalf("cmpToFrDecimal: %v", err)
	}
	toDec := func(hex string) string {
		dec, err := HexToDecimal(hex)
		if err != nil {
			t.Fatalf("HexToDecimal(%s): %v", hex, err)
		}
		return dec
	}
	aIsSeller := "0"
	if fx.AIsSeller {
		aIsSeller = "1"
	}
	signals := []string{
		cmpDec,
		toDec(fx.NewOrderACommitmentHex),
		toDec(fx.NewOrderBCommitmentHex),
		toDec(fx.NewLockedACommitmentHex),
		toDec(fx.NewLockedBCommitmentHex),
		toDec(fx.RecvACommitmentHex),
		toDec(fx.RecvBCommitmentHex),
		toDec(fx.OrderACommitmentHex),
		toDec(fx.OrderBCommitmentHex),
		strconv.FormatUint(fx.Price, 10),
		aIsSeller,
	}
	for _, h := range fx.LockedAHashesHex {
		signals = append(signals, toDec(h))
	}
	for _, h := range fx.LockedBHashesHex {
		signals = append(signals, toDec(h))
	}
	return signals
}

// The Go-side reconstruction of the public vector must byte-match what the
// circuit produced — this pins the signal ordering between chain and circuit.
func TestSettleCoZkPublicSignalLayoutMatchesCircuit(t *testing.T) {
	fx := loadCoZkFixture(t)
	signals := rebuildCoZkSignals(t, fx)
	if len(signals) != len(fx.PublicJSON) {
		t.Fatalf("signal count mismatch: rebuilt %d, circuit %d", len(signals), len(fx.PublicJSON))
	}
	for i := range signals {
		if signals[i] != fx.PublicJSON[i] {
			t.Fatalf("signal %d mismatch: rebuilt %s, circuit %s", i, signals[i], fx.PublicJSON[i])
		}
	}
}

func TestVerifyGroth16AcceptsCollaborativeSettleCoZkProof(t *testing.T) {
	fx := loadCoZkFixture(t)
	vk, err := LoadVK("settle_cozk", fx.VKPath)
	if err != nil {
		t.Fatalf("loading VK: %v", err)
	}
	if err := VerifyGroth16(vk, string(fx.ProofJSON), rebuildCoZkSignals(t, fx)); err != nil {
		t.Fatalf("verify on a valid collaborative settle_cozk proof must succeed, got: %v", err)
	}
}

func TestVerifyGroth16RejectsTamperedSettleCoZkCmp(t *testing.T) {
	fx := loadCoZkFixture(t)
	vk, err := LoadVK("settle_cozk", fx.VKPath)
	if err != nil {
		t.Fatalf("loading VK: %v", err)
	}
	tampered := rebuildCoZkSignals(t, fx)
	// Flipping the public comparison result must break verification — a
	// submitter cannot lie about which order fully filled.
	flipped, err := cmpToFrDecimal(-fx.Cmp)
	if err != nil {
		t.Fatalf("cmpToFrDecimal: %v", err)
	}
	tampered[0] = flipped
	if err := VerifyGroth16(vk, string(fx.ProofJSON), tampered); err == nil {
		t.Fatalf("verify must reject when the cmp public signal is altered")
	}
}

func TestVerifyGroth16RejectsTamperedSettleCoZkRemainder(t *testing.T) {
	fx := loadCoZkFixture(t)
	vk, err := LoadVK("settle_cozk", fx.VKPath)
	if err != nil {
		t.Fatalf("loading VK: %v", err)
	}
	tampered := rebuildCoZkSignals(t, fx)
	// public[1] is new_order_a_commitment — the surviving order's remainder.
	tampered[1] = bumpLastDigit(tampered[1])
	if err := VerifyGroth16(vk, string(fx.ProofJSON), tampered); err == nil {
		t.Fatalf("verify must reject when the remainder commitment is altered")
	}
}
