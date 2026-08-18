package core

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

// cozk2pFixture mirrors `cozk2p/src/bin/dump_settle2p_fixture.rs` output
// (locked-only model). The proof inside was generated COLLABORATIVELY by
// two in-process SPDZ parties, so these tests cover exactly what
// production comparison submits.
type cozk2pFixture struct {
	Cmp        int             `json:"cmp"`
	LockedAHex string          `json:"locked_a_hex"`
	LockedBHex string          `json:"locked_b_hex"`
	PriceA     uint64          `json:"price_a"`
	PriceB     uint64          `json:"price_b"`
	AIsSeller  bool            `json:"a_is_seller"`
	ProofHex   string          `json:"proof_hex"`
	Public     json.RawMessage `json:"public"`
	VKPath     string          `json:"vk_path"`
}

func loadCoZk2pFixture(t *testing.T) cozk2pFixture {
	t.Helper()
	const path = "/tmp/settle_cozk2p_fixture.json"
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("fixture not found at %s — run `make dump-cozk2p-fixture`", path)
	}
	var f cozk2pFixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("decoding fixture: %v", err)
	}
	if f.PriceA == 0 || f.PriceB == 0 {
		t.Skip("stale cozk2p fixture; regenerate for the two-price statement")
	}
	return f
}

// The Go-side reconstruction of the comparison statement must field-match
// the SettlePublic JSON the Rust prover consumed — this pins the serde
// layout between chain and cozk2p.
func TestCompareCoZk2pPublicLayoutMatchesRust(t *testing.T) {
	fx := loadCoZk2pFixture(t)
	rebuilt, err := json.Marshal(settle2pPublic{
		Cmp:       fx.Cmp,
		LockedA:   fx.LockedAHex,
		LockedB:   fx.LockedBHex,
		PriceA:    fx.PriceA,
		PriceB:    fx.PriceB,
		AIsSeller: fx.AIsSeller,
	})
	if err != nil {
		t.Fatalf("marshaling rebuilt public: %v", err)
	}
	var got, want map[string]any
	if err := json.Unmarshal(rebuilt, &got); err != nil {
		t.Fatalf("parsing rebuilt public: %v", err)
	}
	if err := json.Unmarshal(fx.Public, &want); err != nil {
		t.Fatalf("parsing fixture public: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("public statement mismatch:\nrebuilt: %s\ncircuit: %s", rebuilt, fx.Public)
	}
}

// A signature over one compare variant's message must never authorize the
// other — the domain prefixes must differ on otherwise-identical requests.
func TestCompareMessageDomainSeparation(t *testing.T) {
	req := &CompareRequest{
		OrderAID: "order-a",
		OrderBID: "order-b",
		Cmp:      1,
	}
	if bytes.Equal(CoZkCompareMessage(req), CoZk2pCompareMessage(req)) {
		t.Fatal("CoZkCompareMessage and CoZk2pCompareMessage must be domain-separated")
	}
	// The settle submissions have their own domains too.
	small := SettleSmallSigMessage(&SettleSmallRequest{
		OrderID: "order-a", MatchOrderID: "order-b", CmNoteOut: "00",
	})
	large := SettleLargeSigMessage(&SettleLargeRequest{
		OrderID: "order-a", MatchOrderID: "order-b",
		CmLockedResidual: "00", CmNoteOut: "00",
	})
	if bytes.Equal(small, large) {
		t.Fatal("settle small/large signing messages must be domain-separated")
	}
}
