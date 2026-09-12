package core

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

// cozk2pFixture mirrors `cozk2p/src/bin/dump_settle2p_fixture.rs` output.
// The proof inside was generated COLLABORATIVELY by two in-process SPDZ
// parties, so these tests cover exactly what production settlement submits.
type cozk2pFixture struct {
	Price                   uint64          `json:"price"`
	AIsSeller               bool            `json:"a_is_seller"`
	Cmp                     int             `json:"cmp"`
	OrderACommitmentHex     string          `json:"order_a_commitment_hex"`
	OrderBCommitmentHex     string          `json:"order_b_commitment_hex"`
	LockedAHashesHex        [2]string       `json:"locked_a_hashes_hex"`
	LockedBHashesHex        [2]string       `json:"locked_b_hashes_hex"`
	NewOrderACommitmentHex  string          `json:"new_order_a_commitment_hex"`
	NewOrderBCommitmentHex  string          `json:"new_order_b_commitment_hex"`
	NewLockedACommitmentHex string          `json:"new_locked_a_commitment_hex"`
	NewLockedBCommitmentHex string          `json:"new_locked_b_commitment_hex"`
	RecvACommitmentHex      string          `json:"recv_a_commitment_hex"`
	RecvBCommitmentHex      string          `json:"recv_b_commitment_hex"`
	ProofHex                string          `json:"proof_hex"`
	Public                  json.RawMessage `json:"public"`
	VKPath                  string          `json:"vk_path"`
}

func loadCoZk2pFixture(t *testing.T) cozk2pFixture {
	t.Helper()
	const path = "/tmp/settle_cozk2p_fixture.json"
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("fixture not found at %s — run `cargo run --release --bin dump_settle2p_fixture -- --vk-out ../chain/vk/settle_cozk2p_vk.bin --fixture-out %s` in cozk2p/", path, path)
	}
	var f cozk2pFixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("decoding fixture: %v", err)
	}
	return f
}

// rebuildCoZk2pPublic assembles the settle2pPublic statement from the
// fixture's fields the same way SettleOrdersCoZk2p does from a request +
// on-chain state.
func rebuildCoZk2pPublic(fx cozk2pFixture) settle2pPublic {
	return settle2pPublic{
		Cmp:        fx.Cmp,
		NewOrderA:  fx.NewOrderACommitmentHex,
		NewOrderB:  fx.NewOrderBCommitmentHex,
		NewLockedA: fx.NewLockedACommitmentHex,
		NewLockedB: fx.NewLockedBCommitmentHex,
		RecvA:      fx.RecvACommitmentHex,
		RecvB:      fx.RecvBCommitmentHex,
		OrderA:     fx.OrderACommitmentHex,
		OrderB:     fx.OrderBCommitmentHex,
		Price:      fx.Price,
		AIsSeller:  fx.AIsSeller,
		LockedA:    fx.LockedAHashesHex,
		LockedB:    fx.LockedBHashesHex,
	}
}

// The Go-side reconstruction of the public statement must field-match the
// SettlePublic JSON the Rust prover consumed — this pins the serde layout
// between chain and cozk2p.
func TestSettleCoZk2pPublicLayoutMatchesRust(t *testing.T) {
	fx := loadCoZk2pFixture(t)
	rebuilt, err := json.Marshal(rebuildCoZk2pPublic(fx))
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

// A signature over one settle variant's message must never authorize the
// other — the domain prefixes must differ on otherwise-identical requests.
func TestCoZkSettleMessageDomainSeparation(t *testing.T) {
	req := &CoZkSettleRequest{
		OrderAID: "order-a",
		OrderBID: "order-b",
		Cmp:      1,
	}
	if bytes.Equal(CoZkSettleMessage(req), CoZk2pSettleMessage(req)) {
		t.Fatal("CoZkSettleMessage and CoZk2pSettleMessage must be domain-separated")
	}
}
