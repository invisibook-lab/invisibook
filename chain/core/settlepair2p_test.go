package core

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// settlePair2pFixture mirrors `cozk2p/src/bin/dump_settlepair2p_fixture.rs`
// output: a merged-statement proof generated collaboratively by two
// in-process SPDZ parties.
type settlePair2pFixture struct {
	Cmp                 int             `json:"cmp"`
	OrderACommitmentHex string          `json:"order_a_commitment_hex"`
	OrderBCommitmentHex string          `json:"order_b_commitment_hex"`
	LockedAHex          string          `json:"locked_a_hex"`
	LockedBHex          string          `json:"locked_b_hex"`
	CmNoteOutAHex       string          `json:"cm_note_out_a_hex"`
	CmNoteOutBHex       string          `json:"cm_note_out_b_hex"`
	CmQResAHex          string          `json:"cm_q_res_a_hex"`
	CmLockedResAHex     string          `json:"cm_locked_res_a_hex"`
	CmQResBHex          string          `json:"cm_q_res_b_hex"`
	CmLockedResBHex     string          `json:"cm_locked_res_b_hex"`
	Price               uint64          `json:"price"`
	AIsSeller           bool            `json:"a_is_seller"`
	TokenRecvA          string          `json:"token_recv_a"`
	TokenRecvB          string          `json:"token_recv_b"`
	ProofHex            string          `json:"proof_hex"`
	Public              json.RawMessage `json:"public"`
	VKPath              string          `json:"vk_path"`
}

func loadSettlePair2pFixture(t *testing.T) settlePair2pFixture {
	t.Helper()
	const path = "/tmp/settle_pair_cozk2p_fixture.json"
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("fixture not found at %s — run `make dump-settlepair2p-fixture`", path)
	}
	var f settlePair2pFixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("decoding fixture: %v", err)
	}
	return f
}

// rebuiltPair2pPublic rebuilds the merged statement from the fixture's
// chain-visible fields, the way the writing does from order rows.
func rebuiltPair2pPublic(t *testing.T, fx settlePair2pFixture) settlePair2pPublic {
	t.Helper()
	assetA, err := AssetID(TokenID(fx.TokenRecvA))
	if err != nil {
		t.Fatalf("recv asset A: %v", err)
	}
	assetB, err := AssetID(TokenID(fx.TokenRecvB))
	if err != nil {
		t.Fatalf("recv asset B: %v", err)
	}
	return settlePair2pPublic{
		Cmp:          fx.Cmp,
		CmNoteOutA:   fx.CmNoteOutAHex,
		CmNoteOutB:   fx.CmNoteOutBHex,
		CmQResA:      fx.CmQResAHex,
		CmLockedResA: fx.CmLockedResAHex,
		CmQResB:      fx.CmQResBHex,
		CmLockedResB: fx.CmLockedResBHex,
		CmQA:         fx.OrderACommitmentHex,
		CmQB:         fx.OrderBCommitmentHex,
		LockedA:      fx.LockedAHex,
		LockedB:      fx.LockedBHex,
		Price:        fx.Price,
		AIsSeller:    fx.AIsSeller,
		AssetRecvA:   FrToHex(assetA),
		AssetRecvB:   FrToHex(assetB),
	}
}

// The Go-side reconstruction of the merged statement must field-match the
// PairPublic JSON the Rust prover consumed — the serde-layout pin between
// chain and cozk2p for the merged path.
func TestSettlePair2pPublicLayoutMatchesRust(t *testing.T) {
	fx := loadSettlePair2pFixture(t)
	rebuilt, err := json.Marshal(rebuiltPair2pPublic(t, fx))
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

// The merged settle message must be domain-separated from every other
// signed settlement message on otherwise-identical content.
func TestSettlePair2pMessageDomainSeparation(t *testing.T) {
	merged := SettlePairCoZk2pMessage(&SettlePairCoZk2pRequest{
		OrderAID: "order-a", OrderBID: "order-b", Cmp: 1,
		CmNoteOutA: "00", CmNoteOutB: "00",
		CmQResidualA: "00", CmLockedResidualA: "00",
		CmQResidualB: "00", CmLockedResidualB: "00",
	})
	compare := CoZk2pCompareMessage(&CompareRequest{
		OrderAID: "order-a", OrderBID: "order-b", Cmp: 1,
	})
	large := SettleLargeSigMessage(&SettleLargeRequest{
		OrderID: "order-a", MatchOrderID: "order-b",
		CmQResidual: "00", CmLockedResidual: "00", CmNoteOut: "00",
	})
	if bytes.Equal(merged, compare) || bytes.Equal(merged, large) {
		t.Fatal("the merged settle message must be domain-separated")
	}
	if !bytes.HasPrefix(merged[4:], []byte("invisibook-settle-pair-cozk2p-v1")) {
		t.Fatalf("unexpected merged message layout: %q", merged)
	}
}

// mergedFixture is one MATCHED pair on fresh temp databases with real
// ed25519 keys (proofs skipped: dev mode, no VKs) plus a signed merged
// request with cmp = 1 (A larger).
type mergedFixture struct {
	ot     *OrderBook
	acc    *Account
	orderA OrderID
	orderB OrderID
	req    *SettlePairCoZk2pRequest
}

func newMergedFixture(t *testing.T) *mergedFixture {
	t.Helper()
	dir := t.TempDir()
	acc := NewAccount(&AccountConfig{
		DBPath:        filepath.Join(dir, "accounts.db"),
		RequireProofs: false,
	})
	ot := NewOrderBook(&OrderBookConfig{
		DBPath:        filepath.Join(dir, "orders.db"),
		RequireProofs: false,
	})
	ot.Account = acc

	alicePub, alicePriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	bobPub, bobPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	orderA := OrderID("merged-a-" + canonicalTestHex(0x1A)[:8])
	orderB := OrderID("merged-b-" + canonicalTestHex(0x1B)[:8])
	pair := TradePair{Token1: "ETH", Token2: "USDT"}
	price := new(big.Int).SetUint64(3)
	mk := func(id OrderID, typ TradeType, pub ed25519.PublicKey, match OrderID, height uint32) *Order {
		return &Order{
			ID:               id,
			Type:             typ,
			Subject:          pair,
			Price:            price,
			Amount:           CipherText(canonicalTestHex(byte(id[7]))),
			Pubkey:           hex.EncodeToString(pub),
			LockedCommitment: canonicalTestHex(byte(id[7]) + 1),
			BlockHeight:      height,
			Status:           Matched,
			MatchOrder:       match,
		}
	}
	if err := ot.InsertOrder(mk(orderA, Sell, alicePub, orderB, 1)); err != nil {
		t.Fatal(err)
	}
	if err := ot.InsertOrder(mk(orderB, Buy, bobPub, orderA, 2)); err != nil {
		t.Fatal(err)
	}

	req := &SettlePairCoZk2pRequest{
		OrderAID: orderA, OrderBID: orderB, Cmp: 1,
		CmNoteOutA:        canonicalTestHex(0x21),
		CmNoteOutB:        canonicalTestHex(0x22),
		CmQResidualA:      canonicalTestHex(0x23),
		CmLockedResidualA: canonicalTestHex(0x24),
		CmQResidualB:      canonicalTestHex(0x25),
		CmLockedResidualB: canonicalTestHex(0x26),
		ZkProof:           "00", // skipped: no VK loaded
	}
	msg := SettlePairCoZk2pMessage(req)
	req.SigA = hex.EncodeToString(ed25519.Sign(alicePriv, msg))
	req.SigB = hex.EncodeToString(ed25519.Sign(bobPriv, msg))
	return &mergedFixture{ot: ot, acc: acc, orderA: orderA, orderB: orderB, req: req}
}

// The merged pipeline from a MATCHED pair: both payout notes mint, the
// smaller side closes, the larger side relists in place with the residual
// commitments, and a replay is rejected.
func TestSettlePair2pPipeline(t *testing.T) {
	fx := newMergedFixture(t)
	before := fx.acc.PoolSize()

	evt, err := fx.ot.executeSettlePairMerged(fx.req, 10)
	if err != nil {
		t.Fatalf("merged settlement failed: %v", err)
	}
	if evt.EventType != "settle_pair_cozk2p" {
		t.Fatalf("unexpected event type %q", evt.EventType)
	}

	// Both payout notes are in the pool exactly once.
	if got := fx.acc.PoolSize(); got != before+2 {
		t.Fatalf("pool size: got %d, want %d", got, before+2)
	}
	for _, cm := range []string{fx.req.CmNoteOutA, fx.req.CmNoteOutB} {
		idx, err := fx.acc.FindNoteByCm(cm)
		if err != nil || idx < 0 {
			t.Fatalf("payout note %s not minted (idx %d, err %v)", cm, idx, err)
		}
	}

	// B (smaller) closed; A (larger) relisted in place with residuals.
	b, err := fx.ot.GetOrder(fx.orderB)
	if err != nil || b.Status != Done {
		t.Fatalf("order B: status %v err %v, want Done", b.Status, err)
	}
	a, err := fx.ot.GetOrder(fx.orderA)
	if err != nil {
		t.Fatal(err)
	}
	if a.Status != Pending || a.MatchOrder != "" {
		t.Fatalf("order A not relisted: status %v match %q", a.Status, a.MatchOrder)
	}
	if string(a.Amount) != fx.req.CmQResidualA || a.LockedCommitment != fx.req.CmLockedResidualA {
		t.Fatalf("order A residuals not applied: amount %s locked %s", a.Amount, a.LockedCommitment)
	}

	// Replay: the pair is no longer Matched.
	if _, err := fx.ot.executeSettlePairMerged(fx.req, 11); err == nil ||
		!strings.Contains(err.Error(), "not Matched") {
		t.Fatalf("replay must be rejected with a not-Matched error, got %v", err)
	}
}

// A crash between the pool mint and the order updates is completed by a
// resubmission: the mint is skipped (idempotent) and the order updates
// land — the shared journal machinery works from the Matched state too.
func TestSettlePair2pCrashRetry(t *testing.T) {
	fx := newMergedFixture(t)
	before := fx.acc.PoolSize()

	settlePairFailpoint = func() error { return errors.New("injected crash") }
	_, err := fx.ot.executeSettlePairMerged(fx.req, 10)
	settlePairFailpoint = nil
	if err == nil || !strings.Contains(err.Error(), "injected crash") {
		t.Fatalf("want injected crash, got %v", err)
	}

	// Orders untouched (still Matched), notes already minted.
	a, _ := fx.ot.GetOrder(fx.orderA)
	if a.Status != Matched {
		t.Fatalf("order A must stay Matched after the crash, got %v", a.Status)
	}
	if got := fx.acc.PoolSize(); got != before+2 {
		t.Fatalf("mint must precede the crash point: pool %d, want %d", got, before+2)
	}

	// Retry completes without double-minting.
	if _, err := fx.ot.executeSettlePairMerged(fx.req, 11); err != nil {
		t.Fatalf("retry failed: %v", err)
	}
	if got := fx.acc.PoolSize(); got != before+2 {
		t.Fatalf("retry double-minted: pool %d, want %d", got, before+2)
	}
	a, _ = fx.ot.GetOrder(fx.orderA)
	if a.Status != Pending || string(a.Amount) != fx.req.CmQResidualA {
		t.Fatalf("retry did not complete the relist: status %v amount %s", a.Status, a.Amount)
	}
}
