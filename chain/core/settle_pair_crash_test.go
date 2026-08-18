package core

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"math/big"
	"path/filepath"
	"strings"
	"testing"
)

// canonicalTestHex builds a deterministic 64-char CANONICAL field-element
// hex (leading zero byte keeps it below the BN254 modulus).
func canonicalTestHex(seed byte) string {
	return "00" + strings.Repeat(hex.EncodeToString([]byte{seed}), 31)
}

// pairFixture is one matched Settling pair on fresh temp databases, with
// real ed25519 keys so the per-leg signatures verify (proofs are skipped:
// dev mode, no VKs).
type pairFixture struct {
	ot          *OrderBook
	acc         *Account
	orderA      OrderID // the larger side (cmp = 1)
	orderB      OrderID
	alicePriv   ed25519.PrivateKey
	bobPriv     ed25519.PrivateKey
	pairRequest *SettlePairRequest
}

// newPairFixture builds the pair, records cmp = 1 (A larger), and signs
// both legs the way the wallets do.
func newPairFixture(t *testing.T) *pairFixture {
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

	orderA := OrderID("order-a-" + canonicalTestHex(0x0A)[:8])
	orderB := OrderID("order-b-" + canonicalTestHex(0x0B)[:8])
	pair := TradePair{Token1: "ETH", Token2: "USDT"}
	price := new(big.Int).SetUint64(3)
	mk := func(id OrderID, typ TradeType, pub ed25519.PublicKey, match OrderID, height uint32) *Order {
		return &Order{
			ID:               id,
			Type:             typ,
			Subject:          pair,
			Price:            price,
			Pubkey:           hex.EncodeToString(pub),
			LockedCommitment: canonicalTestHex(byte(id[6]) + 1),
			BlockHeight:      height,
			Status:           Settling,
			MatchOrder:       match,
		}
	}
	if err := ot.InsertOrder(mk(orderA, Sell, alicePub, orderB, 1)); err != nil {
		t.Fatal(err)
	}
	if err := ot.InsertOrder(mk(orderB, Buy, bobPub, orderA, 2)); err != nil {
		t.Fatal(err)
	}
	if err := ot.SaveCompareResult(&CompareResultScheme{
		OrderAID: string(orderA),
		OrderBID: string(orderB),
		Cmp:      1, // A larger
		Height:   3,
	}); err != nil {
		t.Fatal(err)
	}

	fx := &pairFixture{
		ot: ot, acc: acc, orderA: orderA, orderB: orderB,
		alicePriv: alicePriv, bobPriv: bobPriv,
	}
	fx.pairRequest = fx.signedPair(canonicalTestHex(0xC2), canonicalTestHex(0xC1))
	return fx
}

// signedPair builds a SettlePair request whose legs carry fresh signatures
// over the given payout note commitments (A large with residuals, B small).
func (fx *pairFixture) signedPair(cmNoteA, cmNoteB string) *SettlePairRequest {
	largeSig := &SettleLargeRequest{
		OrderID:          fx.orderA,
		MatchOrderID:     fx.orderB,
		CmLockedResidual: canonicalTestHex(0xA2),
		CmNoteOut:        cmNoteA,
	}
	smallSig := &SettleSmallRequest{
		OrderID:      fx.orderB,
		MatchOrderID: fx.orderA,
		CmNoteOut:    cmNoteB,
	}
	return &SettlePairRequest{
		OrderAID: fx.orderA,
		OrderBID: fx.orderB,
		A: SettlePairLeg{
			CmNoteOut:        cmNoteA,
			CmLockedResidual: largeSig.CmLockedResidual,
			ZkProof:          "test-proof-skip",
			Signature: hex.EncodeToString(
				ed25519.Sign(fx.alicePriv, SettleLargeSigMessage(largeSig))),
		},
		B: SettlePairLeg{
			CmNoteOut: cmNoteB,
			ZkProof:   "test-proof-skip",
			Signature: hex.EncodeToString(
				ed25519.Sign(fx.bobPriv, SettleSmallSigMessage(smallSig))),
		},
	}
}

// mustStatus asserts one order's on-chain status.
func mustStatus(t *testing.T, ot *OrderBook, id OrderID, want OrderStat) {
	t.Helper()
	order, err := ot.GetOrder(id)
	if err != nil {
		t.Fatalf("GetOrder(%s): %v", id, err)
	}
	if order.Status != want {
		t.Fatalf("order %s status = %s, want %s", id, order.Status.String(), want.String())
	}
}

// P1-3 regression: a crash between the payout mint (accounts.db) and the
// order updates (orders.db) must not double-mint on retry, and the retry
// must bring the orders to their final states.
func TestSettlePairCrashBetweenDatabasesThenRetry(t *testing.T) {
	fx := newPairFixture(t)
	boom := errors.New("injected crash after mint")
	settlePairFailpoint = func() error { return boom }
	defer func() { settlePairFailpoint = nil }()

	if _, err := fx.ot.executeSettlePair(fx.pairRequest, 10); !errors.Is(err, boom) {
		t.Fatalf("expected the injected crash, got %v", err)
	}
	// The crash left the two databases split: notes minted, orders not.
	if got := fx.acc.PoolSize(); got != 2 {
		t.Fatalf("payout notes must be minted before the crash point, pool = %d", got)
	}
	mustStatus(t, fx.ot, fx.orderA, Settling)
	mustStatus(t, fx.ot, fx.orderB, Settling)
	j, err := fx.ot.GetSettlementJournal(settlementID(fx.orderA, fx.orderB))
	if err != nil || j == nil || j.State != SettlementPending {
		t.Fatalf("journal must be PENDING after the crash, got %+v err %v", j, err)
	}

	// Retry the SAME request: the mint must be skipped, the orders must
	// reach their final states.
	settlePairFailpoint = nil
	evt, err := fx.ot.executeSettlePair(fx.pairRequest, 11)
	if err != nil {
		t.Fatalf("retry must succeed: %v", err)
	}
	if got := fx.acc.PoolSize(); got != 2 {
		t.Fatalf("retry must NOT mint again, pool = %d", got)
	}
	mustStatus(t, fx.ot, fx.orderA, Pending) // relisted with the residual
	mustStatus(t, fx.ot, fx.orderB, Done)
	relisted, _ := fx.ot.GetOrder(fx.orderA)
	if relisted.LockedCommitment != canonicalTestHex(0xA2) {
		t.Fatal("relisted order must carry the residual collateral commitment")
	}
	if relisted.MatchOrder != "" {
		t.Fatal("relisted order must have its match link cleared")
	}
	j, _ = fx.ot.GetSettlementJournal(settlementID(fx.orderA, fx.orderB))
	if j == nil || j.State != SettlementDone {
		t.Fatalf("journal must be DONE after the retry, got %+v", j)
	}
	if evt.ALeafIndex != 1 || evt.BLeafIndex != 0 {
		t.Fatalf("event must carry the ORIGINAL leaf indices, got %d/%d",
			evt.ALeafIndex, evt.BLeafIndex)
	}
}

// P1-3 regression: after the same crash, a chain RESTART (no resubmission)
// must complete the order-side updates from the journal.
func TestSettlePairCrashThenRestartRecovery(t *testing.T) {
	fx := newPairFixture(t)
	settlePairFailpoint = func() error { return errors.New("injected crash") }
	if _, err := fx.ot.executeSettlePair(fx.pairRequest, 10); err == nil {
		t.Fatal("expected the injected crash")
	}
	settlePairFailpoint = nil

	// Simulates InitChain on reboot.
	fx.ot.recoverPendingSettlements()

	if got := fx.acc.PoolSize(); got != 2 {
		t.Fatalf("recovery must not mint again, pool = %d", got)
	}
	mustStatus(t, fx.ot, fx.orderA, Pending)
	mustStatus(t, fx.ot, fx.orderB, Done)
	j, _ := fx.ot.GetSettlementJournal(settlementID(fx.orderA, fx.orderB))
	if j == nil || j.State != SettlementDone {
		t.Fatalf("journal must be DONE after recovery, got %+v", j)
	}
}

// P1-3 regression: a retry that carries DIFFERENT payout commitments than
// the minted ones must be rejected — never silently skipped or re-minted.
func TestSettlePairDivergentRetryRejected(t *testing.T) {
	fx := newPairFixture(t)
	settlePairFailpoint = func() error { return errors.New("injected crash") }
	if _, err := fx.ot.executeSettlePair(fx.pairRequest, 10); err == nil {
		t.Fatal("expected the injected crash")
	}
	settlePairFailpoint = nil

	diverged := fx.signedPair(canonicalTestHex(0xD2), canonicalTestHex(0xD1))
	if _, err := fx.ot.executeSettlePair(diverged, 11); err == nil ||
		!strings.Contains(err.Error(), "already minted different") {
		t.Fatalf("divergent retry must be rejected, got %v", err)
	}
	if got := fx.acc.PoolSize(); got != 2 {
		t.Fatalf("divergent retry must not mint, pool = %d", got)
	}
	mustStatus(t, fx.ot, fx.orderA, Settling)
	mustStatus(t, fx.ot, fx.orderB, Settling)
}

// P1-3 regression: replaying a COMPLETED settlement is an idempotent no-op
// error (the pair is no longer Settling) and never mints.
func TestSettlePairReplayAfterDoneRejected(t *testing.T) {
	fx := newPairFixture(t)
	if _, err := fx.ot.executeSettlePair(fx.pairRequest, 10); err != nil {
		t.Fatalf("settlement must succeed: %v", err)
	}
	if _, err := fx.ot.executeSettlePair(fx.pairRequest, 11); err == nil {
		t.Fatal("replay after completion must be rejected")
	}
	if got := fx.acc.PoolSize(); got != 2 {
		t.Fatalf("replay must not mint, pool = %d", got)
	}
	mustStatus(t, fx.ot, fx.orderA, Pending)
	mustStatus(t, fx.ot, fx.orderB, Done)
}

// P1-3 regression: a journal row whose mint never happened (crash BEFORE
// the pool write) is dropped by recovery and the orders stay Settling —
// nothing happened, the pair remains submittable.
func TestSettlePairPreMintCrashJournalDropped(t *testing.T) {
	fx := newPairFixture(t)
	// Simulate the pre-mint crash: journal written, pool untouched.
	if err := fx.ot.UpsertSettlementJournal(&SettlementJournalScheme{
		SettlementID: settlementID(fx.orderA, fx.orderB),
		OrderAID:     string(fx.orderA),
		OrderBID:     string(fx.orderB),
		CmNoteA:      canonicalTestHex(0xC2),
		CmNoteB:      canonicalTestHex(0xC1),
		ALarge:       true,
		State:        SettlementPending,
	}); err != nil {
		t.Fatal(err)
	}

	fx.ot.recoverPendingSettlements()

	if got := fx.acc.PoolSize(); got != 0 {
		t.Fatalf("recovery must not mint for a pre-mint crash, pool = %d", got)
	}
	mustStatus(t, fx.ot, fx.orderA, Settling)
	mustStatus(t, fx.ot, fx.orderB, Settling)
	j, _ := fx.ot.GetSettlementJournal(settlementID(fx.orderA, fx.orderB))
	if j != nil {
		t.Fatalf("stale pre-mint journal must be dropped, got %+v", j)
	}
	// The pair is still fully submittable.
	if _, err := fx.ot.executeSettlePair(fx.pairRequest, 12); err != nil {
		t.Fatalf("pair must still settle after the dropped journal: %v", err)
	}
	mustStatus(t, fx.ot, fx.orderA, Pending)
	mustStatus(t, fx.ot, fx.orderB, Done)
}
