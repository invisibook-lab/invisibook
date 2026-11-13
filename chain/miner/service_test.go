package miner

import (
	"context"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yu-org/yu/common"

	"github.com/invisibook-lab/invisibook/budgetproof"
	"github.com/invisibook-lab/invisibook/ckb"
	"github.com/invisibook-lab/invisibook/consensus"
)

// fakeProve stands in for the Rust prover: the commitments it reports are
// the real ones, the proof is not.
func fakeProve(amounts []uint64, randoms []string) (*budgetproof.Proof, error) {
	out := &budgetproof.Proof{Bytes: []byte("fake proof")}
	for i, a := range amounts {
		c, err := consensus.PaymentCommit(new(big.Int).SetUint64(a), randoms[i])
		if err != nil {
			return nil, err
		}
		out.Prepaid += a
		out.Commitments = append(out.Commitments, c)
	}
	return out, nil
}

// fakeWallet stands in for the CKB client.
type fakeWallet struct {
	mu        sync.Mutex
	sendErr   error
	awaitErr  error
	prepaid   []uint64
	entries   [][]ckb.BudgetEntry
	committed uint64
	// tip is L1's tip; nil means "already past the lead" of whatever was
	// committed, so tests that are not about maturing never wait.
	tip *atomic.Uint64
}

func (w *fakeWallet) CreateBudget(_ context.Context, prepaid uint64, entries []ckb.BudgetEntry, _ []byte) (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.sendErr != nil {
		return "", w.sendErr
	}
	w.prepaid = append(w.prepaid, prepaid)
	w.entries = append(w.entries, entries)
	return "0x" + strings.Repeat("ab", 32), nil
}

func (w *fakeWallet) AwaitCommitted(context.Context, string) (uint64, error) {
	return w.committed, w.awaitErr
}

func (w *fakeWallet) TipNumber(context.Context) (uint64, error) {
	if w.tip == nil {
		return w.committed + consensus.PaymentLeadBlocks, nil
	}
	return w.tip.Load(), nil
}

func (w *fakeWallet) Balance(context.Context) (uint64, error) { return 500 * ShannonPerCKB, nil }
func (w *fakeWallet) Address() (string, error)                { return "ckt1qtest", nil }

// fakeBook is a payment book with a settable height.
type fakeBook struct{ consumed common.BlockNum }

func (b *fakeBook) Consumed() common.BlockNum { return b.consumed }
func (b *fakeBook) Pending() int              { return 0 }

// fakeDeclarer records what it was asked to declare and can refuse it.
type fakeDeclarer struct {
	mu     sync.Mutex
	calls  [][]consensus.PaymentDeclaration
	reject bool
}

func (d *fakeDeclarer) Declare(_ context.Context, payments []consensus.PaymentDeclaration) consensus.PayL1TokenResponse {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls = append(d.calls, payments)
	var resp consensus.PayL1TokenResponse
	for _, p := range payments {
		if d.reject {
			resp.Rejected = append(resp.Rejected, consensus.RejectedDeclaration{BlockHeight: p.BlockHeight, Error: "no such allocation"})
		} else {
			resp.Accepted = append(resp.Accepted, p.BlockHeight)
		}
	}
	return resp
}

func newTestService(t *testing.T, wallet Wallet) (*Service, *fakeBook, *fakeDeclarer) {
	t.Helper()
	store, err := OpenStore(filepath.Join(t.TempDir(), "prepayments.json"))
	if err != nil {
		t.Fatal(err)
	}
	book, declarer := &fakeBook{consumed: 10}, &fakeDeclarer{}
	svc := NewService(wallet, declarer, book, store, Info{MinerPubkey: "02ab", Network: "devnet", BlockIntervalMs: 3000})
	svc.maturePoll = time.Millisecond
	svc.prove = fakeProve
	// Let background steps finish before the temp dir is removed under them.
	t.Cleanup(svc.Wait)
	return svc, book, declarer
}

// evenPlan is a small plan from height 20.
func evenPlan(t *testing.T, svc *Service, count uint32) []Allocation {
	t.Helper()
	plan, err := svc.Plan(PlanRequest{Mode: ModeEven, From: 20, Count: count, Total: big.NewInt(int64(count) * 1000)})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

// waitFor polls until prepayment `id` reaches `status`.
func waitFor(t *testing.T, svc *Service, id string, status PrepayStatus) Prepayment {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if p, ok := svc.store.Get(id); ok && p.Status == status {
			return p
		}
		time.Sleep(5 * time.Millisecond)
	}
	p, _ := svc.store.Get(id)
	t.Fatalf("prepayment %s is %q, want %q", id, p.Status, status)
	return p
}

// TestPrepayConfirmsAndAutoDeclares walks the happy path: openings saved,
// budget paid, committed, declared, with the amounts the plan named.
func TestPrepayConfirmsAndAutoDeclares(t *testing.T) {
	wallet := &fakeWallet{committed: 777}
	svc, _, declarer := newTestService(t, wallet)

	p, err := svc.Prepay(evenPlan(t, svc, 3), true)
	if err != nil {
		t.Fatal(err)
	}
	if p.Status != StatusBroadcasting || p.Total != "3000" || len(p.Bids) != 3 {
		t.Fatalf("unexpected accepted state: %+v", p)
	}

	done := waitFor(t, svc, p.ID, StatusConfirmed)
	if done.L1Block != 777 || done.TxHash == "" {
		t.Errorf("L1 details missing: %+v", done)
	}
	// The declarations are made from the confirmed state; wait for the flag.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if got, _ := svc.store.Get(p.ID); got.Bids[0].Declared {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	got, _ := svc.store.Get(p.ID)
	for _, b := range got.Bids {
		if !b.Declared {
			t.Errorf("height %d not declared", b.Height)
		}
	}

	if len(wallet.prepaid) != 1 || wallet.prepaid[0] != 3000 || len(wallet.entries[0]) != 3 {
		t.Errorf("wallet saw %v / %v", wallet.prepaid, wallet.entries)
	}
	if len(declarer.calls) != 1 || len(declarer.calls[0]) != 3 {
		t.Fatalf("declarer calls: %+v", declarer.calls)
	}
	first := declarer.calls[0][0]
	if first.Amount != "1000" || first.TxHash != done.TxHash || len(first.Random) != 64 {
		t.Errorf("declaration wrong: %+v", first)
	}
}

// TestPrepayWithoutAutoDeclareWaits checks nothing is declared unless asked,
// and that Declare then does it, and only once.
func TestPrepayWithoutAutoDeclareWaits(t *testing.T) {
	svc, _, declarer := newTestService(t, &fakeWallet{committed: 5})
	p, err := svc.Prepay(evenPlan(t, svc, 2), false)
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, svc, p.ID, StatusConfirmed)
	if len(declarer.calls) != 0 {
		t.Fatalf("declared without being asked: %+v", declarer.calls)
	}

	if _, err := svc.Declare(p.ID, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Declare(p.ID, 0); err == nil {
		t.Error("a second Declare with nothing left should say so")
	}
}

// TestDeclareSkipsHeightsAlreadyPast checks a late Declare does not send
// heights the chain has moved beyond, which would sink the whole batch.
func TestDeclareSkipsHeightsAlreadyPast(t *testing.T) {
	svc, book, declarer := newTestService(t, &fakeWallet{committed: 5})
	p, err := svc.Prepay(evenPlan(t, svc, 4), false) // heights 20..23
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, svc, p.ID, StatusConfirmed)

	book.consumed = 21
	if _, err := svc.Declare(p.ID, 0); err != nil {
		t.Fatal(err)
	}
	if got := declarer.calls[0]; len(got) != 2 || got[0].BlockHeight != 22 {
		t.Errorf("declared %+v, want heights 22 and 23", got)
	}
}

// TestRejectedDeclarationChangesNothing checks a refused batch marks nothing
// declared, so it can be retried.
func TestRejectedDeclarationChangesNothing(t *testing.T) {
	svc, _, declarer := newTestService(t, &fakeWallet{committed: 5})
	p, _ := svc.Prepay(evenPlan(t, svc, 2), false)
	waitFor(t, svc, p.ID, StatusConfirmed)

	declarer.reject = true
	resp, err := svc.Declare(p.ID, 0)
	if err != nil || len(resp.Rejected) != 2 {
		t.Fatalf("resp %+v, err %v", resp, err)
	}
	got, _ := svc.store.Get(p.ID)
	for _, b := range got.Bids {
		if b.Declared {
			t.Errorf("height %d marked declared after a rejection", b.Height)
		}
	}
}

// TestFailedSendFreesTheHeights checks a transaction that never went out
// leaves the heights available to a new prepayment.
func TestFailedSendFreesTheHeights(t *testing.T) {
	wallet := &fakeWallet{sendErr: errors.New("insufficient capacity")}
	svc, _, _ := newTestService(t, wallet)
	plan := evenPlan(t, svc, 2)

	p, err := svc.Prepay(plan, true)
	if err != nil {
		t.Fatal(err)
	}
	failed := waitFor(t, svc, p.ID, StatusFailed)
	if failed.Error != "insufficient capacity" {
		t.Errorf("error = %q", failed.Error)
	}

	wallet.mu.Lock()
	wallet.sendErr = nil
	wallet.mu.Unlock()
	wallet.committed = 9
	if _, err := svc.Prepay(plan, false); err != nil {
		t.Fatalf("heights should be free again: %v", err)
	}
}

// TestUnconfirmedKeepsTheOpenings checks that a sent-but-uncommitted
// transaction is not written off: the money may be gone.
func TestUnconfirmedKeepsTheOpenings(t *testing.T) {
	svc, _, _ := newTestService(t, &fakeWallet{awaitErr: context.DeadlineExceeded})
	p, _ := svc.Prepay(evenPlan(t, svc, 2), true)
	got := waitFor(t, svc, p.ID, StatusUnconfirmed)
	if got.TxHash == "" || len(got.Bids) != 2 || got.Bids[0].Random == "" {
		t.Errorf("hash or openings lost: %+v", got)
	}
}

// TestOverlapAndPastHeightsRefused checks the guards that stop a miner paying
// for allocations it can never use.
func TestOverlapAndPastHeightsRefused(t *testing.T) {
	svc, _, _ := newTestService(t, &fakeWallet{committed: 5})
	if _, err := svc.Plan(PlanRequest{Mode: ModeEven, From: 5, Count: 3, Total: big.NewInt(300)}); err == nil {
		t.Error("heights at or below the chain's should be refused")
	}

	if _, err := svc.Prepay(evenPlan(t, svc, 3), true); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Plan(PlanRequest{Mode: ModeEven, From: 22, Count: 3, Total: big.NewInt(300)}); err == nil {
		t.Error("heights an earlier prepayment covers should be refused")
	}
}

// TestNoWalletRefusesToSpend checks the mock-L1 node stays read-only.
func TestNoWalletRefusesToSpend(t *testing.T) {
	svc, _, _ := newTestService(t, nil)
	plan := evenPlan(t, svc, 2)
	if _, err := svc.Prepay(plan, true); !errors.Is(err, ErrNoL1) {
		t.Errorf("err = %v, want ErrNoL1", err)
	}
	if st := svc.Status(context.Background()); st.L1Enabled || st.Address != "" {
		t.Errorf("status claims a wallet: %+v", st)
	}
}

// TestStatusSuggestion checks the suggested start: the very next height while
// the chain waits (it may be waiting on us), and far enough ahead to outlast
// the 24-block lead once it is seen moving: (24+6) × 10s / 3s = 100 heights.
func TestStatusSuggestion(t *testing.T) {
	svc, book, _ := newTestService(t, &fakeWallet{})
	st := svc.Status(context.Background())
	if st.ChainAdvancing || st.SuggestedFrom != 11 {
		t.Errorf("stalled chain: advancing=%v SuggestedFrom=%d, want false/11", st.ChainAdvancing, st.SuggestedFrom)
	}
	if st.BalanceCKB == nil || *st.BalanceCKB != "500" || st.Address != "ckt1qtest" || st.L1Tip == 0 {
		t.Errorf("wallet fields missing: %+v", st)
	}

	book.consumed = 12
	st = svc.Status(context.Background())
	if !st.ChainAdvancing || st.SuggestedFrom != 12+1+100 {
		t.Errorf("moving chain: advancing=%v SuggestedFrom=%d, want true/113", st.ChainAdvancing, st.SuggestedFrom)
	}

	// A prepayment reaching further ahead is continued from, not skipped past.
	if err := svc.store.Add(&Prepayment{ID: "p", Status: StatusConfirmed, Bids: []Bid{{Height: 200}}}); err != nil {
		t.Fatal(err)
	}
	if st := svc.Status(context.Background()); st.SuggestedFrom != 201 {
		t.Errorf("SuggestedFrom = %d, want 201 right after the last allocation", st.SuggestedFrom)
	}
}

// TestLeadFollowsL1Pace checks the lead is converted at L1's measured block
// time: a devnet at 1s a block needs (24+6)×1s/3s = 10 heights, not 100.
func TestLeadFollowsL1Pace(t *testing.T) {
	svc, _, _ := newTestService(t, &fakeWallet{})
	svc.observeTip(100)
	svc.l1Mu.Lock()
	svc.firstTipAt = svc.firstTipAt.Add(-10 * time.Second)
	svc.l1Mu.Unlock()
	svc.observeTip(110)
	// The clock runs on between the two readings, so the ceiling may tip to 11.
	if got := svc.leadHeights(); got != 10 && got != 11 {
		t.Errorf("leadHeights = %d, want 10", got)
	}
}

// TestDeclareWaitsForTheLead checks neither path declares a prepayment inside
// the payment lead: the node would produce a block at once, and its anchor
// could never clear V4.
func TestDeclareWaitsForTheLead(t *testing.T) {
	tip := &atomic.Uint64{}
	tip.Store(100)
	wallet := &fakeWallet{committed: 100, tip: tip}
	svc, _, declarer := newTestService(t, wallet)

	manual, _ := svc.Prepay(evenPlan(t, svc, 2), false)
	waitFor(t, svc, manual.ID, StatusConfirmed)
	if _, err := svc.Declare(manual.ID, 0); err == nil {
		t.Fatal("declaring inside the lead should be refused")
	}

	plan, err := svc.Plan(PlanRequest{Mode: ModeEven, From: 40, Count: 2, Total: big.NewInt(2000)})
	if err != nil {
		t.Fatal(err)
	}
	auto, _ := svc.Prepay(plan, true)
	waitFor(t, svc, auto.ID, StatusConfirmed)
	time.Sleep(50 * time.Millisecond)
	declarer.mu.Lock()
	early := len(declarer.calls)
	declarer.mu.Unlock()
	if early != 0 {
		t.Fatalf("auto-declared %d batch(es) before maturing", early)
	}

	tip.Store(100 + consensus.PaymentLeadBlocks)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if got, _ := svc.store.Get(auto.ID); got.Bids[0].Declared {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got, _ := svc.store.Get(auto.ID); !got.Bids[0].Declared {
		t.Error("auto-declare did not fire once the prepayment matured")
	}
	if _, err := svc.Declare(manual.ID, 0); err != nil {
		t.Errorf("a matured prepayment should declare: %v", err)
	}
}

// TestResumeReconcilesInterruptedPrepayments checks a restart re-awaits what
// was in flight and flags what may or may not have gone out.
func TestResumeReconcilesInterruptedPrepayments(t *testing.T) {
	wallet := &fakeWallet{committed: 42}
	svc, _, _ := newTestService(t, wallet)
	for _, p := range []*Prepayment{
		{ID: "sent", Status: StatusConfirming, TxHash: "0xaa", Bids: []Bid{{Height: 30, Amount: "1", Random: "r"}}},
		{ID: "unsure", Status: StatusBroadcasting, Bids: []Bid{{Height: 31, Amount: "1", Random: "r"}}},
	} {
		if err := svc.store.Add(p); err != nil {
			t.Fatal(err)
		}
	}

	svc.Resume()
	waitFor(t, svc, "sent", StatusConfirmed)
	// "sent" was never marked auto-declare, so nothing more happens to it.
	waitFor(t, svc, "unsure", StatusInterrupted)
}

// TestStoreSurvivesRestart checks openings come back from disk and the file is
// private to its owner.
func TestStoreSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "prepayments.json")
	store, _ := OpenStore(path)
	if err := store.Add(&Prepayment{ID: "x", Bids: []Bid{{Height: 9, Amount: "5", Random: "secret"}}}); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := reopened.Get("x")
	if !ok || got.Bids[0].Random != "secret" {
		t.Fatalf("lost after reopen: %+v", got)
	}
	if info, _ := statMode(path); info != 0o600 {
		t.Errorf("file mode %o, want 600", info)
	}
}

// statMode returns a file's permission bits.
func statMode(path string) (os.FileMode, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return info.Mode().Perm(), nil
}
