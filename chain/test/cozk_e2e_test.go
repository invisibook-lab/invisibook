package test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/invisibook-lab/invisibook/core"
)

// cashID mirrors core.computeCashID: hex(SHA256(pubkey || token || amount)).
func cashID(pubkey, token, amountHex string) string {
	h := sha256.Sum256([]byte(pubkey + token + amountHex))
	return hex.EncodeToString(h[:])
}

// hexCommit builds a deterministic 64-char hex commitment placeholder for
// test mode (ZK verification skipped). The leading zero byte keeps it a
// CANONICAL field element — the chain now rejects hexes >= the modulus.
func hexCommit(seed byte) string {
	return "00" + strings.Repeat(hex.EncodeToString([]byte{seed}), 31)
}

// TestCoZkSettleLifecycle drives the paper's settlement state machine end
// to end in test mode (VK paths empty → proof checks skipped; signatures
// are still enforced): match → SubmitCompareCoZk → SettleSmall (taker,
// fully filled, payout note minted) → SettleLarge (maker relisted with its
// remainder, fill note minted).
func TestCoZkSettleLifecycle(t *testing.T) {
	runCompareSettleLifecycle(t, "SubmitCompareCoZk", core.CoZkCompareMessage, core.CoZk2pCompareMessage)
}

// TestCoZk2pSettleLifecycle drives the same state machine through the
// 2-party compare writing (PLONK VK path empty in test mode → proof
// verification skipped; signatures still enforced over the domain-separated
// 2p message).
func TestCoZk2pSettleLifecycle(t *testing.T) {
	runCompareSettleLifecycle(t, "SubmitCompareCoZk2p", core.CoZk2pCompareMessage, core.CoZkCompareMessage)
}

// runCompareSettleLifecycle is the shared lifecycle driver. `writing` names
// the compare writing to submit; `signMsg` builds its canonical message;
// `crossMsg` the OTHER variant's — a request signed with it must be
// rejected, pinning signature domain separation end to end.
func runCompareSettleLifecycle(
	t *testing.T,
	writing string,
	signMsg func(*core.CompareRequest) []byte,
	crossMsg func(*core.CompareRequest) []byte,
) {
	alicePriv, alicePubkey := deriveKeypair(t, aliceDerivedSeedHex)
	bobPriv, bobPubkey := deriveKeypair(t, bobDerivedSeedHex)

	// --- Start a fresh chain ---
	exec.Command("bash", "-c", "lsof -ti:7999 -ti:8999 -ti:8887 | xargs kill -9 2>/dev/null").Run()
	time.Sleep(1 * time.Second)
	chainDir := ".."
	os.RemoveAll(chainDir + "/data")
	cmd := exec.Command("./invisibook", "--core-config", "cfg/tests/core_test.toml")
	cmd.Dir = chainDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start chain: %v", err)
	}
	defer func() {
		cmd.Process.Kill()
		cmd.Wait()
	}()
	time.Sleep(6 * time.Second)

	// --- Match a pair: alice sells (maker, earlier block), bob buys ---
	aliceETH := getAccount(t, alicePubkey, "ETH")
	if len(aliceETH) != 1 {
		t.Fatalf("expected 1 genesis ETH cash for alice, got %d", len(aliceETH))
	}
	aliceETHCashID := aliceETH[0].ID
	bobUSDT := getAccount(t, bobPubkey, "USDT")
	if len(bobUSDT) != 1 {
		t.Fatalf("expected 1 genesis USDT cash for bob, got %d", len(bobUSDT))
	}
	bobUSDTCashID := bobUSDT[0].ID

	sellReq := signedSendOrder(alicePriv, core.Sell, "ETH", "USDT",
		3500, hexCommit(0xAA), alicePubkey, []string{aliceETHCashID})
	sellOrderID := sellReq.ID
	if err := wrCall("orderbook", "SendOrder", sellReq); err != nil {
		t.Fatalf("SendOrder (sell) failed: %v", err)
	}
	waitBlock()

	buyReq := signedSendOrder(bobPriv, core.Buy, "ETH", "USDT",
		3500, hexCommit(0xBB), bobPubkey, []string{bobUSDTCashID})
	buyOrderID := buyReq.ID
	if err := wrCall("orderbook", "SendOrder", buyReq); err != nil {
		t.Fatalf("SendOrder (buy) failed: %v", err)
	}
	waitBlock()

	if st := queryOrders(t, sellOrderID)[0].Status; st != 1 {
		t.Fatalf("expected sell order Matched(1), got %d", st)
	}

	poolBefore := getPoolInfo(t)

	// --- Compare submission: cmp = 1 (alice's sell is larger) ---
	req := &core.CompareRequest{
		OrderAID: sellOrderID,
		OrderBID: buyOrderID,
		Cmp:      1,
		ZkProof:  "test-proof-skip",
	}
	msg := signMsg(req)
	req.SigA = hex.EncodeToString(ed25519.Sign(alicePriv, msg))
	req.SigB = hex.EncodeToString(ed25519.Sign(bobPriv, msg))

	// Negative: a tampered signature must not change any state.
	badReq := *req
	badReq.SigB = hex.EncodeToString(ed25519.Sign(alicePriv, msg)) // wrong key
	if err := wrCall("orderbook", writing, &badReq); err != nil {
		t.Fatalf("submitting bad-signature compare failed at HTTP level: %v", err)
	}
	waitBlock()
	if st := queryOrders(t, sellOrderID)[0].Status; st != 1 {
		t.Fatalf("bad signature must be rejected: sell order moved to %d", st)
	}

	// Negative: signatures over the OTHER variant's message must be rejected.
	crossReq := *req
	wrongMsg := crossMsg(req)
	crossReq.SigA = hex.EncodeToString(ed25519.Sign(alicePriv, wrongMsg))
	crossReq.SigB = hex.EncodeToString(ed25519.Sign(bobPriv, wrongMsg))
	if err := wrCall("orderbook", writing, &crossReq); err != nil {
		t.Fatalf("submitting cross-domain compare failed at HTTP level: %v", err)
	}
	waitBlock()
	if st := queryOrders(t, sellOrderID)[0].Status; st != 1 {
		t.Fatalf("cross-domain signature must be rejected: sell order moved to %d", st)
	}

	// Happy path: both orders move to Settling.
	if err := wrCall("orderbook", writing, req); err != nil {
		t.Fatalf("%s failed: %v", writing, err)
	}
	waitBlock()
	if st := queryOrders(t, sellOrderID)[0].Status; st != 5 {
		t.Fatalf("expected sell order Settling(5), got %d", st)
	}
	if st := queryOrders(t, buyOrderID)[0].Status; st != 5 {
		t.Fatalf("expected buy order Settling(5), got %d", st)
	}

	// --- SettleSmall: bob (smaller) pays his whole USDT collateral to
	// alice as a pool note ---
	smallReq := &core.SettleSmallRequest{
		OrderID:      buyOrderID,
		MatchOrderID: sellOrderID,
		CmNoteOut:    hexCommit(0xC1),
		ZkProof:      "test-proof-skip",
	}
	smallReq.Signature = hex.EncodeToString(
		ed25519.Sign(bobPriv, core.SettleSmallSigMessage(smallReq)))

	// Negative: the larger side must not be able to use the small path.
	wrongSide := &core.SettleSmallRequest{
		OrderID:      sellOrderID,
		MatchOrderID: buyOrderID,
		CmNoteOut:    hexCommit(0xC9),
		ZkProof:      "test-proof-skip",
	}
	wrongSide.Signature = hex.EncodeToString(
		ed25519.Sign(alicePriv, core.SettleSmallSigMessage(wrongSide)))
	if err := wrCall("orderbook", "SettleSmall", wrongSide); err != nil {
		t.Fatalf("submitting wrong-side settle failed at HTTP level: %v", err)
	}
	waitBlock()
	if st := queryOrders(t, sellOrderID)[0].Status; st != 5 {
		t.Fatalf("larger side using SettleSmall must be rejected, order moved to %d", st)
	}

	if err := wrCall("orderbook", "SettleSmall", smallReq); err != nil {
		t.Fatalf("SettleSmall failed: %v", err)
	}
	waitBlock()

	// Bob's order is Done; the payout note is a new pool leaf. (Collateral
	// is order-bound in v2, not a cash row, so it leaves the book with the
	// order — there is nothing to check on the cash side.)
	if st := queryOrders(t, buyOrderID)[0].Status; st != 2 {
		t.Fatalf("expected buy order Done(2), got %d", st)
	}
	afterSmall := getPoolInfo(t)
	if afterSmall.LeafCount != poolBefore.LeafCount+1 {
		t.Fatalf("SettleSmall must append exactly one pool note, %d → %d",
			poolBefore.LeafCount, afterSmall.LeafCount)
	}
	if getNoteByCm(t, smallReq.CmNoteOut) < 0 {
		t.Fatalf("alice's payout note %s must be in the tree", smallReq.CmNoteOut)
	}

	// --- SettleLarge: alice (larger) pays the fill and relists 20 ---
	largeReq := &core.SettleLargeRequest{
		OrderID:          sellOrderID,
		MatchOrderID:     buyOrderID,
		CmQResidual:      hexCommit(0xA1),
		CmLockedResidual: hexCommit(0xA2),
		CmNoteOut:        hexCommit(0xC2),
		ZkProof:          "test-proof-skip",
	}
	largeReq.Signature = hex.EncodeToString(
		ed25519.Sign(alicePriv, core.SettleLargeSigMessage(largeReq)))
	if err := wrCall("orderbook", "SettleLarge", largeReq); err != nil {
		t.Fatalf("SettleLarge failed: %v", err)
	}
	waitBlock()

	// Alice's order is relisted in place with the residual commitments.
	sellAfter := queryOrders(t, sellOrderID)[0]
	if sellAfter.Status != 0 { // Pending
		t.Fatalf("expected relisted sell order Pending(0), got %d", sellAfter.Status)
	}
	if sellAfter.Amount != largeReq.CmQResidual {
		t.Fatalf("relisted order amount = %s, want %s", sellAfter.Amount, largeReq.CmQResidual)
	}
	if sellAfter.MatchOrder != "" {
		t.Fatalf("relisted order must have match_order cleared, got %s", sellAfter.MatchOrder)
	}
	if sellAfter.LockedCommitment != largeReq.CmLockedResidual {
		t.Fatalf("relisted order collateral = %s, want %s",
			sellAfter.LockedCommitment, largeReq.CmLockedResidual)
	}

	// Bob's fill note is a new pool leaf.
	afterLarge := getPoolInfo(t)
	if afterLarge.LeafCount != afterSmall.LeafCount+1 {
		t.Fatalf("SettleLarge must append exactly one pool note")
	}
	if getNoteByCm(t, largeReq.CmNoteOut) < 0 {
		t.Fatalf("bob's fill note %s must be in the tree", largeReq.CmNoteOut)
	}

	// Replays must not change anything.
	if err := wrCall("orderbook", "SettleLarge", largeReq); err != nil {
		t.Logf("replay rejected at txpool level: %v", err)
	}
	waitBlock()
	if st := queryOrders(t, sellOrderID)[0].Status; st != 0 {
		t.Fatalf("replayed settle must not change relisted order, got status %d", st)
	}
	if got := getPoolInfo(t); got.LeafCount != afterLarge.LeafCount {
		t.Fatalf("replayed settle must not mint again")
	}

	t.Logf("=== %s lifecycle verified ===", writing)
}
