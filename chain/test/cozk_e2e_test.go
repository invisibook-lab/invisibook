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
// test mode (ZK verification skipped, so any well-formed hex works).
func hexCommit(seed byte) string {
	return strings.Repeat(hex.EncodeToString([]byte{seed}), 32)
}

// TestCoZkSettleLifecycle drives the SettleOrdersCoZk state machine end to
// end in test mode (VK paths empty → Groth16 check skipped; signatures are
// still enforced): match two orders, settle with cmp=1, and verify the taker
// leaves the book while the maker is relisted in place with its remainder
// commitments and a fresh locked collateral cash.
func TestCoZkSettleLifecycle(t *testing.T) {
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

	sellOrderID := core.ComputeOrderID([]string{aliceETHCashID})
	if err := wrCall("orderbook", "SendOrder", map[string]any{
		"id":             sellOrderID,
		"type":           1, // Sell
		"subject":        map[string]string{"token1": "ETH", "token2": "USDT"},
		"price":          3500,
		"amount":         hexCommit(0xAA),
		"pubkey":         alicePubkey,
		"signature":      signOrderID(alicePriv, string(sellOrderID)),
		"input_cash_ids": []string{aliceETHCashID},
		"handling_fee":   []string{"0"},
	}); err != nil {
		t.Fatalf("SendOrder (sell) failed: %v", err)
	}
	waitBlock()

	buyOrderID := core.ComputeOrderID([]string{bobUSDTCashID})
	if err := wrCall("orderbook", "SendOrder", map[string]any{
		"id":             buyOrderID,
		"type":           0, // Buy
		"subject":        map[string]string{"token1": "ETH", "token2": "USDT"},
		"price":          3500,
		"amount":         hexCommit(0xBB),
		"pubkey":         bobPubkey,
		"signature":      signOrderID(bobPriv, string(buyOrderID)),
		"input_cash_ids": []string{bobUSDTCashID},
		"handling_fee":   []string{"0"},
	}); err != nil {
		t.Fatalf("SendOrder (buy) failed: %v", err)
	}
	waitBlock()

	if st := queryOrders(t, sellOrderID)[0].Status; st != 1 {
		t.Fatalf("expected sell order Matched(1), got %d", st)
	}
	if st := queryOrders(t, buyOrderID)[0].Status; st != 1 {
		t.Fatalf("expected buy order Matched(1), got %d", st)
	}

	// --- Build the co-zk settlement request ---
	// Alice's sell order is the maker (earlier block) → order A. cmp=1 means
	// a > b: bob fully fills, alice keeps a remainder on the book.
	req := &core.CoZkSettleRequest{
		OrderAID:             sellOrderID,
		OrderBID:             buyOrderID,
		Cmp:                  1,
		NewOrderACommitment:  hexCommit(0xA1),
		NewOrderBCommitment:  hexCommit(0xB1),
		NewLockedACommitment: hexCommit(0xA2),
		NewLockedBCommitment: hexCommit(0xB2),
		RecvACommitment:      hexCommit(0xA3),
		RecvBCommitment:      hexCommit(0xB3),
		ZkProof:              "test-proof-skip",
	}
	msg := core.CoZkSettleMessage(req)
	req.SigA = hex.EncodeToString(ed25519.Sign(alicePriv, msg))
	req.SigB = hex.EncodeToString(ed25519.Sign(bobPriv, msg))

	// --- Negative case: a tampered signature must not change any state ---
	badReq := *req
	badReq.SigB = hex.EncodeToString(ed25519.Sign(alicePriv, msg)) // signed by the wrong key
	if err := wrCall("orderbook", "SettleOrdersCoZk", &badReq); err != nil {
		t.Fatalf("submitting bad-signature settle failed at HTTP level: %v", err)
	}
	waitBlock()
	if st := queryOrders(t, sellOrderID)[0].Status; st != 1 {
		t.Fatalf("bad signature must be rejected: sell order moved to %d", st)
	}

	// --- Happy path ---
	if err := wrCall("orderbook", "SettleOrdersCoZk", req); err != nil {
		t.Fatalf("SettleOrdersCoZk failed: %v", err)
	}
	waitBlock()

	// Bob (taker, fully filled) leaves the book.
	buyAfter := queryOrders(t, buyOrderID)[0]
	if buyAfter.Status != 2 { // Done
		t.Fatalf("expected buy order Done(2), got %d", buyAfter.Status)
	}

	// Alice (maker, larger) is relisted in place with the remainder.
	sellAfter := queryOrders(t, sellOrderID)[0]
	if sellAfter.Status != 0 { // Pending
		t.Fatalf("expected relisted sell order Pending(0), got %d", sellAfter.Status)
	}
	if sellAfter.Amount != req.NewOrderACommitment {
		t.Fatalf("relisted order amount = %s, want %s", sellAfter.Amount, req.NewOrderACommitment)
	}
	if sellAfter.MatchOrder != "" {
		t.Fatalf("relisted order must have match_order cleared, got %s", sellAfter.MatchOrder)
	}
	wantLockedID := cashID(alicePubkey, "ETH", req.NewLockedACommitment)
	if len(sellAfter.InputCashIDs) != 1 || sellAfter.InputCashIDs[0] != wantLockedID {
		t.Fatalf("relisted order input cash = %v, want [%s]", sellAfter.InputCashIDs, wantLockedID)
	}

	// Alice's cash: old genesis ETH spent; new Locked ETH remainder; new
	// Active USDT receive cash.
	aliceETHAfter := getAccount(t, alicePubkey, "ETH")
	var lockedRemainder *CashItem
	for i := range aliceETHAfter {
		if aliceETHAfter[i].ID == wantLockedID {
			lockedRemainder = &aliceETHAfter[i]
		}
		if aliceETHAfter[i].ID == aliceETHCashID {
			t.Fatalf("alice's original locked ETH cash must be Spent (absent from GetAccount)")
		}
	}
	if lockedRemainder == nil || lockedRemainder.Status != 1 { // Locked
		t.Fatalf("expected alice's remainder collateral %s to exist and be Locked, got %+v", wantLockedID, lockedRemainder)
	}
	aliceUSDTAfter := getAccount(t, alicePubkey, "USDT")
	foundRecvA := false
	for _, c := range aliceUSDTAfter {
		if c.Amount == req.RecvACommitment && c.Status == 0 {
			foundRecvA = true
		}
	}
	if !foundRecvA {
		t.Fatalf("expected alice to hold an Active USDT recv cash with amount %s", req.RecvACommitment)
	}

	// Bob's cash: USDT collateral spent; new Active ETH receive cash.
	if n := len(getAccount(t, bobPubkey, "USDT")); n != 0 {
		t.Fatalf("expected bob USDT fully spent, got %d non-spent items", n)
	}
	foundRecvB := false
	for _, c := range getAccount(t, bobPubkey, "ETH") {
		if c.Amount == req.RecvBCommitment && c.Status == 0 {
			foundRecvB = true
		}
	}
	if !foundRecvB {
		t.Fatalf("expected bob to hold an Active ETH recv cash with amount %s", req.RecvBCommitment)
	}

	// A second submission must be rejected — either at the txpool level
	// ("Transaction duplicated") or, if it reaches execution, by the
	// Matched-status check leaving state untouched.
	if err := wrCall("orderbook", "SettleOrdersCoZk", req); err == nil {
		waitBlock()
	} else {
		t.Logf("replay rejected at txpool level: %v", err)
	}
	if st := queryOrders(t, sellOrderID)[0].Status; st != 0 {
		t.Fatalf("replayed settle must not change relisted order, got status %d", st)
	}

	t.Log("=== Co-zk settle lifecycle verified ===")
}
