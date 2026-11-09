package test

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/invisibook-lab/invisibook/core"
)

// TestSettlePairAtomic drives match → two comparison shares → two owner
// SubmitSettleLeg writings. The chain verifies each proof independently and
// mints both payout notes atomically only after both are present. Test mode skips proof verification (empty VK paths);
// signatures and the state machine are still enforced. It asserts the fully
// filled side closes, the larger side relists its residual, both payout
// notes land in ONE step, and — the point of the atomic writing — a single
// bad leg aborts the whole pair, minting nothing.
func TestSettlePairAtomic(t *testing.T) {
	alicePriv, alicePubkey := deriveKeypair(t, aliceDerivedSeedHex)
	bobPriv, bobPubkey := deriveKeypair(t, bobDerivedSeedHex)

	// --- Fresh chain ---
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

	// --- Match: alice sells (maker, earlier block), bob buys ---
	sellReq := signedSendOrder(alicePriv, core.Sell, "ETH", "USDT",
		3500, hexCommit(0xAA), alicePubkey, []string{"alice-eth-note"})
	sellOrderID := sellReq.ID
	if err := wrCall("orderbook", "SendOrder", sellReq); err != nil {
		t.Fatalf("SendOrder (sell) failed: %v", err)
	}
	waitBlock()

	buyReq := signedSendOrder(bobPriv, core.Buy, "ETH", "USDT",
		3500, hexCommit(0xBB), bobPubkey, []string{"bob-usdt-note"})
	buyOrderID := buyReq.ID
	if err := wrCall("orderbook", "SendOrder", buyReq); err != nil {
		t.Fatalf("SendOrder (buy) failed: %v", err)
	}
	waitBlock()

	if st := queryOrders(t, sellOrderID)[0].Status; st != 1 {
		t.Fatalf("expected sell order Matched(1), got %d", st)
	}
	poolBefore := getPoolInfo(t)

	// --- Compare: both owners submit shares; cmp = 1 (A larger). ---
	registerPairAddresses(t, alicePriv, bobPriv, sellOrderID, buyOrderID, 1)
	deadline := queryCompareShareDeadline(t, sellOrderID, buyOrderID, sellOrderID, 1)
	if err := wrCall("orderbook", "SubmitCompareCoZk2pShare",
		compareShareRequest(alicePriv, sellOrderID, buyOrderID, sellOrderID, 1, 1,
			deadline, hex.EncodeToString([]byte("native-share-a")))); err != nil {
		t.Fatalf("A comparison share failed: %v", err)
	}
	waitBlock()
	if err := wrCall("orderbook", "SubmitCompareCoZk2pShare",
		compareShareRequest(bobPriv, sellOrderID, buyOrderID, buyOrderID, 1, 1,
			deadline, hex.EncodeToString([]byte("native-share-b")))); err != nil {
		t.Fatalf("B comparison share failed: %v", err)
	}
	waitBlock()
	if st := queryOrders(t, sellOrderID)[0].Status; st != 5 { // Settling
		t.Fatalf("expected sell order Settling(5), got %d", st)
	}

	// --- Two legs: A = alice (larger, π_B, relists), B = bob (smaller, π_A) ---
	largeSig := &core.SettleLargeRequest{
		OrderID:          sellOrderID,
		MatchOrderID:     buyOrderID,
		CmLockedResidual: hexCommit(0xA2),
		CmNoteOut:        hexCommit(0xC2), // alice mints bob's fill note
		CmRefundOut:      hexCommit(0xD2),
	}
	aLeg := core.SettlePairLeg{
		CmNoteOut:        largeSig.CmNoteOut,
		CmRefundOut:      largeSig.CmRefundOut,
		CmLockedResidual: largeSig.CmLockedResidual,
		ZkProof:          "test-proof-skip",
		Signature: hex.EncodeToString(
			ed25519.Sign(alicePriv, core.SettleLargeSigMessage(largeSig))),
	}
	smallSig := &core.SettleSmallRequest{
		OrderID:      buyOrderID,
		MatchOrderID: sellOrderID,
		CmNoteOut:    hexCommit(0xC1), // bob mints alice's payout note
		CmRefundOut:  hexCommit(0xD1),
	}
	bLeg := core.SettlePairLeg{
		CmNoteOut:   smallSig.CmNoteOut,
		CmRefundOut: smallSig.CmRefundOut,
		ZkProof:     "test-proof-skip",
		Signature: hex.EncodeToString(
			ed25519.Sign(bobPriv, core.SettleSmallSigMessage(smallSig))),
	}
	// A's valid owner-bound leg lands first but cannot settle alone.
	aReq := ownerLegRequest(alicePriv, sellOrderID, buyOrderID, sellOrderID, 1, aLeg)
	if err := wrCall("orderbook", "SubmitSettleLeg", aReq); err != nil {
		t.Fatalf("SubmitSettleLeg (A) failed: %v", err)
	}
	waitBlock()
	if getPoolInfo(t).LeafCount != poolBefore.LeafCount {
		t.Fatal("one valid owner leg must mint no notes")
	}

	// Negative: B's wrong-key inner leg must not complete the pair.
	badB := bLeg
	badB.Signature = hex.EncodeToString(
		ed25519.Sign(alicePriv, core.SettleSmallSigMessage(smallSig))) // wrong key
	badBReq := ownerLegRequest(bobPriv, sellOrderID, buyOrderID, buyOrderID, 1, badB)
	if err := wrCall("orderbook", "SubmitSettleLeg", badBReq); err != nil {
		t.Fatalf("submitting bad B leg failed at HTTP level: %v", err)
	}
	waitBlock()
	if st := queryOrders(t, sellOrderID)[0].Status; st != 5 {
		t.Fatalf("a bad leg must abort the pair: sell order moved to %d", st)
	}
	if getPoolInfo(t).LeafCount != poolBefore.LeafCount {
		t.Fatal("a rejected pair must mint no notes")
	}

	// Happy path: B independently submits its own valid leg; both settle.
	bReq := ownerLegRequest(bobPriv, sellOrderID, buyOrderID, buyOrderID, 1, bLeg)
	if err := wrCall("orderbook", "SubmitSettleLeg", bReq); err != nil {
		t.Fatalf("SubmitSettleLeg (B) failed: %v", err)
	}
	waitBlock()

	// Bob (smaller) closed; alice (larger) relisted with her residual.
	if st := queryOrders(t, buyOrderID)[0].Status; st != 2 { // Done
		t.Fatalf("expected buy order Done(2), got %d", st)
	}
	sellAfter := queryOrders(t, sellOrderID)[0]
	if sellAfter.Status != 0 { // Pending (relisted)
		t.Fatalf("expected relisted sell order Pending(0), got %d", sellAfter.Status)
	}
	if sellAfter.LockedCommitment != aLeg.CmLockedResidual {
		t.Fatalf("relisted collateral = %s, want %s",
			sellAfter.LockedCommitment, aLeg.CmLockedResidual)
	}

	// Both payouts and both private refund notes land atomically (+4 leaves).
	afterPair := getPoolInfo(t)
	if afterPair.LeafCount != poolBefore.LeafCount+4 {
		t.Fatalf("two-leg settlement must append exactly four notes, %d → %d",
			poolBefore.LeafCount, afterPair.LeafCount)
	}
	if getNoteByCm(t, aLeg.CmNoteOut) < 0 || getNoteByCm(t, bLeg.CmNoteOut) < 0 {
		t.Fatal("both payout notes must be in the pool tree")
	}
	if getNoteByCm(t, aLeg.CmRefundOut) < 0 || getNoteByCm(t, bLeg.CmRefundOut) < 0 {
		t.Fatal("both refund notes must be in the pool tree")
	}

	t.Log("=== independent owner legs + atomic settlement verified on-chain ===")
}
