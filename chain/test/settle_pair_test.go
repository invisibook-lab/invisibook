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

// TestSettlePairAtomic drives match → SubmitCompareCoZk → SettlePair: one
// atomic writing that verifies both settle proofs and mints both payout
// notes together. Test mode skips proof verification (empty VK paths);
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

	// --- Compare: cmp = 1 (alice's sell is the larger side) ---
	cmpReq := &core.CompareRequest{
		OrderAID: sellOrderID,
		OrderBID: buyOrderID,
		Cmp:      1,
		ZkProof:  "test-proof-skip",
	}
	msg := core.CoZkCompareMessage(cmpReq)
	cmpReq.SigA = hex.EncodeToString(ed25519.Sign(alicePriv, msg))
	cmpReq.SigB = hex.EncodeToString(ed25519.Sign(bobPriv, msg))
	if err := wrCall("orderbook", "SubmitCompareCoZk", cmpReq); err != nil {
		t.Fatalf("SubmitCompareCoZk failed: %v", err)
	}
	waitBlock()
	if st := queryOrders(t, sellOrderID)[0].Status; st != 5 { // Settling
		t.Fatalf("expected sell order Settling(5), got %d", st)
	}

	// --- Two legs: A = alice (larger, π_B, relists), B = bob (smaller, π_A) ---
	largeSig := &core.SettleLargeRequest{
		OrderID:          sellOrderID,
		MatchOrderID:     buyOrderID,
		CmQResidual:      hexCommit(0xA1),
		CmLockedResidual: hexCommit(0xA2),
		CmNoteOut:        hexCommit(0xC2), // alice mints bob's fill note
	}
	aLeg := core.SettlePairLeg{
		CmNoteOut:        largeSig.CmNoteOut,
		CmQResidual:      largeSig.CmQResidual,
		CmLockedResidual: largeSig.CmLockedResidual,
		ZkProof:          "test-proof-skip",
		Signature: hex.EncodeToString(
			ed25519.Sign(alicePriv, core.SettleLargeSigMessage(largeSig))),
	}
	smallSig := &core.SettleSmallRequest{
		OrderID:      buyOrderID,
		MatchOrderID: sellOrderID,
		CmNoteOut:    hexCommit(0xC1), // bob mints alice's payout note
	}
	bLeg := core.SettlePairLeg{
		CmNoteOut: smallSig.CmNoteOut,
		ZkProof:   "test-proof-skip",
		Signature: hex.EncodeToString(
			ed25519.Sign(bobPriv, core.SettleSmallSigMessage(smallSig))),
	}
	pairReq := &core.SettlePairRequest{
		OrderAID: sellOrderID,
		OrderBID: buyOrderID,
		A:        aLeg,
		B:        bLeg,
	}

	// Negative: a single wrong-key leg must abort the WHOLE pair — no state
	// change, no note minted (this is the atomicity the writing exists for).
	badPair := *pairReq
	badB := bLeg
	badB.Signature = hex.EncodeToString(
		ed25519.Sign(alicePriv, core.SettleSmallSigMessage(smallSig))) // wrong key
	badPair.B = badB
	if err := wrCall("orderbook", "SettlePair", &badPair); err != nil {
		t.Fatalf("submitting bad-leg pair failed at HTTP level: %v", err)
	}
	waitBlock()
	if st := queryOrders(t, sellOrderID)[0].Status; st != 5 {
		t.Fatalf("a bad leg must abort the pair: sell order moved to %d", st)
	}
	if getPoolInfo(t).LeafCount != poolBefore.LeafCount {
		t.Fatal("a rejected pair must mint no notes")
	}

	// Happy path: both legs settle atomically.
	if err := wrCall("orderbook", "SettlePair", pairReq); err != nil {
		t.Fatalf("SettlePair failed: %v", err)
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
	if sellAfter.Amount != aLeg.CmQResidual {
		t.Fatalf("relisted amount = %s, want %s", sellAfter.Amount, aLeg.CmQResidual)
	}
	if sellAfter.LockedCommitment != aLeg.CmLockedResidual {
		t.Fatalf("relisted collateral = %s, want %s",
			sellAfter.LockedCommitment, aLeg.CmLockedResidual)
	}

	// BOTH payout notes landed in the SAME step (+2 leaves).
	afterPair := getPoolInfo(t)
	if afterPair.LeafCount != poolBefore.LeafCount+2 {
		t.Fatalf("SettlePair must append exactly two notes, %d → %d",
			poolBefore.LeafCount, afterPair.LeafCount)
	}
	if getNoteByCm(t, aLeg.CmNoteOut) < 0 || getNoteByCm(t, bLeg.CmNoteOut) < 0 {
		t.Fatal("both payout notes must be in the pool tree")
	}

	t.Log("=== SettlePair atomic settlement verified on-chain ===")
}
