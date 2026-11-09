package test

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/invisibook-lab/invisibook/core"
)

// hexCommit builds a deterministic 64-char hex commitment placeholder for
// test mode (ZK verification skipped). The leading zero byte keeps it a
// CANONICAL field element — the chain now rejects hexes >= the modulus.
func hexCommit(seed byte) string {
	return "00" + strings.Repeat(hex.EncodeToString([]byte{seed}), 31)
}

// TestCoZk2pSettleLifecycle drives the current state machine through two
// owner-bound comparison shares and two owner-bound settlement legs. Proof
// verification is skipped in this test config; signatures remain enforced.
func TestCoZk2pSettleLifecycle(t *testing.T) {
	runCompareSettleLifecycle(t)
}

func runCompareSettleLifecycle(t *testing.T) {
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

	// --- Comparison shares: cmp = 1 (alice's sell is larger). ---
	writing := "SubmitCompareCoZk2pShare"
	registerPairAddresses(t, alicePriv, bobPriv, sellOrderID, buyOrderID, 1)
	aShare := []byte("native-share-a")
	bShare := []byte("native-share-b")
	deadline := queryCompareShareDeadline(t, sellOrderID, buyOrderID, sellOrderID, 1)
	aReq := compareShareRequest(alicePriv, sellOrderID, buyOrderID, sellOrderID, 1, 1, deadline, hex.EncodeToString(aShare))
	if err := wrCall("orderbook", writing, aReq); err != nil {
		t.Fatalf("A compare share: %v", err)
	}
	waitBlock()
	if st := queryOrders(t, sellOrderID)[0].Status; st != 1 {
		t.Fatalf("one comparison share must leave the pair Matched, got %d", st)
	}
	badB := compareShareRequest(bobPriv, sellOrderID, buyOrderID, buyOrderID, 1, 1, deadline, hex.EncodeToString(bShare))
	badB.Signature = hex.EncodeToString(ed25519.Sign(alicePriv, core.CompareShareSigningMessage(badB)))
	if err := wrCall("orderbook", writing, badB); err != nil {
		t.Fatalf("bad B compare share HTTP submission: %v", err)
	}
	waitBlock()
	if st := queryOrders(t, sellOrderID)[0].Status; st != 1 {
		t.Fatalf("impersonated comparison share must be rejected, got %d", st)
	}
	bReq := compareShareRequest(bobPriv, sellOrderID, buyOrderID, buyOrderID, 1, 1, deadline, hex.EncodeToString(bShare))
	if err := wrCall("orderbook", writing, bReq); err != nil {
		t.Fatalf("B compare share: %v", err)
	}
	waitBlock()
	if st := queryOrders(t, sellOrderID)[0].Status; st != 5 {
		t.Fatalf("expected sell order Settling(5), got %d", st)
	}
	if st := queryOrders(t, buyOrderID)[0].Status; st != 5 {
		t.Fatalf("expected buy order Settling(5), got %d", st)
	}

	// --- Build both signed legs (bob = smaller, π_A shape; alice = larger,
	// π_B shape). Proofs are skipped in this config; signatures and the
	// state machine are enforced. ---
	smallSig := &core.SettleSmallRequest{
		OrderID:      buyOrderID,
		MatchOrderID: sellOrderID,
		CmNoteOut:    hexCommit(0xC1),
		CmRefundOut:  hexCommit(0xD1),
	}
	bobLeg := core.SettlePairLeg{
		CmNoteOut:   smallSig.CmNoteOut,
		CmRefundOut: smallSig.CmRefundOut,
		ZkProof:     "test-proof-skip",
		Signature: hex.EncodeToString(
			ed25519.Sign(bobPriv, core.SettleSmallSigMessage(smallSig))),
	}
	largeSig := &core.SettleLargeRequest{
		OrderID:          sellOrderID,
		MatchOrderID:     buyOrderID,
		CmLockedResidual: hexCommit(0xA2),
		CmNoteOut:        hexCommit(0xC2),
		CmRefundOut:      hexCommit(0xD2),
	}
	aliceLeg := core.SettlePairLeg{
		CmNoteOut:        largeSig.CmNoteOut,
		CmRefundOut:      largeSig.CmRefundOut,
		CmLockedResidual: largeSig.CmLockedResidual,
		ZkProof:          "test-proof-skip",
		Signature: hex.EncodeToString(
			ed25519.Sign(alicePriv, core.SettleLargeSigMessage(largeSig))),
	}

	// P1-2 regression: the unilateral settle writings are NOT registered.
	// A party holding only the counterparty's signed leg must not be able
	// to collect its payout alone.
	oldSmall := &core.SettleSmallRequest{
		OrderID:      buyOrderID,
		MatchOrderID: sellOrderID,
		CmNoteOut:    smallSig.CmNoteOut,
		CmRefundOut:  smallSig.CmRefundOut,
		Signature:    bobLeg.Signature,
		ZkProof:      "test-proof-skip",
	}
	_ = wrCall("orderbook", "SettleSmall", oldSmall) // must be a dead endpoint
	oldLarge := &core.SettleLargeRequest{
		OrderID:          sellOrderID,
		MatchOrderID:     buyOrderID,
		CmLockedResidual: largeSig.CmLockedResidual,
		CmNoteOut:        largeSig.CmNoteOut,
		CmRefundOut:      largeSig.CmRefundOut,
		Signature:        aliceLeg.Signature,
		ZkProof:          "test-proof-skip",
	}
	_ = wrCall("orderbook", "SettleLarge", oldLarge)
	waitBlock()
	if st := queryOrders(t, buyOrderID)[0].Status; st != 5 {
		t.Fatalf("unregistered SettleSmall must not settle: buy order moved to %d", st)
	}
	if st := queryOrders(t, sellOrderID)[0].Status; st != 5 {
		t.Fatalf("unregistered SettleLarge must not relist: sell order moved to %d", st)
	}
	if got := getPoolInfo(t); got.LeafCount != poolBefore.LeafCount {
		t.Fatalf("unregistered settle writings must not mint notes, %d → %d",
			poolBefore.LeafCount, got.LeafCount)
	}

	// A forged owner leg must not be stored or mint anything.
	forged := *largeSig
	forged.CmNoteOut = hexCommit(0xC7) // attacker redirects the payout
	forgedLeg := aliceLeg
	forgedLeg.CmNoteOut = forged.CmNoteOut
	// The attacker cannot produce alice's signature over the forged leg;
	// reusing the old signature must fail verification.
	forgedReq := ownerLegRequest(alicePriv, sellOrderID, buyOrderID, sellOrderID, 1, forgedLeg)
	if err := wrCall("orderbook", "SubmitSettleLeg", forgedReq); err != nil {
		t.Fatalf("submitting forged owner leg failed at HTTP level: %v", err)
	}
	waitBlock()
	if st := queryOrders(t, buyOrderID)[0].Status; st != 5 {
		t.Fatalf("forged leg must not settle: buy order moved to %d", st)
	}
	if got := getPoolInfo(t); got.LeafCount != poolBefore.LeafCount {
		t.Fatal("pair with a forged leg must mint nothing")
	}

	// Negative: the small shape submitted as larger owner A must be rejected;
	// the recorded cmp decides which circuit each owner may use.
	swapped := ownerLegRequest(alicePriv, sellOrderID, buyOrderID, sellOrderID, 1, bobLeg)
	if err := wrCall("orderbook", "SubmitSettleLeg", swapped); err != nil {
		t.Fatalf("submitting wrong-shape owner leg failed at HTTP level: %v", err)
	}
	waitBlock()
	if st := queryOrders(t, sellOrderID)[0].Status; st != 5 {
		t.Fatalf("wrong-shape leg must be rejected, sell order moved to %d", st)
	}

	// Happy path: each owner submits only its own leg. The first changes no
	// balances; the second triggers the existing atomic pair executor.
	aLegReq := ownerLegRequest(alicePriv, sellOrderID, buyOrderID, sellOrderID, 1, aliceLeg)
	if err := wrCall("orderbook", "SubmitSettleLeg", aLegReq); err != nil {
		t.Fatalf("SubmitSettleLeg (alice) failed: %v", err)
	}
	waitBlock()
	if got := getPoolInfo(t); got.LeafCount != poolBefore.LeafCount {
		t.Fatal("one settlement leg must mint nothing")
	}
	bLegReq := ownerLegRequest(bobPriv, sellOrderID, buyOrderID, buyOrderID, 1, bobLeg)
	if err := wrCall("orderbook", "SubmitSettleLeg", bLegReq); err != nil {
		t.Fatalf("SubmitSettleLeg (bob) failed: %v", err)
	}
	waitBlock()

	// Bob's order is Done; alice is relisted in place with the residuals.
	if st := queryOrders(t, buyOrderID)[0].Status; st != 2 {
		t.Fatalf("expected buy order Done(2), got %d", st)
	}
	sellAfter := queryOrders(t, sellOrderID)[0]
	if sellAfter.Status != 0 { // Pending
		t.Fatalf("expected relisted sell order Pending(0), got %d", sellAfter.Status)
	}
	if sellAfter.MatchOrder != "" {
		t.Fatalf("relisted order must have match_order cleared, got %s", sellAfter.MatchOrder)
	}
	if sellAfter.LockedCommitment != largeSig.CmLockedResidual {
		t.Fatalf("relisted order collateral = %s, want %s",
			sellAfter.LockedCommitment, largeSig.CmLockedResidual)
	}

	// Both payouts and both refund notes landed in the same step (+4 leaves).
	afterPair := getPoolInfo(t)
	if afterPair.LeafCount != poolBefore.LeafCount+4 {
		t.Fatalf("two-leg settlement must append exactly four pool notes, %d → %d",
			poolBefore.LeafCount, afterPair.LeafCount)
	}
	if getNoteByCm(t, bobLeg.CmNoteOut) < 0 || getNoteByCm(t, aliceLeg.CmNoteOut) < 0 {
		t.Fatal("both payout notes must be in the tree")
	}

	// Replays must not change anything (the pair is no longer Settling, and
	// the settlement id has already minted).
	if err := wrCall("orderbook", "SubmitSettleLeg", aLegReq); err != nil {
		t.Logf("replay rejected at txpool level: %v", err)
	}
	waitBlock()
	if st := queryOrders(t, sellOrderID)[0].Status; st != 0 {
		t.Fatalf("replayed settle must not change relisted order, got status %d", st)
	}
	if got := getPoolInfo(t); got.LeafCount != afterPair.LeafCount {
		t.Fatalf("replayed settle must not mint again")
	}

	t.Logf("=== %s lifecycle verified ===", writing)
}
