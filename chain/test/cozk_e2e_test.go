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

	// P1-2 regression: one signed counterparty leg + a garbage own leg must
	// abort the WHOLE pair — no payout for anyone.
	forged := *largeSig
	forged.CmNoteOut = hexCommit(0xC7) // attacker redirects the payout
	forgedLeg := aliceLeg
	forgedLeg.CmNoteOut = forged.CmNoteOut
	// The attacker cannot produce alice's signature over the forged leg;
	// reusing the old signature must fail verification.
	oneLeg := &core.SettlePairRequest{
		OrderAID: sellOrderID,
		OrderBID: buyOrderID,
		A:        forgedLeg,
		B:        bobLeg,
	}
	if err := wrCall("orderbook", "SettlePair", oneLeg); err != nil {
		t.Fatalf("submitting one-good-leg pair failed at HTTP level: %v", err)
	}
	waitBlock()
	if st := queryOrders(t, buyOrderID)[0].Status; st != 5 {
		t.Fatalf("pair with a forged leg must not settle: buy order moved to %d", st)
	}
	if got := getPoolInfo(t); got.LeafCount != poolBefore.LeafCount {
		t.Fatal("pair with a forged leg must mint nothing")
	}

	// Negative: swapping the legs (small shape on the larger side) must be
	// rejected — the recorded cmp decides which circuit each side may use.
	swapped := &core.SettlePairRequest{
		OrderAID: sellOrderID,
		OrderBID: buyOrderID,
		A:        bobLeg,
		B:        aliceLeg,
	}
	if err := wrCall("orderbook", "SettlePair", swapped); err != nil {
		t.Fatalf("submitting swapped-legs pair failed at HTTP level: %v", err)
	}
	waitBlock()
	if st := queryOrders(t, sellOrderID)[0].Status; st != 5 {
		t.Fatalf("swapped legs must be rejected, sell order moved to %d", st)
	}

	// Happy path: the ATOMIC pair settles both sides in one writing.
	pairReq := &core.SettlePairRequest{
		OrderAID: sellOrderID,
		OrderBID: buyOrderID,
		A:        aliceLeg,
		B:        bobLeg,
	}
	if err := wrCall("orderbook", "SettlePair", pairReq); err != nil {
		t.Fatalf("SettlePair failed: %v", err)
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
		t.Fatalf("SettlePair must append exactly four pool notes, %d → %d",
			poolBefore.LeafCount, afterPair.LeafCount)
	}
	if getNoteByCm(t, bobLeg.CmNoteOut) < 0 || getNoteByCm(t, aliceLeg.CmNoteOut) < 0 {
		t.Fatal("both payout notes must be in the tree")
	}

	// Replays must not change anything (the pair is no longer Settling, and
	// the settlement id has already minted).
	if err := wrCall("orderbook", "SettlePair", pairReq); err != nil {
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
