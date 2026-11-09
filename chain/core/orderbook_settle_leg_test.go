package core

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/yu-org/yu/common"
	yucontext "github.com/yu-org/yu/core/context"
)

func assertSettleTimeoutEventPayload(t *testing.T, raw []byte, wantType string, wantDelivery bool) {
	t.Helper()
	var event map[string]any
	if err := json.Unmarshal(raw, &event); err != nil {
		t.Fatal(err)
	}
	if event["event_type"] != wantType || event["reveal_delivery_proven"] != wantDelivery {
		t.Fatalf("unexpected timeout event: %s", raw)
	}
	if _, legacy := event["privacy_reveal_occurred"]; legacy {
		t.Fatalf("timeout event asserted unverifiable privacy state: %s", raw)
	}
}

func addSettleLegTestAddresses(t *testing.T, fx *pairFixture) {
	t.Helper()
	for _, row := range []*SettleAddrScheme{
		{OrderID: string(fx.orderA), MatchOrderID: string(fx.orderB), MatchRound: 1, Addr: "a"},
		{OrderID: string(fx.orderB), MatchOrderID: string(fx.orderA), MatchRound: 1, Addr: "b"},
	} {
		if err := fx.ot.UpsertSettleAddr(row); err != nil {
			t.Fatal(err)
		}
	}
}

func assertSettleExpiryCleanup(t *testing.T, fx *pairFixture) {
	t.Helper()
	var comparisonCount, addressCount int64
	if err := fx.ot.db.Model(&CompareResultScheme{}).
		Where("(order_a_id = ? AND order_b_id = ?) OR (order_a_id = ? AND order_b_id = ?)",
			string(fx.orderA), string(fx.orderB), string(fx.orderB), string(fx.orderA)).
		Count(&comparisonCount).Error; err != nil {
		t.Fatal(err)
	}
	if err := fx.ot.db.Model(&SettleAddrScheme{}).
		Where("order_id IN ?", []string{string(fx.orderA), string(fx.orderB)}).
		Count(&addressCount).Error; err != nil {
		t.Fatal(err)
	}
	if comparisonCount != 0 || addressCount != 0 {
		t.Fatalf("expiry left stale pair state: comparisons=%d addresses=%d", comparisonCount, addressCount)
	}
}

func signedSettleLeg(fx *pairFixture, owner OrderID, leg SettlePairLeg) *SubmitSettleLegRequest {
	req := &SubmitSettleLegRequest{
		ChainID: fx.ot.chainID, OrderAID: fx.orderA, OrderBID: fx.orderB,
		OwnerOrderID: owner, MatchRound: 1, Leg: leg,
	}
	priv := fx.alicePriv
	if owner == fx.orderB {
		priv = fx.bobPriv
	}
	req.SubmissionSignature = hex.EncodeToString(ed25519.Sign(priv, SettleLegSubmissionSigningMessage(req)))
	return req
}

func signedExpireSettleLegs(fx *pairFixture, owner OrderID) *ExpireSettleLegsRequest {
	req := &ExpireSettleLegsRequest{
		ChainID: fx.ot.chainID, OrderAID: fx.orderA, OrderBID: fx.orderB,
		OwnerOrderID: owner, MatchRound: 1,
	}
	priv := fx.alicePriv
	if owner == fx.orderB {
		priv = fx.bobPriv
	}
	req.Signature = hex.EncodeToString(ed25519.Sign(priv, ExpireSettleLegsSigningMessage(req)))
	return req
}

func TestSettlementExecutesOnlyAfterBothOwnersSubmitTheirLegs(t *testing.T) {
	fx := newPairFixture(t)
	aReq := signedSettleLeg(fx, fx.orderA, fx.pairRequest.A)
	if err := fx.ot.SubmitSettleLeg(compareShareWriteContext(t, aReq, 100)); err != nil {
		t.Fatalf("A leg: %v", err)
	}
	mustStatus(t, fx.ot, fx.orderA, Settling)
	mustStatus(t, fx.ot, fx.orderB, Settling)

	var row SettleLegRoundScheme
	if err := fx.ot.db.First(&row, "order_a_id = ? AND match_round = ?", string(fx.orderA), 1).Error; err != nil {
		t.Fatal(err)
	}
	if row.ASubmittedHeight != 100 || row.BSubmittedHeight != 0 || row.DeadlineHeight != 110 {
		t.Fatalf("unexpected first-leg row: %+v", row)
	}

	bReq := signedSettleLeg(fx, fx.orderB, fx.pairRequest.B)
	if err := fx.ot.SubmitSettleLeg(compareShareWriteContext(t, bReq, 104)); err != nil {
		t.Fatalf("B leg: %v", err)
	}
	mustStatus(t, fx.ot, fx.orderA, Pending) // A was larger and is relisted.
	mustStatus(t, fx.ot, fx.orderB, Done)
	if err := fx.ot.db.First(&row, "order_a_id = ? AND match_round = ?", string(fx.orderA), 1).Error; err != nil {
		t.Fatal(err)
	}
	if row.BSubmittedHeight != 104 || row.CompletedHeight != 104 {
		t.Fatalf("settlement leg round was not completed: %+v", row)
	}
}

func TestSettlementLegCannotCreateOrExtendMissingRound(t *testing.T) {
	fx := newPairFixture(t)
	if err := fx.ot.db.Where("order_a_id = ? AND match_round = ?", string(fx.orderA), 1).
		Delete(&SettleLegRoundScheme{}).Error; err != nil {
		t.Fatal(err)
	}

	req := signedSettleLeg(fx, fx.orderA, fx.pairRequest.A)
	if err := fx.ot.SubmitSettleLeg(compareShareWriteContext(t, req, 100)); err == nil {
		t.Fatal("first settlement leg created a deadline instead of requiring the comparison-opened round")
	}
	var count int64
	if err := fx.ot.db.Model(&SettleLegRoundScheme{}).
		Where("order_a_id = ? AND match_round = ?", string(fx.orderA), 1).
		Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("failed leg submission created %d settlement round rows", count)
	}
}

func TestSuccessfulSettlementRematchUsesCompletionHeight(t *testing.T) {
	fx := newPairFixture(t)
	waitingBuy := mkOrder("waiting-buy-after-settlement", Buy, 3, 50)
	if err := fx.ot.InsertOrder(waitingBuy); err != nil {
		t.Fatal(err)
	}
	aReq := signedSettleLeg(fx, fx.orderA, fx.pairRequest.A)
	if err := fx.ot.SubmitSettleLeg(compareShareWriteContext(t, aReq, 100)); err != nil {
		t.Fatal(err)
	}
	bReq := signedSettleLeg(fx, fx.orderB, fx.pairRequest.B)
	if err := fx.ot.SubmitSettleLeg(compareShareWriteContext(t, bReq, 104)); err != nil {
		t.Fatal(err)
	}
	mustStatus(t, fx.ot, fx.orderA, Matched)
	mustStatus(t, fx.ot, fx.orderB, Done)
	mustStatus(t, fx.ot, waitingBuy.ID, Matched)
	for _, id := range []OrderID{fx.orderA, waitingBuy.ID} {
		order, err := fx.ot.GetOrder(id)
		if err != nil {
			t.Fatal(err)
		}
		if order.MatchHeight != 104 || compareProofShareDeadline(order, order) != 114 {
			t.Fatalf("settlement rematch %s has stale height/deadline %d/%d", id,
				order.MatchHeight, compareProofShareDeadline(order, order))
		}
	}
}

func TestLargeLegDeadlineFreezesOnlyMissingSmallOwner(t *testing.T) {
	fx := newPairFixture(t)
	addSettleLegTestAddresses(t, fx)
	waitingBuy := mkOrder("waiting-buy-after-leg-timeout", Buy, 3, 50)
	if err := fx.ot.InsertOrder(waitingBuy); err != nil {
		t.Fatal(err)
	}
	aReq := signedSettleLeg(fx, fx.orderA, fx.pairRequest.A)
	if err := fx.ot.SubmitSettleLeg(compareShareWriteContext(t, aReq, 100)); err != nil {
		t.Fatal(err)
	}
	// The missing small owner may trigger the deterministic transition; the
	// caller does not influence which stored leg supplies reveal evidence.
	expire := signedExpireSettleLegs(fx, fx.orderB)
	if err := fx.ot.ExpireSettleLegs(compareShareWriteContext(t, expire, 110)); err == nil {
		t.Fatal("expiry at the deadline height must be rejected")
	}
	expireCtx := compareShareWriteContext(t, expire, 111)
	if err := fx.ot.ExpireSettleLegs(expireCtx); err != nil {
		t.Fatalf("expiry after deadline: %v", err)
	}
	if len(expireCtx.Events) != 1 {
		t.Fatalf("punitive expiry emitted %d events", len(expireCtx.Events))
	}
	assertSettleTimeoutEventPayload(t, expireCtx.Events[0].Value, "settlement_leg_timeout", true)
	mustStatus(t, fx.ot, fx.orderA, Matched)
	mustStatus(t, fx.ot, fx.orderB, Frozen)
	mustStatus(t, fx.ot, waitingBuy.ID, Matched)
	for _, id := range []OrderID{fx.orderA, waitingBuy.ID} {
		order, err := fx.ot.GetOrder(id)
		if err != nil {
			t.Fatal(err)
		}
		if order.MatchHeight != 111 || compareProofShareDeadline(order, order) != 121 {
			t.Fatalf("timeout rematch %s has stale height/deadline %d/%d", id,
				order.MatchHeight, compareProofShareDeadline(order, order))
		}
	}
	assertSettleExpiryCleanup(t, fx)

	var row SettleLegRoundScheme
	if err := fx.ot.db.First(&row, "order_a_id = ? AND match_round = ?", string(fx.orderA), 1).Error; err != nil {
		t.Fatal(err)
	}
	if row.MissingOrderID != string(fx.orderB) || row.ExpiredAtHeight != 111 {
		t.Fatalf("unexpected expiry audit row: %+v", row)
	}
}

func TestSmallLegAloneCannotBlameMissingLargeOwner(t *testing.T) {
	fx := newPairFixture(t)
	addSettleLegTestAddresses(t, fx)
	// cmp=1 means A is large and B is small. B can construct this proof
	// without proving that it delivered q to A.
	bReq := signedSettleLeg(fx, fx.orderB, fx.pairRequest.B)
	if err := fx.ot.SubmitSettleLeg(compareShareWriteContext(t, bReq, 100)); err != nil {
		t.Fatal(err)
	}
	// Even the missing large owner may trigger expiry; both outcomes are
	// derived only from the already-authenticated stored leg.
	expire := signedExpireSettleLegs(fx, fx.orderA)
	expireCtx := compareShareWriteContext(t, expire, 111)
	if err := fx.ot.ExpireSettleLegs(expireCtx); err != nil {
		t.Fatalf("expiring only-small round: %v", err)
	}
	if len(expireCtx.Events) != 1 {
		t.Fatalf("unattributed expiry emitted %d events", len(expireCtx.Events))
	}
	assertSettleTimeoutEventPayload(t, expireCtx.Events[0].Value, "settlement_unattributed_timeout", false)
	mustStatus(t, fx.ot, fx.orderA, Pending)
	mustStatus(t, fx.ot, fx.orderB, Pending)
	assertSettleExpiryCleanup(t, fx)

	var row SettleLegRoundScheme
	if err := fx.ot.db.First(&row, "order_a_id = ? AND match_round = ?", string(fx.orderA), 1).Error; err != nil {
		t.Fatal(err)
	}
	if row.ExpiredAtHeight != 111 || row.MissingOrderID != "" {
		t.Fatalf("only-small proof falsely attributed q delivery or blame: %+v", row)
	}
}

func TestLargeBLegFreezesMissingSmallA(t *testing.T) {
	fx := newPairFixture(t)
	if err := fx.ot.db.Model(&CompareResultScheme{}).
		Where("order_a_id = ?", string(fx.orderA)).Update("cmp", -1).Error; err != nil {
		t.Fatal(err)
	}
	large := &SettleLargeRequest{
		OrderID: fx.orderB, MatchOrderID: fx.orderA,
		CmLockedResidual: canonicalTestHex(0xB2),
		CmNoteOut:        canonicalTestHex(0xC3),
		CmRefundOut:      canonicalTestHex(0xD3),
	}
	leg := SettlePairLeg{
		CmNoteOut: large.CmNoteOut, CmRefundOut: large.CmRefundOut,
		CmLockedResidual: large.CmLockedResidual, ZkProof: "test-proof-skip",
		Signature: hex.EncodeToString(ed25519.Sign(fx.bobPriv, SettleLargeSigMessage(large))),
	}
	bReq := signedSettleLeg(fx, fx.orderB, leg)
	if err := fx.ot.SubmitSettleLeg(compareShareWriteContext(t, bReq, 100)); err != nil {
		t.Fatal(err)
	}
	// A is the missing small owner and can itself trigger the deterministic
	// expiry; B's large proof is the evidence that A's opening was delivered.
	expire := signedExpireSettleLegs(fx, fx.orderA)
	if err := fx.ot.ExpireSettleLegs(compareShareWriteContext(t, expire, 111)); err != nil {
		t.Fatal(err)
	}
	mustStatus(t, fx.ot, fx.orderA, Frozen)
	mustStatus(t, fx.ot, fx.orderB, Pending)
	var row SettleLegRoundScheme
	if err := fx.ot.db.First(&row, "order_a_id = ? AND match_round = ?", string(fx.orderA), 1).Error; err != nil {
		t.Fatal(err)
	}
	if row.MissingOrderID != string(fx.orderA) || row.ExpiredAtHeight != 111 {
		t.Fatalf("B-large expiry blamed the wrong side: %+v", row)
	}
}

func TestSettlementDeadlineWithNoLegsReleasesBothWithoutAttribution(t *testing.T) {
	fx := newPairFixture(t)
	addSettleLegTestAddresses(t, fx)
	expire := signedExpireSettleLegs(fx, fx.orderA)
	if err := fx.ot.ExpireSettleLegs(compareShareWriteContext(t, expire, 110)); err == nil {
		t.Fatal("zero-leg expiry at the deadline height must be rejected")
	}
	expireCtx := compareShareWriteContext(t, expire, 111)
	if err := fx.ot.ExpireSettleLegs(expireCtx); err != nil {
		t.Fatalf("zero-leg expiry after deadline: %v", err)
	}
	if len(expireCtx.Events) != 1 {
		t.Fatalf("zero-leg expiry emitted %d events", len(expireCtx.Events))
	}
	assertSettleTimeoutEventPayload(t, expireCtx.Events[0].Value, "settlement_unattributed_timeout", false)
	mustStatus(t, fx.ot, fx.orderA, Pending)
	mustStatus(t, fx.ot, fx.orderB, Pending)
	assertSettleExpiryCleanup(t, fx)

	var row SettleLegRoundScheme
	if err := fx.ot.db.First(&row, "order_a_id = ? AND match_round = ?", string(fx.orderA), 1).Error; err != nil {
		t.Fatal(err)
	}
	if row.ExpiredAtHeight != 111 || row.MissingOrderID != "" {
		t.Fatalf("zero-leg timeout must not attribute a missing owner: %+v", row)
	}
}

func TestSettlementWithTwoTimelyLegsFinalizesPermissionlesslyAfterDeadline(t *testing.T) {
	fx := newPairFixture(t)
	addSettleLegTestAddresses(t, fx)
	aReq := signedSettleLeg(fx, fx.orderA, fx.pairRequest.A)
	if err := fx.ot.SubmitSettleLeg(compareShareWriteContext(t, aReq, 100)); err != nil {
		t.Fatal(err)
	}

	boom := errors.New("injected post-mint failure")
	settlePairFailpoint = func() error { return boom }
	defer func() { settlePairFailpoint = nil }()
	bReq := signedSettleLeg(fx, fx.orderB, fx.pairRequest.B)
	if err := fx.ot.SubmitSettleLeg(compareShareWriteContext(t, bReq, 104)); !errors.Is(err, boom) {
		t.Fatalf("expected injected settlement failure, got %v", err)
	}
	settlePairFailpoint = nil

	var row SettleLegRoundScheme
	if err := fx.ot.db.First(&row, "order_a_id = ? AND match_round = ?", string(fx.orderA), 1).Error; err != nil {
		t.Fatal(err)
	}
	if row.LegAJSON == "" || row.LegBJSON == "" || row.CompletedHeight != 0 ||
		row.ASubmittedHeight != 100 || row.BSubmittedHeight != 104 {
		t.Fatalf("failed execution did not retain both timely legs: %+v", row)
	}
	expire := signedExpireSettleLegs(fx, fx.orderA)
	if err := fx.ot.ExpireSettleLegs(compareShareWriteContext(t, expire, 111)); err == nil {
		t.Fatal("two timely legs must not be expired or attributed to either owner")
	}
	mustStatus(t, fx.ot, fx.orderA, Settling)
	mustStatus(t, fx.ot, fx.orderB, Settling)

	// Both legs were already authenticated on chain by the deadline. A
	// permissionless caller can resume their immutable journaled execution.
	finalize := &FinalizeSettleLegsRequest{
		ChainID: fx.ot.chainID, OrderAID: fx.orderA, OrderBID: fx.orderB, MatchRound: 1,
	}
	if err := fx.ot.FinalizeSettleLegs(compareShareWriteContext(t, finalize, 111)); err != nil {
		t.Fatalf("finalizing two timely legs after deadline: %v", err)
	}
	mustStatus(t, fx.ot, fx.orderA, Pending)
	mustStatus(t, fx.ot, fx.orderB, Done)
	if err := fx.ot.db.First(&row, "order_a_id = ? AND match_round = ?", string(fx.orderA), 1).Error; err != nil {
		t.Fatal(err)
	}
	if row.CompletedHeight != 111 || row.ExpiredAtHeight != 0 || row.MissingOrderID != "" {
		t.Fatalf("retry did not close the two-leg round cleanly: %+v", row)
	}
	var addressCount int64
	if err := fx.ot.db.Model(&SettleAddrScheme{}).
		Where("order_id IN ?", []string{string(fx.orderA), string(fx.orderB)}).
		Count(&addressCount).Error; err != nil {
		t.Fatal(err)
	}
	if addressCount != 0 {
		t.Fatalf("completed retry left %d rendezvous rows", addressCount)
	}
}

func TestStartupRecoveryAtomicallyCompletesStoredLegRound(t *testing.T) {
	fx := newPairFixture(t)
	aReq := signedSettleLeg(fx, fx.orderA, fx.pairRequest.A)
	if err := fx.ot.SubmitSettleLeg(compareShareWriteContext(t, aReq, 100)); err != nil {
		t.Fatal(err)
	}
	boom := errors.New("injected recovery crash")
	settlePairFailpoint = func() error { return boom }
	defer func() { settlePairFailpoint = nil }()
	bReq := signedSettleLeg(fx, fx.orderB, fx.pairRequest.B)
	if err := fx.ot.SubmitSettleLeg(compareShareWriteContext(t, bReq, 104)); !errors.Is(err, boom) {
		t.Fatalf("expected injected failure, got %v", err)
	}
	settlePairFailpoint = nil

	fx.ot.recoverPendingSettlements()
	mustStatus(t, fx.ot, fx.orderA, Pending)
	mustStatus(t, fx.ot, fx.orderB, Done)
	var row SettleLegRoundScheme
	if err := fx.ot.db.First(&row, "order_a_id = ? AND match_round = ?", string(fx.orderA), 1).Error; err != nil {
		t.Fatal(err)
	}
	if row.CompletedHeight != 104 || row.ExpiredAtHeight != 0 {
		t.Fatalf("startup recovery did not atomically complete stored legs: %+v", row)
	}
	journal, err := fx.ot.GetSettlementJournal(settlementID(fx.orderA, fx.orderB))
	if err != nil || journal == nil || journal.State != SettlementDone || journal.MatchRound != 1 {
		t.Fatalf("startup recovery journal mismatch: %+v err=%v", journal, err)
	}
}

func TestQuerySettleLegsDerivesCompletionFromDoneJournal(t *testing.T) {
	fx := newPairFixture(t)
	aReq := signedSettleLeg(fx, fx.orderA, fx.pairRequest.A)
	if err := fx.ot.SubmitSettleLeg(compareShareWriteContext(t, aReq, 100)); err != nil {
		t.Fatal(err)
	}
	bReq := signedSettleLeg(fx, fx.orderB, fx.pairRequest.B)
	if err := fx.ot.SubmitSettleLeg(compareShareWriteContext(t, bReq, 104)); err != nil {
		t.Fatal(err)
	}
	// Simulate a pre-fix database where settlement reached journal DONE but
	// the separate leg-round completion marker was lost.
	if err := fx.ot.db.Model(&SettleLegRoundScheme{}).
		Where("order_a_id = ? AND match_round = ?", string(fx.orderA), 1).
		Update("completed_height", 0).Error; err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(&QuerySettleLegsRequest{
		OrderAID: fx.orderA, OrderBID: fx.orderB, OwnerOrderID: fx.orderA, MatchRound: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	readCtx, err := yucontext.NewReadContext(&common.RdCall{Params: string(raw)})
	if err != nil {
		t.Fatal(err)
	}
	fx.ot.QuerySettleLegs(readCtx)
	response, ok := readCtx.Response().DataInterface.(SettleLegsResponse)
	if !ok || !response.Complete || response.CompletedHeight != 104 {
		t.Fatalf("query did not derive DONE journal completion: %#v", readCtx.Response().DataInterface)
	}
}

func TestEqualComparisonTimeoutReleasesBothWithoutRevealPenalty(t *testing.T) {
	fx := newPairFixture(t)
	addSettleLegTestAddresses(t, fx)
	if err := fx.ot.db.Model(&CompareResultScheme{}).
		Where("order_a_id = ?", string(fx.orderA)).Update("cmp", 0).Error; err != nil {
		t.Fatal(err)
	}
	bReq := signedSettleLeg(fx, fx.orderB, fx.pairRequest.B)
	if err := fx.ot.SubmitSettleLeg(compareShareWriteContext(t, bReq, 100)); err != nil {
		t.Fatal(err)
	}
	expire := signedExpireSettleLegs(fx, fx.orderA)
	if err := fx.ot.ExpireSettleLegs(compareShareWriteContext(t, expire, 111)); err != nil {
		t.Fatalf("equal-size expiry: %v", err)
	}
	mustStatus(t, fx.ot, fx.orderA, Pending)
	mustStatus(t, fx.ot, fx.orderB, Pending)
	assertSettleExpiryCleanup(t, fx)
	var row SettleLegRoundScheme
	if err := fx.ot.db.First(&row, "order_a_id = ? AND match_round = ?", string(fx.orderA), 1).Error; err != nil {
		t.Fatal(err)
	}
	if row.MissingOrderID != "" {
		t.Fatalf("equal-size timeout must not attribute blame: %+v", row)
	}
}

func TestSettlementLegSignatureCannotImpersonatePeer(t *testing.T) {
	fx := newPairFixture(t)
	req := signedSettleLeg(fx, fx.orderB, fx.pairRequest.B)
	req.SubmissionSignature = hex.EncodeToString(
		ed25519.Sign(fx.alicePriv, SettleLegSubmissionSigningMessage(req)),
	)
	if err := fx.ot.SubmitSettleLeg(compareShareWriteContext(t, req, 100)); err == nil {
		t.Fatal("order A key must not authorize order B's settlement leg")
	}
}
