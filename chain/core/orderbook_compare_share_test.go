package core

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/yu-org/yu/common"
	yucontext "github.com/yu-org/yu/core/context"
	yutypes "github.com/yu-org/yu/core/types"
)

func compareShareWriteContext(t *testing.T, request any, height uint32) *yucontext.WriteContext {
	t.Helper()
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	stxn := &yutypes.SignedTxn{Raw: &yutypes.UnsignedTxn{WrCall: &common.WrCall{Params: string(raw)}}}
	block := &yutypes.Block{Header: &yutypes.Header{Height: common.BlockNum(height)}}
	ctx, err := yucontext.NewWriteContext(stxn, block, 0)
	if err != nil {
		t.Fatal(err)
	}
	return ctx
}

func matchedShareFixture(t *testing.T) *pairFixture {
	t.Helper()
	fx := newPairFixture(t)
	for i, id := range []OrderID{fx.orderA, fx.orderB} {
		height := 90
		if i == 1 {
			height = 100
		}
		if err := fx.ot.db.Model(&OrderScheme{}).Where("id = ?", string(id)).
			Updates(map[string]any{
				"status": int(Matched), "block_height": height, "match_height": 100,
			}).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := fx.ot.DeleteCompareResult(fx.orderA, fx.orderB); err != nil {
		t.Fatal(err)
	}
	if err := fx.ot.db.Where("order_a_id = ? AND match_round = ?", string(fx.orderA), 1).
		Delete(&SettleLegRoundScheme{}).Error; err != nil {
		t.Fatal(err)
	}
	for _, row := range []*SettleAddrScheme{
		{OrderID: string(fx.orderA), MatchOrderID: string(fx.orderB), MatchRound: 1, Addr: "a", EncryptionPubkey: canonicalTestHex(0x41)},
		{OrderID: string(fx.orderB), MatchOrderID: string(fx.orderA), MatchRound: 1, Addr: "b", EncryptionPubkey: canonicalTestHex(0x42)},
	} {
		if err := fx.ot.UpsertSettleAddr(row); err != nil {
			t.Fatal(err)
		}
	}
	return fx
}

func signedCompareShare(fx *pairFixture, owner OrderID, share string) *SubmitCompareShareRequest {
	a, _ := fx.ot.GetOrder(fx.orderA)
	b, _ := fx.ot.GetOrder(fx.orderB)
	req := &SubmitCompareShareRequest{
		ChainID: fx.ot.chainID, OrderAID: fx.orderA, OrderBID: fx.orderB,
		OwnerOrderID: owner, MatchRound: 1, Cmp: 1,
		DeadlineHeight: compareProofShareDeadline(a, b), ProofShare: share,
	}
	priv := fx.alicePriv
	if owner == fx.orderB {
		priv = fx.bobPriv
	}
	req.Signature = hex.EncodeToString(ed25519.Sign(priv, CompareShareSigningMessage(req)))
	return req
}

func TestCompareProofShareDeadlineAndSignatureAreMatchBound(t *testing.T) {
	a := &Order{BlockHeight: 1, MatchHeight: 100}
	b := &Order{BlockHeight: 9, MatchHeight: 100}
	if got := compareProofShareDeadline(a, b); got != 110 {
		t.Fatalf("deadline = %d, want match height 100 + 10", got)
	}

	fx := matchedShareFixture(t)
	req := signedCompareShare(fx, fx.orderA, "0011")
	original := CompareShareSigningMessage(req)
	req.DeadlineHeight--
	if bytes.Equal(original, CompareShareSigningMessage(req)) {
		t.Fatal("comparison share signature message does not bind deadline_height")
	}
	req.Signature = hex.EncodeToString(ed25519.Sign(fx.alicePriv, CompareShareSigningMessage(req)))
	if err := fx.ot.SubmitCompareCoZk2pShare(compareShareWriteContext(t, req, 100)); err == nil {
		t.Fatal("chain accepted a signed deadline not fixed by the match")
	}
}

func TestCompareProofSharesVerifyOnlyAfterBothOwnersSubmit(t *testing.T) {
	fx := matchedShareFixture(t)
	// These are deliberately different-length opaque payloads. Proof
	// verification is intentionally skipped by this fixture's nil VK; this
	// pins that Go no longer interprets or XOR-combines native shares.
	aReq := signedCompareShare(fx, fx.orderA, "0011")
	if err := fx.ot.SubmitCompareCoZk2pShare(compareShareWriteContext(t, aReq, 100)); err != nil {
		t.Fatalf("A share: %v", err)
	}
	mustStatus(t, fx.ot, fx.orderA, Matched)
	mustStatus(t, fx.ot, fx.orderB, Matched)

	var row CompareShareScheme
	if err := fx.ot.db.First(&row, "order_a_id = ? AND match_round = ?", string(fx.orderA), 1).Error; err != nil {
		t.Fatal(err)
	}
	if row.ASubmittedHeight != 100 || row.BSubmittedHeight != 0 || row.DeadlineHeight != 110 {
		t.Fatalf("unexpected first-share row: %+v", row)
	}

	bReq := signedCompareShare(fx, fx.orderB, "abcdef")
	if err := fx.ot.SubmitCompareCoZk2pShare(compareShareWriteContext(t, bReq, 104)); err != nil {
		t.Fatalf("B share: %v", err)
	}
	mustStatus(t, fx.ot, fx.orderA, Settling)
	mustStatus(t, fx.ot, fx.orderB, Settling)
	cmp, _, err := fx.ot.GetCompareResult(fx.orderA, fx.orderB)
	if err != nil || cmp.Cmp != 1 || cmp.Height != 104 {
		t.Fatalf("comparison was not recorded after assembly: cmp=%+v err=%v", cmp, err)
	}
	if err := fx.ot.db.First(&row, "order_a_id = ? AND match_round = ?", string(fx.orderA), 1).Error; err != nil {
		t.Fatal(err)
	}
	if row.VerifiedHeight != 104 || row.BSubmittedHeight != 104 {
		t.Fatalf("assembled row not marked verified: %+v", row)
	}
	var legs SettleLegRoundScheme
	if err := fx.ot.db.First(&legs, "order_a_id = ? AND match_round = ?", string(fx.orderA), 1).Error; err != nil {
		t.Fatal(err)
	}
	if legs.DeadlineHeight != 114 || legs.LegAJSON != "" || legs.LegBJSON != "" {
		t.Fatalf("comparison did not open the zero-leg release window: %+v", legs)
	}
}

func TestCompareVerificationAndZeroLegRoundOpenAtomically(t *testing.T) {
	fx := matchedShareFixture(t)
	aReq := signedCompareShare(fx, fx.orderA, "0011")
	if err := fx.ot.SubmitCompareCoZk2pShare(compareShareWriteContext(t, aReq, 100)); err != nil {
		t.Fatal(err)
	}

	// A conflicting row simulates a failure while opening the post-compare
	// release window. Every earlier comparison mutation must roll back.
	conflict := &SettleLegRoundScheme{
		OrderAID: string(fx.orderA), OrderBID: string(fx.orderB), MatchRound: 1,
		DeadlineHeight: 999,
	}
	if err := fx.ot.db.Create(conflict).Error; err != nil {
		t.Fatal(err)
	}
	bReq := signedCompareShare(fx, fx.orderB, "abcdef")
	if err := fx.ot.SubmitCompareCoZk2pShare(compareShareWriteContext(t, bReq, 104)); err == nil {
		t.Fatal("comparison succeeded without atomically opening its zero-leg window")
	}
	mustStatus(t, fx.ot, fx.orderA, Matched)
	mustStatus(t, fx.ot, fx.orderB, Matched)
	var resultCount int64
	if err := fx.ot.db.Model(&CompareResultScheme{}).
		Where("order_a_id = ? AND order_b_id = ?", string(fx.orderA), string(fx.orderB)).
		Count(&resultCount).Error; err != nil {
		t.Fatal(err)
	}
	if resultCount != 0 {
		t.Fatal("comparison result escaped the failed transaction")
	}
	var shares CompareShareScheme
	if err := fx.ot.db.First(&shares, "order_a_id = ? AND match_round = ?", string(fx.orderA), 1).Error; err != nil {
		t.Fatal(err)
	}
	if shares.ShareB != "" || shares.BSubmittedHeight != 0 || shares.VerifiedHeight != 0 {
		t.Fatalf("second share escaped the failed transaction: %+v", shares)
	}

	if err := fx.ot.db.Where("order_a_id = ? AND match_round = ?", conflict.OrderAID, conflict.MatchRound).
		Delete(&SettleLegRoundScheme{}).Error; err != nil {
		t.Fatal(err)
	}
	if err := fx.ot.SubmitCompareCoZk2pShare(compareShareWriteContext(t, bReq, 104)); err != nil {
		t.Fatalf("retry after restoring atomic zero-leg window: %v", err)
	}
	mustStatus(t, fx.ot, fx.orderA, Settling)
	mustStatus(t, fx.ot, fx.orderB, Settling)
}

func TestCompareShareDeadlineReleasesBothOrdersWithoutPrivacyPenalty(t *testing.T) {
	fx := matchedShareFixture(t)
	aReq := signedCompareShare(fx, fx.orderA, "0011")
	if err := fx.ot.SubmitCompareCoZk2pShare(compareShareWriteContext(t, aReq, 100)); err != nil {
		t.Fatal(err)
	}
	expire := &ExpireCompareSharesRequest{
		ChainID: fx.ot.chainID, OrderAID: fx.orderA, OrderBID: fx.orderB,
		OwnerOrderID: fx.orderA, MatchRound: 1,
	}
	expire.Signature = hex.EncodeToString(ed25519.Sign(
		fx.alicePriv, ExpireCompareSharesSigningMessage(expire)))
	if err := fx.ot.ExpireCompareCoZk2pShares(compareShareWriteContext(t, expire, 110)); err == nil {
		t.Fatal("expiry at the deadline height must be rejected")
	}
	if err := fx.ot.ExpireCompareCoZk2pShares(compareShareWriteContext(t, expire, 111)); err != nil {
		t.Fatalf("expiry after deadline: %v", err)
	}
	mustStatus(t, fx.ot, fx.orderA, Pending)
	mustStatus(t, fx.ot, fx.orderB, Pending)

	var row CompareShareScheme
	if err := fx.ot.db.First(&row, "order_a_id = ? AND match_round = ?", string(fx.orderA), 1).Error; err != nil {
		t.Fatal(err)
	}
	if row.MissingOrderID != string(fx.orderB) || row.ExpiredAtHeight != 111 {
		t.Fatalf("unexpected expiry audit row: %+v", row)
	}
}

func TestCompareShareDeadlineWithNoUploadsReleasesBothOrders(t *testing.T) {
	fx := matchedShareFixture(t)
	expire := &ExpireCompareSharesRequest{
		ChainID: fx.ot.chainID, OrderAID: fx.orderA, OrderBID: fx.orderB,
		OwnerOrderID: fx.orderA, MatchRound: 1,
	}
	expire.Signature = hex.EncodeToString(ed25519.Sign(
		fx.alicePriv, ExpireCompareSharesSigningMessage(expire)))
	if err := fx.ot.ExpireCompareCoZk2pShares(compareShareWriteContext(t, expire, 111)); err != nil {
		t.Fatalf("expiring zero-upload comparison round: %v", err)
	}
	mustStatus(t, fx.ot, fx.orderA, Pending)
	mustStatus(t, fx.ot, fx.orderB, Pending)

	var row CompareShareScheme
	if err := fx.ot.db.First(&row, "order_a_id = ? AND match_round = ?", string(fx.orderA), 1).Error; err != nil {
		t.Fatal(err)
	}
	if row.DeadlineHeight != 110 || row.ExpiredAtHeight != 111 || row.MissingOrderID != "" {
		t.Fatalf("unexpected zero-upload expiry row: %+v", row)
	}
}

func TestCompareShareSignatureCannotImpersonatePeer(t *testing.T) {
	fx := matchedShareFixture(t)
	req := signedCompareShare(fx, fx.orderB, "abcd")
	// Replace B's valid signature with A's signature over the exact B request.
	req.Signature = hex.EncodeToString(ed25519.Sign(fx.alicePriv, CompareShareSigningMessage(req)))
	if err := fx.ot.SubmitCompareCoZk2pShare(compareShareWriteContext(t, req, 100)); err == nil {
		t.Fatal("order A key must not authorize order B's proof share")
	}
}
