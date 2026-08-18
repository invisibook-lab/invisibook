package core

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/yu-org/yu/common"
	yucontext "github.com/yu-org/yu/core/context"
	yutypes "github.com/yu-org/yu/core/types"
)

func checkpointWriteContext(t *testing.T, request any, height uint32) *yucontext.WriteContext {
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

func TestPreOpenCheckpointCommitsExactMatchRound(t *testing.T) {
	fx := newPairFixture(t)
	a, err := fx.ot.GetOrder(fx.orderA)
	if err != nil {
		t.Fatal(err)
	}
	b, err := fx.ot.GetOrder(fx.orderB)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []*SettleAddrScheme{
		{OrderID: string(a.ID), MatchOrderID: string(b.ID), MatchRound: 1, Addr: "a", EncryptionPubkey: canonicalTestHex(0x31)},
		{OrderID: string(b.ID), MatchOrderID: string(a.ID), MatchRound: 1, Addr: "b", EncryptionPubkey: canonicalTestHex(0x32)},
	} {
		if err := fx.ot.UpsertSettleAddr(row); err != nil {
			t.Fatal(err)
		}
	}
	state, err := fx.ot.preOpenStateCommitment(a, b)
	if err != nil {
		t.Fatal(err)
	}
	if len(state) != 64 {
		t.Fatalf("state commitment must be a SHA-256 hex, got %q", state)
	}
	a.MatchRound++
	b.MatchRound++
	for _, id := range []OrderID{a.ID, b.ID} {
		if err := fx.ot.db.Model(&SettleAddrScheme{}).Where("order_id = ?", string(id)).
			Update("match_round", uint64(2)).Error; err != nil {
			t.Fatal(err)
		}
	}
	changed, err := fx.ot.preOpenStateCommitment(a, b)
	if err != nil {
		t.Fatal(err)
	}
	if changed == state {
		t.Fatal("a new match round must have a different pre-open commitment")
	}
}

func TestCheckpointResponseAttributesMissingUploader(t *testing.T) {
	row := &SettleCheckpointScheme{
		OrderAID: "a", OrderBID: "b", MatchRound: 3,
		StateCommitment: "00", ASubmittedHeight: 100,
	}
	aView := checkpointResponse(row, true)
	if !aView.MySubmitted || aView.PeerSubmitted || aView.Ready || aView.DeadlineHeight != 110 {
		t.Fatalf("unexpected A checkpoint view: %+v", aView)
	}
	bView := checkpointResponse(row, false)
	if bView.MySubmitted || !bView.PeerSubmitted || bView.Ready {
		t.Fatalf("unexpected B checkpoint view: %+v", bView)
	}
	row.BSubmittedHeight = 104
	if ready := checkpointResponse(row, true); !ready.Ready || ready.DeadlineHeight != 110 {
		t.Fatalf("both uploads must open the barrier: %+v", ready)
	}
}

func TestMissingCheckpointUploaderIsFrozenAfterDeadline(t *testing.T) {
	fx := newPairFixture(t)
	for _, row := range []*SettleAddrScheme{
		{OrderID: string(fx.orderA), MatchOrderID: string(fx.orderB), MatchRound: 1, Addr: "a", EncryptionPubkey: canonicalTestHex(0x41)},
		{OrderID: string(fx.orderB), MatchOrderID: string(fx.orderA), MatchRound: 1, Addr: "b", EncryptionPubkey: canonicalTestHex(0x42)},
	} {
		if err := fx.ot.UpsertSettleAddr(row); err != nil {
			t.Fatal(err)
		}
	}

	checkpoint := &SubmitSettleCheckpointRequest{
		OrderID: fx.orderA, MatchOrderID: fx.orderB, MatchRound: 1,
	}
	checkpoint.Signature = hex.EncodeToString(ed25519.Sign(
		fx.alicePriv, SettleCheckpointSigningMessage(checkpoint)))
	if err := fx.ot.SubmitSettleCheckpoint(checkpointWriteContext(t, checkpoint, 100)); err != nil {
		t.Fatalf("A checkpoint: %v", err)
	}

	abort := &AbortSettleRoundRequest{
		OrderID: fx.orderA, MatchOrderID: fx.orderB, MatchRound: 1,
	}
	abort.Signature = hex.EncodeToString(ed25519.Sign(
		fx.alicePriv, AbortSettleRoundSigningMessage(abort)))
	if err := fx.ot.AbortSettleRound(checkpointWriteContext(t, abort, 110)); err == nil {
		t.Fatal("abort at the deadline height must be rejected")
	}
	if err := fx.ot.AbortSettleRound(checkpointWriteContext(t, abort, 111)); err != nil {
		t.Fatalf("abort after the deadline: %v", err)
	}

	mustStatus(t, fx.ot, fx.orderA, Pending)
	mustStatus(t, fx.ot, fx.orderB, Frozen)
	if _, _, err := fx.ot.GetCompareResult(fx.orderA, fx.orderB); err == nil {
		t.Fatal("aborted round must remove its comparison result")
	}
	for _, id := range []OrderID{fx.orderA, fx.orderB} {
		if _, err := fx.ot.GetSettleAddr(id); err == nil {
			t.Fatalf("aborted round must remove rendezvous row for %s", id)
		}
	}
	var audit SettleCheckpointScheme
	if err := fx.ot.db.First(&audit, "order_a_id = ? AND match_round = ?", string(fx.orderA), 1).Error; err != nil {
		t.Fatal(err)
	}
	if audit.AbortedOrderID != string(fx.orderB) || audit.AbortedAtHeight != 111 ||
		audit.ASubmittedHeight != 100 || audit.BSubmittedHeight != 0 {
		t.Fatalf("unexpected checkpoint audit row: %+v", audit)
	}
}
