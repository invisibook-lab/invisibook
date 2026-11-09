package test

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/invisibook-lab/invisibook/core"
)

func ownerLegRequest(
	priv ed25519.PrivateKey,
	orderA, orderB, owner core.OrderID,
	matchRound uint64,
	leg core.SettlePairLeg,
) *core.SubmitSettleLegRequest {
	req := &core.SubmitSettleLegRequest{
		ChainID: 1926, OrderAID: orderA, OrderBID: orderB,
		OwnerOrderID: owner, MatchRound: matchRound, Leg: leg,
	}
	req.SubmissionSignature = hex.EncodeToString(
		ed25519.Sign(priv, core.SettleLegSubmissionSigningMessage(req)),
	)
	return req
}

func compareShareRequest(
	priv ed25519.PrivateKey,
	orderA, orderB, owner core.OrderID,
	matchRound uint64,
	cmp int,
	deadlineHeight uint64,
	share string,
) *core.SubmitCompareShareRequest {
	req := &core.SubmitCompareShareRequest{
		ChainID: 1926, OrderAID: orderA, OrderBID: orderB,
		OwnerOrderID: owner, MatchRound: matchRound, Cmp: cmp,
		DeadlineHeight: deadlineHeight, ProofShare: share,
	}
	req.Signature = hex.EncodeToString(
		ed25519.Sign(priv, core.CompareShareSigningMessage(req)),
	)
	return req
}

// queryCompareShareDeadline exercises the no-row query path: the chain must
// return the absolute deadline fixed by the match before either owner uploads
// a share.
func queryCompareShareDeadline(
	t *testing.T, orderA, orderB, owner core.OrderID, matchRound uint64,
) uint64 {
	t.Helper()
	data, err := rdCall("orderbook", "QueryCompareCoZk2pShares", map[string]any{
		"order_a_id": orderA, "order_b_id": orderB,
		"owner_order_id": owner, "match_round": matchRound,
	})
	if err != nil {
		t.Fatalf("QueryCompareCoZk2pShares: %v", err)
	}
	var response struct {
		DeadlineHeight uint64 `json:"deadline_height"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		t.Fatalf("decoding comparison share deadline: %v", err)
	}
	if response.DeadlineHeight == 0 {
		t.Fatal("chain returned an empty comparison share deadline")
	}
	return response.DeadlineHeight
}

func registerPairAddresses(
	t interface{ Fatalf(string, ...any) },
	alicePriv, bobPriv ed25519.PrivateKey,
	orderA, orderB core.OrderID,
	matchRound uint64,
) {
	a := &core.RegisterSettleAddrRequest{
		OrderID: orderA, MatchOrderID: orderB, MatchRound: matchRound,
		Addr: "127.0.0.1:19001", EncryptionPubkey: hexCommit(0x41),
	}
	a.Signature = hex.EncodeToString(ed25519.Sign(alicePriv, core.SettleAddrSigningMessage(a)))
	if err := wrCall("orderbook", "RegisterSettleAddr", a); err != nil {
		t.Fatalf("RegisterSettleAddr (A): %v", err)
	}
	waitBlock()
	b := &core.RegisterSettleAddrRequest{
		OrderID: orderB, MatchOrderID: orderA, MatchRound: matchRound,
		Addr: "127.0.0.1:19002", EncryptionPubkey: hexCommit(0x42),
	}
	b.Signature = hex.EncodeToString(ed25519.Sign(bobPriv, core.SettleAddrSigningMessage(b)))
	if err := wrCall("orderbook", "RegisterSettleAddr", b); err != nil {
		t.Fatalf("RegisterSettleAddr (B): %v", err)
	}
	waitBlock()
}
