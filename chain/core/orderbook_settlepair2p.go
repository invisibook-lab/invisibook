package core

import (
	"encoding/json"
	"fmt"
	"log"
	"strconv"

	"github.com/yu-org/yu/core/context"
)

// ────────────────────── Writing: SettlePairCoZk2p ──────────────────────
//
// The MERGED settlement: ONE collaborative TurboPlonk proof covers the
// quantity comparison AND both settlement legs, so a Matched pair settles
// in a single writing — no Settling stage, no per-leg Groth16 proofs, and
// no reveal of either quantity before the settlement is final. The split
// flow (SubmitCompareCoZk2p + SettlePair) stays registered unchanged; the
// two paths coexist for benchmarking.

// SettlePairCoZk2pRequest carries the merged settlement of a matched pair.
// LOCKED-ONLY MODEL: an order commits only its collateral, so each side
// contributes ONE residual commitment. Both are ALWAYS present — the merged
// statement commits the fully filled side's residual collateral to zero —
// but only the larger side's is applied to its order row. `ZkProof` is hex
// of the ark-compressed PLONK proof both traders revealed.
type SettlePairCoZk2pRequest struct {
	OrderAID OrderID `json:"order_a_id" validate:"required"`
	OrderBID OrderID `json:"order_b_id" validate:"required"`
	Cmp      int     `json:"cmp"        validate:"oneof=-1 0 1"`

	// MPC-computed output commitments (statement signals 1..4).
	// cm_note_out_a is the payout note minted TO trader A, and vice versa.
	CmNoteOutA        string `json:"cm_note_out_a"        validate:"required,len=64"`
	CmNoteOutB        string `json:"cm_note_out_b"        validate:"required,len=64"`
	CmLockedResidualA string `json:"cm_locked_residual_a" validate:"required,len=64"`
	CmLockedResidualB string `json:"cm_locked_residual_b" validate:"required,len=64"`

	// ed25519 signatures (128-char hex) over the canonical merged settle
	// message, by each order's pubkey.
	SigA string `json:"sig_a" validate:"required,len=128"`
	SigB string `json:"sig_b" validate:"required,len=128"`

	ZkProof string `json:"zk_proof" validate:"required"`
}

// SettlePairCoZk2pMessage is the canonical byte string BOTH traders
// ed25519-sign for a merged settlement: length-prefixed and
// domain-separated, covering the pair ids, cmp, and every output
// commitment. Must stay in lockstep with the Rust client.
func SettlePairCoZk2pMessage(req *SettlePairCoZk2pRequest) []byte {
	return settleSigMessage("invisibook-settle-pair-cozk2p-v1",
		string(req.OrderAID), string(req.OrderBID), strconv.Itoa(req.Cmp),
		req.CmNoteOutA, req.CmNoteOutB,
		req.CmLockedResidualA, req.CmLockedResidualB)
}

// settlePair2pPublic mirrors cozk2p's `PairPublic` serde layout
// (cozk2p/src/relation_pair.rs): the merged 11-signal statement. Field
// names and order must stay in lockstep with the Rust struct.
type settlePair2pPublic struct {
	Cmp          int    `json:"cmp"`
	CmNoteOutA   string `json:"cm_note_out_a"`
	CmNoteOutB   string `json:"cm_note_out_b"`
	CmLockedResA string `json:"cm_locked_res_a"`
	CmLockedResB string `json:"cm_locked_res_b"`
	LockedA      string `json:"locked_a"`
	LockedB      string `json:"locked_b"`
	Price        uint64 `json:"price"`
	AIsSeller    bool   `json:"a_is_seller"`
	AssetRecvA   string `json:"asset_recv_a"`
	AssetRecvB   string `json:"asset_recv_b"`
}

// buildSettlePair2pPublicJSON rebuilds the canonical `PairPublic` JSON:
// signals 0..4 from the request, 5..10 from on-chain order state. Each
// order's recv asset is the counterparty's lock token.
func buildSettlePair2pPublicJSON(
	req *SettlePairCoZk2pRequest, orderA, orderB *Order, price uint64,
) ([]byte, error) {
	assetRecvA, err := AssetID(recvToken(orderA))
	if err != nil {
		return nil, fmt.Errorf("order A recv asset: %w", err)
	}
	assetRecvB, err := AssetID(recvToken(orderB))
	if err != nil {
		return nil, fmt.Errorf("order B recv asset: %w", err)
	}
	public := settlePair2pPublic{
		Cmp:          req.Cmp,
		CmNoteOutA:   req.CmNoteOutA,
		CmNoteOutB:   req.CmNoteOutB,
		CmLockedResA: req.CmLockedResidualA,
		CmLockedResB: req.CmLockedResidualB,
		LockedA:      orderA.LockedCommitment,
		LockedB:      orderB.LockedCommitment,
		Price:        price,
		AIsSeller:    orderA.Type == Sell,
		AssetRecvA:   FrToHex(assetRecvA),
		AssetRecvB:   FrToHex(assetRecvB),
	}
	return json.Marshal(&public)
}

// SettlePairCoZk2p settles a MATCHED pair with one merged collaborative
// proof: dual signatures + one PLONK verification, then the same
// journaled, idempotent settlement pipeline as SettlePair (mint both
// payout notes at most once, close the filled side(s), relist the larger
// side in place). A crash between the two databases is completed by a
// resubmission of the same request or by the startup recovery — the
// orders stay Matched until the order-side transaction commits.
func (ot *OrderBook) SettlePairCoZk2p(ctx *context.WriteContext) error {
	ctx.SetLei(100)

	req := new(SettlePairCoZk2pRequest)
	if err := ctx.BindJson(req); err != nil {
		return err
	}
	if err := Validator.Struct(req); err != nil {
		return err
	}
	evt, err := ot.executeSettlePairMerged(req, uint64(ctx.Block.Height))
	if err != nil {
		return err
	}
	return ctx.EmitJsonEvent(evt)
}

// executeSettlePairMerged verifies and applies a merged settlement: the
// checks-then-journaled-pipeline body of SettlePairCoZk2p, split out so
// tests can drive it without a WriteContext.
func (ot *OrderBook) executeSettlePairMerged(
	req *SettlePairCoZk2pRequest, height uint64,
) (*SettlePairEvent, error) {
	// Canonical-form checks on the request-carried commitments: the Rust
	// verifier reduces non-canonical hex mod r, which would silently alias
	// another statement.
	for what, h := range map[string]string{
		"cm_note_out_a":        req.CmNoteOutA,
		"cm_note_out_b":        req.CmNoteOutB,
		"cm_locked_residual_a": req.CmLockedResidualA,
		"cm_locked_residual_b": req.CmLockedResidualB,
	} {
		if _, err := ParseFrHex(h); err != nil {
			return nil, fmt.Errorf("non-canonical %s: %w", what, err)
		}
	}

	// Same preconditions as the compare phase: Matched pair, mutual link,
	// opposite sides, A is the maker, prices valid and equal.
	orderA, orderB, price, err := ot.loadMatchedPair(req.OrderAID, req.OrderBID)
	if err != nil {
		return nil, err
	}
	if err := verifyCoZkSignature(orderA.Pubkey, req.SigA, SettlePairCoZk2pMessage(req)); err != nil {
		return nil, fmt.Errorf("order A signature: %w", err)
	}
	if err := verifyCoZkSignature(orderB.Pubkey, req.SigB, SettlePairCoZk2pMessage(req)); err != nil {
		return nil, fmt.Errorf("order B signature: %w", err)
	}

	publicJSON, err := buildSettlePair2pPublicJSON(req, orderA, orderB, price)
	if err != nil {
		return nil, fmt.Errorf("building merged settle statement: %w", err)
	}
	if err := VerifyPlonkSettlePair(ot.settlePairCoZk2pVK, req.ZkProof, publicJSON); err != nil {
		return nil, fmt.Errorf("merged settle proof verification failed: %w", err)
	}

	return ot.applyMergedSettlement(req, orderA, orderB, height)
}

// applyMergedSettlement runs the journaled settlement pipeline for an
// already-verified merged request — the exact machinery of
// executeSettlePair steps 2..5 (see its doc comment), sharing the journal
// schema, mint idempotency, order updates, and recovery path.
func (ot *OrderBook) applyMergedSettlement(
	req *SettlePairCoZk2pRequest, orderA, orderB *Order, height uint64,
) (*SettlePairEvent, error) {
	aIsLarge := req.Cmp > 0
	bIsLarge := req.Cmp < 0

	// The journal stores each leg by its PAYER: CmNoteA is what A's leg
	// mints (= B's incoming note, cm_note_out_b) and vice versa — the same
	// orientation as SettlePair's per-leg requests. The residual COLLATERAL
	// commitment (the only re-commitment in the locked-only model) is
	// recorded for the larger side only; the smaller side's zero-commitment
	// is verified by the proof but never applied to an order row.
	id := settlementID(orderA.ID, orderB.ID)
	journal := &SettlementJournalScheme{
		SettlementID: id,
		OrderAID:     string(orderA.ID),
		OrderBID:     string(orderB.ID),
		CmNoteA:      req.CmNoteOutB,
		CmNoteB:      req.CmNoteOutA,
		ALarge:       aIsLarge,
		BLarge:       bIsLarge,
		State:        SettlementPending,
		Height:       height,
	}
	if aIsLarge {
		journal.CmLockedResidA = req.CmLockedResidualA
	}
	if bIsLarge {
		journal.CmLockedResidB = req.CmLockedResidualB
	}
	if err := ot.UpsertSettlementJournal(journal); err != nil {
		return nil, fmt.Errorf("writing settlement journal: %w", err)
	}

	indices, already, err := ot.Account.MintSettlementNotes(
		id, journal.CmNoteA, journal.CmNoteB, height,
		fmt.Sprintf("settle-pair-cozk2p:%.8s", string(req.OrderAID)))
	if err != nil {
		return nil, fmt.Errorf("minting payout notes: %w", err)
	}
	if already {
		log.Printf("[settle] %.16s: payout notes already minted, resuming order updates", id)
	}

	// TESTS ONLY: injected crash between the two databases.
	if settlePairFailpoint != nil {
		if ferr := settlePairFailpoint(); ferr != nil {
			return nil, ferr
		}
	}

	if err := ot.finishSettlementOrders(journal); err != nil {
		return nil, fmt.Errorf("applying order updates: %w", err)
	}

	evt := &SettlePairEvent{
		EventType:  "settle_pair_cozk2p",
		OrderA:     orderA.ID,
		OrderB:     orderB.ID,
		ALeafIndex: indices[1], // A's incoming note = the one B's leg minted
		BLeafIndex: indices[0], // B's incoming note = the one A's leg minted
	}
	ot.postSettlementCleanup(journal, evt)
	return evt, nil
}
