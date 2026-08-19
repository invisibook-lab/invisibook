package core

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"

	"github.com/yu-org/yu/core/context"
	"gorm.io/gorm"
)

const settleLegTimeoutBlocks uint64 = 10

type SubmitSettleLegRequest struct {
	ChainID             uint64        `json:"chain_id"`
	OrderAID            OrderID       `json:"order_a_id" validate:"required"`
	OrderBID            OrderID       `json:"order_b_id" validate:"required"`
	OwnerOrderID        OrderID       `json:"owner_order_id" validate:"required"`
	MatchRound          uint64        `json:"match_round" validate:"required"`
	Leg                 SettlePairLeg `json:"leg"`
	SubmissionSignature string        `json:"submission_signature" validate:"required,len=128"`
}

type ExpireSettleLegsRequest struct {
	ChainID      uint64  `json:"chain_id"`
	OrderAID     OrderID `json:"order_a_id" validate:"required"`
	OrderBID     OrderID `json:"order_b_id" validate:"required"`
	OwnerOrderID OrderID `json:"owner_order_id" validate:"required"`
	MatchRound   uint64  `json:"match_round" validate:"required"`
	Signature    string  `json:"signature" validate:"required,len=128"`
}

type QuerySettleLegsRequest struct {
	OrderAID     OrderID `json:"order_a_id" validate:"required"`
	OrderBID     OrderID `json:"order_b_id" validate:"required"`
	OwnerOrderID OrderID `json:"owner_order_id" validate:"required"`
	MatchRound   uint64  `json:"match_round" validate:"required"`
}

// FinalizeSettleLegsRequest carries no new settlement data or authority.
// Once both identity-bound legs are durably stored, anyone may ask the chain
// to resume their deterministic, journaled atomic execution.
type FinalizeSettleLegsRequest struct {
	ChainID    uint64  `json:"chain_id"`
	OrderAID   OrderID `json:"order_a_id" validate:"required"`
	OrderBID   OrderID `json:"order_b_id" validate:"required"`
	MatchRound uint64  `json:"match_round" validate:"required"`
}

type SettleLegsResponse struct {
	MySubmitted     bool   `json:"my_submitted"`
	PeerSubmitted   bool   `json:"peer_submitted"`
	Complete        bool   `json:"complete"`
	DeadlineHeight  uint64 `json:"deadline_height"`
	CompletedHeight uint64 `json:"completed_height"`
	ExpiredAtHeight uint64 `json:"expired_at_height"`
	MissingOrderID  string `json:"missing_order_id,omitempty"`
}

func settleLegProofDigest(proof string) string {
	digest := sha256.Sum256([]byte(proof))
	return hex.EncodeToString(digest[:])
}

func SettleLegSubmissionSigningMessage(req *SubmitSettleLegRequest) []byte {
	buf := make([]byte, 0, 512)
	for _, field := range []string{
		"invisibook-submit-settle-leg-v1", strconv.FormatUint(req.ChainID, 10),
		string(req.OrderAID), string(req.OrderBID), string(req.OwnerOrderID),
		strconv.FormatUint(req.MatchRound, 10), req.Leg.CmNoteOut, req.Leg.CmRefundOut,
		req.Leg.CmLockedResidual, req.Leg.Signature, settleLegProofDigest(req.Leg.ZkProof),
	} {
		buf = appendSigningField(buf, field)
	}
	return buf
}

func ExpireSettleLegsSigningMessage(req *ExpireSettleLegsRequest) []byte {
	buf := make([]byte, 0, 192)
	for _, field := range []string{
		"invisibook-expire-settle-legs-v1", strconv.FormatUint(req.ChainID, 10),
		string(req.OrderAID), string(req.OrderBID), string(req.OwnerOrderID),
		strconv.FormatUint(req.MatchRound, 10),
	} {
		buf = appendSigningField(buf, field)
	}
	return buf
}

func decodeStoredSettleLeg(raw string) (SettlePairLeg, error) {
	var leg SettlePairLeg
	if err := json.Unmarshal([]byte(raw), &leg); err != nil {
		return leg, fmt.Errorf("decoding stored settlement leg: %w", err)
	}
	return leg, nil
}

func settleLegPairLandedInTime(row *SettleLegRoundScheme) bool {
	return row.LegAJSON != "" && row.LegBJSON != "" &&
		row.ASubmittedHeight != 0 && row.BSubmittedHeight != 0 &&
		row.ASubmittedHeight <= row.DeadlineHeight &&
		row.BSubmittedHeight <= row.DeadlineHeight
}

func settleLegsResponse(row *SettleLegRoundScheme, mineIsA bool) SettleLegsResponse {
	mine, peer := row.LegBJSON, row.LegAJSON
	if mineIsA {
		mine, peer = row.LegAJSON, row.LegBJSON
	}
	return SettleLegsResponse{
		MySubmitted: mine != "", PeerSubmitted: peer != "", Complete: row.CompletedHeight != 0,
		DeadlineHeight: row.DeadlineHeight, CompletedHeight: row.CompletedHeight,
		ExpiredAtHeight: row.ExpiredAtHeight, MissingOrderID: row.MissingOrderID,
	}
}

// SubmitSettleLeg independently verifies and stores this order owner's leg.
// Comparison verification already created the absolute round deadline. One
// leg changes no balances; once both are present, executeSettlePair re-verifies
// them and performs the existing journaled atomic settlement.
func (ot *OrderBook) SubmitSettleLeg(ctx *context.WriteContext) error {
	ctx.SetLei(100)
	LogPayloadSize("SubmitSettleLeg", ctx.GetRequestBytes())
	req := new(SubmitSettleLegRequest)
	if err := ctx.BindJson(req); err != nil {
		return err
	}
	if err := Validator.Struct(req); err != nil {
		return err
	}
	if req.ChainID != ot.chainID {
		return fmt.Errorf("wrong chain_id %d", req.ChainID)
	}
	a, b, cmpA, err := ot.loadSettlingPair(req.OrderAID, req.OrderBID)
	if err != nil {
		return err
	}
	if a.MatchRound != req.MatchRound || b.MatchRound != req.MatchRound {
		return fmt.Errorf("stale match round %d", req.MatchRound)
	}
	owner, ownerIsA, err := compareShareOwner(a, b, req.OwnerOrderID)
	if err != nil {
		return err
	}
	if err := verifyOrderOwnerSignature(owner, SettleLegSubmissionSigningMessage(req), req.SubmissionSignature); err != nil {
		return err
	}
	isLarge := (ownerIsA && cmpA > 0) || (!ownerIsA && cmpA < 0)
	match := a
	if ownerIsA {
		match = b
	}
	if _, err := ot.verifyPairLeg(owner, match, isLarge, req.Leg); err != nil {
		return fmt.Errorf("owner settlement leg: %w", err)
	}
	legJSON, err := json.Marshal(req.Leg)
	if err != nil {
		return err
	}
	height := uint64(ctx.Block.Height)
	var pair *SettlePairRequest
	var deadline uint64
	err = ot.db.Transaction(func(tx *gorm.DB) error {
		var row SettleLegRoundScheme
		dbErr := tx.First(&row, "order_a_id = ? AND match_round = ?", string(a.ID), req.MatchRound).Error
		if dbErr == gorm.ErrRecordNotFound {
			return fmt.Errorf("settlement leg round was not opened by comparison verification")
		} else if dbErr != nil {
			return dbErr
		}
		if row.OrderBID != string(b.ID) || row.CompletedHeight != 0 || row.ExpiredAtHeight != 0 {
			return fmt.Errorf("settlement leg round is already closed or mismatched")
		}
		if height > row.DeadlineHeight {
			// Once both legs landed in time, either owner must be able to retry
			// the journaled cross-database settlement after a transient failure.
			// This does not admit a late second leg: both stored submissions and
			// both of their original heights must already be within the window.
			if !settleLegPairLandedInTime(&row) {
				return fmt.Errorf("settlement leg deadline has elapsed")
			}
		}
		deadline = row.DeadlineHeight
		if ownerIsA {
			if row.LegAJSON != "" && row.LegAJSON != string(legJSON) {
				return fmt.Errorf("order A already submitted a different settlement leg")
			}
			if row.LegAJSON == "" {
				row.LegAJSON, row.ASubmittedHeight = string(legJSON), height
			}
		} else {
			if row.LegBJSON != "" && row.LegBJSON != string(legJSON) {
				return fmt.Errorf("order B already submitted a different settlement leg")
			}
			if row.LegBJSON == "" {
				row.LegBJSON, row.BSubmittedHeight = string(legJSON), height
			}
		}
		if row.LegAJSON != "" && row.LegBJSON != "" {
			legA, err := decodeStoredSettleLeg(row.LegAJSON)
			if err != nil {
				return err
			}
			legB, err := decodeStoredSettleLeg(row.LegBJSON)
			if err != nil {
				return err
			}
			pair = &SettlePairRequest{OrderAID: a.ID, OrderBID: b.ID, A: legA, B: legB}
		}
		return tx.Save(&row).Error
	})
	if err != nil {
		return fmt.Errorf("storing settlement leg: %w", err)
	}
	if pair == nil {
		return ctx.EmitJsonEvent(map[string]any{
			"event_type": "settle_leg_submitted", "owner_order_id": owner.ID,
			"deadline_height": deadline,
		})
	}
	evt, err := ot.executeSettlePair(pair, height)
	if err != nil {
		return err
	}
	return ctx.EmitJsonEvent(evt)
}

// FinalizeSettleLegs resumes atomic execution using only the two previously
// verified and owner-authenticated legs. It is permissionless because the
// caller cannot alter payout commitments, proofs, or signatures.
func (ot *OrderBook) FinalizeSettleLegs(ctx *context.WriteContext) error {
	ctx.SetLei(100)
	req := new(FinalizeSettleLegsRequest)
	if err := ctx.BindJson(req); err != nil {
		return err
	}
	if err := Validator.Struct(req); err != nil {
		return err
	}
	if req.ChainID != ot.chainID {
		return fmt.Errorf("wrong chain_id %d", req.ChainID)
	}
	a, b, _, err := ot.loadSettlingPair(req.OrderAID, req.OrderBID)
	if err != nil {
		return err
	}
	if a.MatchRound != req.MatchRound || b.MatchRound != req.MatchRound {
		return fmt.Errorf("stale match round %d", req.MatchRound)
	}
	var row SettleLegRoundScheme
	if err := ot.db.First(&row, "order_a_id = ? AND order_b_id = ? AND match_round = ?",
		string(a.ID), string(b.ID), req.MatchRound).Error; err != nil {
		return fmt.Errorf("loading settlement leg round: %w", err)
	}
	if row.CompletedHeight != 0 || row.ExpiredAtHeight != 0 {
		return fmt.Errorf("settlement leg round is already closed")
	}
	if !settleLegPairLandedInTime(&row) {
		return fmt.Errorf("both settlement legs were not submitted by the deadline")
	}
	legA, err := decodeStoredSettleLeg(row.LegAJSON)
	if err != nil {
		return err
	}
	legB, err := decodeStoredSettleLeg(row.LegBJSON)
	if err != nil {
		return err
	}
	evt, err := ot.executeSettlePair(&SettlePairRequest{
		OrderAID: a.ID, OrderBID: b.ID, A: legA, B: legB,
	}, uint64(ctx.Block.Height))
	if err != nil {
		return err
	}
	return ctx.EmitJsonEvent(evt)
}

func (ot *OrderBook) QuerySettleLegs(ctx *context.ReadContext) {
	req := new(QuerySettleLegsRequest)
	if err := ctx.BindJson(req); err != nil {
		ctx.Json(http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := Validator.Struct(req); err != nil {
		ctx.Json(http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if req.OwnerOrderID != req.OrderAID && req.OwnerOrderID != req.OrderBID {
		ctx.Json(http.StatusBadRequest, map[string]string{"error": "owner_order_id is not a member of this pair"})
		return
	}
	var row SettleLegRoundScheme
	if err := ot.db.First(&row, "order_a_id = ? AND order_b_id = ? AND match_round = ?",
		string(req.OrderAID), string(req.OrderBID), req.MatchRound).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			ctx.JsonOk(SettleLegsResponse{})
			return
		}
		ctx.Json(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if row.CompletedHeight == 0 {
		journal, err := ot.GetSettlementJournal(settlementID(req.OrderAID, req.OrderBID))
		if err != nil {
			ctx.Json(http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if journal != nil && journal.State == SettlementDone &&
			(journal.MatchRound == 0 || journal.MatchRound == req.MatchRound) {
			row.CompletedHeight = journal.Height
		}
	}
	ctx.JsonOk(settleLegsResponse(&row, req.OwnerOrderID == req.OrderAID))
}

// ExpireSettleLegs closes the settlement window opened when comparison
// verification succeeds. Zero legs provide no reveal evidence. A lone
// small-side proof is also insufficient: its owner can construct it without
// sending q to the large owner. Thus zero legs, only-small, and every
// incomplete cmp==0 round release both orders without blame. Only a lone
// large-side proof proves that the large owner learned the small opening; in
// that case the missing small owner is frozen. Either pair owner may trigger
// this deterministic transition after the deadline.
func (ot *OrderBook) ExpireSettleLegs(ctx *context.WriteContext) error {
	ctx.SetLei(30)
	req := new(ExpireSettleLegsRequest)
	if err := ctx.BindJson(req); err != nil {
		return err
	}
	if err := Validator.Struct(req); err != nil {
		return err
	}
	if req.ChainID != ot.chainID {
		return fmt.Errorf("wrong chain_id %d", req.ChainID)
	}
	a, b, cmpA, err := ot.loadSettlingPair(req.OrderAID, req.OrderBID)
	if err != nil {
		return err
	}
	if a.MatchRound != req.MatchRound || b.MatchRound != req.MatchRound {
		return fmt.Errorf("stale match round %d", req.MatchRound)
	}
	owner, _, err := compareShareOwner(a, b, req.OwnerOrderID)
	if err != nil {
		return err
	}
	if err := verifyOrderOwnerSignature(owner, ExpireSettleLegsSigningMessage(req), req.Signature); err != nil {
		return err
	}
	height := uint64(ctx.Block.Height)
	var survivor, missing *Order
	punitive := false
	err = ot.db.Transaction(func(tx *gorm.DB) error {
		var row SettleLegRoundScheme
		if err := tx.First(&row, "order_a_id = ? AND match_round = ?", string(a.ID), req.MatchRound).Error; err != nil {
			return fmt.Errorf("settlement leg round not found: %w", err)
		}
		if row.OrderBID != string(b.ID) {
			return fmt.Errorf("settlement leg round pair mismatch")
		}
		if row.CompletedHeight != 0 || row.ExpiredAtHeight != 0 {
			return fmt.Errorf("settlement leg round is already closed")
		}
		if height <= row.DeadlineHeight {
			return fmt.Errorf("settlement leg deadline has not elapsed")
		}
		aSubmitted, bSubmitted := row.LegAJSON != "", row.LegBJSON != ""
		if aSubmitted && bSubmitted {
			return fmt.Errorf("cannot expire a round with both settlement legs")
		}
		if !aSubmitted && !bSubmitted {
			for _, order := range []*Order{a, b} {
				if err := tx.Model(&OrderScheme{}).Where("id = ?", string(order.ID)).Updates(map[string]any{
					"status": int(Pending), "match_order": "", "execution_price": "",
				}).Error; err != nil {
					return err
				}
			}
			row.ExpiredAtHeight, row.MissingOrderID = height, ""
		} else {
			submitted, other := b, a
			if aSubmitted {
				submitted, other = a, b
			}
			submittedIsLarge := (submitted.ID == a.ID && cmpA > 0) ||
				(submitted.ID == b.ID && cmpA < 0)
			if cmpA != 0 && submittedIsLarge {
				// Constructing the large proof needs the small opening, so the
				// missing small owner is now the only blameable party.
				punitive, survivor, missing = true, submitted, other
				if err := tx.Model(&OrderScheme{}).Where("id = ?", string(survivor.ID)).Updates(map[string]any{
					"status": int(Pending), "match_order": "", "execution_price": "",
				}).Error; err != nil {
					return err
				}
				if err := tx.Model(&OrderScheme{}).Where("id = ?", string(missing.ID)).Updates(map[string]any{
					"status": int(Frozen), "match_order": "", "execution_price": "",
				}).Error; err != nil {
					return err
				}
				row.ExpiredAtHeight, row.MissingOrderID = height, string(missing.ID)
			} else {
				// A small proof alone does not prove q delivery; cmp==0 has no
				// smaller opening at all. Both cases are non-punitive.
				for _, order := range []*Order{a, b} {
					if err := tx.Model(&OrderScheme{}).Where("id = ?", string(order.ID)).Updates(map[string]any{
						"status": int(Pending), "match_order": "", "execution_price": "",
					}).Error; err != nil {
						return err
					}
				}
				row.ExpiredAtHeight, row.MissingOrderID = height, ""
			}
		}
		if err := tx.Save(&row).Error; err != nil {
			return err
		}
		if err := tx.Where("(order_a_id = ? AND order_b_id = ?) OR (order_a_id = ? AND order_b_id = ?)",
			string(a.ID), string(b.ID), string(b.ID), string(a.ID)).Delete(&CompareResultScheme{}).Error; err != nil {
			return err
		}
		return tx.Where("order_id IN ?", []string{string(a.ID), string(b.ID)}).
			Delete(&SettleAddrScheme{}).Error
	})
	if err != nil {
		return fmt.Errorf("expiring settlement legs: %w", err)
	}
	if !punitive {
		for _, order := range []*Order{a, b} {
			order.Status, order.MatchOrder, order.ExecutionPrice = Pending, "", nil
		}
		return ctx.EmitJsonEvent(map[string]any{
			"event_type": "settlement_unattributed_timeout", "released": []*Order{a, b},
			"reveal_delivery_proven": false,
		})
	}
	survivor.Status, survivor.MatchOrder, survivor.ExecutionPrice = Pending, "", nil
	missing.Status, missing.MatchOrder, missing.ExecutionPrice = Frozen, "", nil
	var matched *Order
	matched, err = ot.matchOrder(survivor, height)
	if err != nil {
		// The expiry transaction is already committed. Treat rematching as
		// best-effort cleanup so callers never see a failed transaction after
		// the survivor was in fact released and the missing owner frozen.
		log.Printf("[settle] re-matching timeout survivor %s: %v", survivor.ID, err)
		matched = nil
	}
	return ctx.EmitJsonEvent(map[string]any{
		"event_type": "settlement_leg_timeout", "survivor": survivor,
		"missing": missing, "matched": matched, "reveal_delivery_proven": true,
	})
}
