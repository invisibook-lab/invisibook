package core

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"

	"github.com/yu-org/yu/core/context"
	"gorm.io/gorm"
)

const compareShareTimeoutBlocks uint64 = 10

// SubmitCompareShareRequest is one order owner's authenticated contribution
// to the two-submission PLONK comparison. ProofShare is the opaque canonical
// payload for that party's native final SPDZ value share; its version and
// party tag are decoded by the Rust verifier. Neither contribution is
// accepted on behalf of the other order owner.
type SubmitCompareShareRequest struct {
	ChainID        uint64  `json:"chain_id"`
	OrderAID       OrderID `json:"order_a_id" validate:"required"`
	OrderBID       OrderID `json:"order_b_id" validate:"required"`
	OwnerOrderID   OrderID `json:"owner_order_id" validate:"required"`
	MatchRound     uint64  `json:"match_round" validate:"required"`
	Cmp            int     `json:"cmp" validate:"oneof=-1 0 1"`
	DeadlineHeight uint64  `json:"deadline_height" validate:"required"`
	ProofShare     string  `json:"proof_share" validate:"required"`
	Signature      string  `json:"signature" validate:"required,len=128"`
}

type QueryCompareSharesRequest struct {
	OrderAID     OrderID `json:"order_a_id" validate:"required"`
	OrderBID     OrderID `json:"order_b_id" validate:"required"`
	OwnerOrderID OrderID `json:"owner_order_id" validate:"required"`
	MatchRound   uint64  `json:"match_round" validate:"required"`
}

type ExpireCompareSharesRequest struct {
	ChainID      uint64  `json:"chain_id"`
	OrderAID     OrderID `json:"order_a_id" validate:"required"`
	OrderBID     OrderID `json:"order_b_id" validate:"required"`
	OwnerOrderID OrderID `json:"owner_order_id" validate:"required"`
	MatchRound   uint64  `json:"match_round" validate:"required"`
	Signature    string  `json:"signature" validate:"required,len=128"`
}

type CompareSharesResponse struct {
	StateCommitment string `json:"state_commitment"`
	MySubmitted     bool   `json:"my_submitted"`
	PeerSubmitted   bool   `json:"peer_submitted"`
	Ready           bool   `json:"ready"`
	DeadlineHeight  uint64 `json:"deadline_height"`
	VerifiedHeight  uint64 `json:"verified_height"`
	ExpiredAtHeight uint64 `json:"expired_at_height"`
	MissingOrderID  string `json:"missing_order_id,omitempty"`
}

func compareShareDigest(proofShare string) (string, error) {
	raw, err := hex.DecodeString(proofShare)
	if err != nil || len(raw) == 0 {
		return "", fmt.Errorf("proof_share must be non-empty hex")
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}

func CompareShareSigningMessage(req *SubmitCompareShareRequest) []byte {
	digest, _ := compareShareDigest(req.ProofShare)
	buf := make([]byte, 0, 256)
	for _, field := range []string{
		"invisibook-cozk2p-proof-share-v3", strconv.FormatUint(req.ChainID, 10),
		string(req.OrderAID), string(req.OrderBID), string(req.OwnerOrderID),
		strconv.FormatUint(req.MatchRound, 10), strconv.Itoa(req.Cmp),
		strconv.FormatUint(req.DeadlineHeight, 10), digest,
	} {
		buf = appendSigningField(buf, field)
	}
	return buf
}

// compareProofShareDeadline is fixed by the match itself, not by whichever
// owner submits first. MatchHeight is refreshed on every match, including
// an immediate rematch of two historical/relisted orders whose original
// BlockHeight values intentionally remain unchanged for time priority.
func compareProofShareDeadline(a, b *Order) uint64 {
	matchHeight := a.MatchHeight
	if b.MatchHeight > matchHeight {
		matchHeight = b.MatchHeight
	}
	return matchHeight + compareShareTimeoutBlocks
}

func ExpireCompareSharesSigningMessage(req *ExpireCompareSharesRequest) []byte {
	buf := make([]byte, 0, 192)
	for _, field := range []string{
		"invisibook-expire-compare-shares-v1", strconv.FormatUint(req.ChainID, 10),
		string(req.OrderAID), string(req.OrderBID), string(req.OwnerOrderID),
		strconv.FormatUint(req.MatchRound, 10),
	} {
		buf = appendSigningField(buf, field)
	}
	return buf
}

func compareShareOwner(a, b *Order, ownerID OrderID) (*Order, bool, error) {
	switch ownerID {
	case a.ID:
		return a, true, nil
	case b.ID:
		return b, false, nil
	default:
		return nil, false, fmt.Errorf("owner_order_id is not a member of this pair")
	}
}

func (ot *OrderBook) compareShareStateCommitment(a, b *Order, cmp int) (string, error) {
	addrA, err := ot.GetSettleAddr(a.ID)
	if err != nil || addrA.MatchRound != a.MatchRound || addrA.MatchOrderID != string(b.ID) {
		return "", fmt.Errorf("order A rendezvous key missing or stale")
	}
	addrB, err := ot.GetSettleAddr(b.ID)
	if err != nil || addrB.MatchRound != b.MatchRound || addrB.MatchOrderID != string(a.ID) {
		return "", fmt.Errorf("order B rendezvous key missing or stale")
	}
	price := func(o *Order) string {
		if p := collateralPrice(o); p != nil {
			return p.String()
		}
		return ""
	}
	execution := ""
	if a.ExecutionPrice != nil {
		execution = a.ExecutionPrice.String()
	}
	buf := make([]byte, 0, 512)
	for _, field := range []string{
		"invisibook-compare-share-state-v1", string(a.ID), string(b.ID),
		strconv.FormatUint(a.MatchRound, 10), a.LockedCommitment, b.LockedCommitment,
		strconv.Itoa(int(a.Kind)), strconv.Itoa(int(b.Kind)), price(a), price(b),
		execution, strconv.Itoa(int(a.Type)), strconv.Itoa(cmp),
		addrA.EncryptionPubkey, addrB.EncryptionPubkey,
	} {
		buf = appendSigningField(buf, field)
	}
	digest := sha256.Sum256(buf)
	return hex.EncodeToString(digest[:]), nil
}

func compareSharesResponse(row *CompareShareScheme, mineIsA bool) CompareSharesResponse {
	myHeight, peerHeight := row.BSubmittedHeight, row.ASubmittedHeight
	if mineIsA {
		myHeight, peerHeight = row.ASubmittedHeight, row.BSubmittedHeight
	}
	return CompareSharesResponse{
		StateCommitment: row.StateCommitment,
		MySubmitted:     myHeight != 0, PeerSubmitted: peerHeight != 0,
		Ready: row.VerifiedHeight != 0, DeadlineHeight: row.DeadlineHeight,
		VerifiedHeight: row.VerifiedHeight, ExpiredAtHeight: row.ExpiredAtHeight,
		MissingOrderID: row.MissingOrderID,
	}
}

// SubmitCompareCoZk2pShare stores exactly one authenticated owner share. The
// match fixes the chain-derived deadline; after the second share arrives,
// Rust validates both opaque native shares, checks their public transcript,
// combines their final KZG point shares, and verifies the reconstructed proof
// before either order becomes Settling. That same transaction creates the
// settlement-leg round with its own absolute deadline, before payout-key
// exchange or quantity reveal.
func (ot *OrderBook) SubmitCompareCoZk2pShare(ctx *context.WriteContext) error {
	ctx.SetLei(100)
	LogPayloadSize("SubmitCompareCoZk2pShare", ctx.GetRequestBytes())
	req := new(SubmitCompareShareRequest)
	if err := ctx.BindJson(req); err != nil {
		return err
	}
	if err := Validator.Struct(req); err != nil {
		return err
	}
	if req.ChainID != ot.chainID {
		return fmt.Errorf("wrong chain_id %d", req.ChainID)
	}
	if _, err := compareShareDigest(req.ProofShare); err != nil {
		return err
	}
	a, b, _, err := ot.loadMatchedPair(req.OrderAID, req.OrderBID)
	if err != nil {
		return err
	}
	if a.MatchRound != req.MatchRound || b.MatchRound != req.MatchRound {
		return fmt.Errorf("stale match round %d", req.MatchRound)
	}
	deadline := compareProofShareDeadline(a, b)
	if req.DeadlineHeight != deadline {
		return fmt.Errorf("wrong comparison share deadline %d (want %d)", req.DeadlineHeight, deadline)
	}
	owner, ownerIsA, err := compareShareOwner(a, b, req.OwnerOrderID)
	if err != nil {
		return err
	}
	if err := verifyOrderOwnerSignature(owner, CompareShareSigningMessage(req), req.Signature); err != nil {
		return err
	}
	state, err := ot.compareShareStateCommitment(a, b, req.Cmp)
	if err != nil {
		return err
	}
	height := uint64(ctx.Block.Height)
	verified := false
	err = ot.db.Transaction(func(tx *gorm.DB) error {
		var row CompareShareScheme
		dbErr := tx.First(&row, "order_a_id = ? AND match_round = ?", string(a.ID), req.MatchRound).Error
		if dbErr == gorm.ErrRecordNotFound {
			row = CompareShareScheme{
				OrderAID: string(a.ID), OrderBID: string(b.ID), MatchRound: req.MatchRound,
				Cmp: req.Cmp, StateCommitment: state,
				DeadlineHeight: deadline,
			}
		} else if dbErr != nil {
			return dbErr
		}
		if row.OrderBID != string(b.ID) || row.Cmp != req.Cmp ||
			row.StateCommitment != state || row.DeadlineHeight != deadline {
			return fmt.Errorf("comparison share state mismatch")
		}
		if row.VerifiedHeight != 0 || row.ExpiredAtHeight != 0 {
			return fmt.Errorf("comparison share round is already closed")
		}
		if height > row.DeadlineHeight {
			return fmt.Errorf("comparison share deadline has elapsed")
		}
		if ownerIsA {
			if row.ShareA != "" && row.ShareA != req.ProofShare {
				return fmt.Errorf("order A already submitted a different proof share")
			}
			if row.ShareA == "" {
				row.ShareA, row.ASubmittedHeight = req.ProofShare, height
			}
		} else {
			if row.ShareB != "" && row.ShareB != req.ProofShare {
				return fmt.Errorf("order B already submitted a different proof share")
			}
			if row.ShareB == "" {
				row.ShareB, row.BSubmittedHeight = req.ProofShare, height
			}
		}
		if row.ShareA != "" && row.ShareB != "" {
			compareReq := &CompareRequest{OrderAID: a.ID, OrderBID: b.ID, Cmp: req.Cmp}
			publicJSON, err := buildCompare2pPublicJSON(compareReq, a, b)
			if err != nil {
				return fmt.Errorf("building compare public statement: %w", err)
			}
			if err := VerifyPlonkSettle2pShares(
				ot.settleCoZk2pVK, row.ShareA, row.ShareB, publicJSON,
			); err != nil {
				return fmt.Errorf("compare proof verification failed: %w", err)
			}
			if err := tx.Save(&CompareResultScheme{
				OrderAID: string(a.ID), OrderBID: string(b.ID), Cmp: req.Cmp, Height: height,
			}).Error; err != nil {
				return err
			}
			for _, id := range []OrderID{a.ID, b.ID} {
				result := tx.Model(&OrderScheme{}).
					Where("id = ? AND status = ?", string(id), int(Matched)).
					Update("status", int(Settling))
				if result.Error != nil {
					return result.Error
				}
				if result.RowsAffected != 1 {
					return fmt.Errorf("order %s left Matched while assembling comparison", id)
				}
			}
			// Open the post-compare settlement window immediately. A zero-leg
			// timeout therefore has a durable, chain-derived unattributed release
			// path when neither owner supplies on-chain delivery evidence.
			legRound := &SettleLegRoundScheme{
				OrderAID: string(a.ID), OrderBID: string(b.ID), MatchRound: req.MatchRound,
				DeadlineHeight: height + settleLegTimeoutBlocks,
			}
			if err := tx.Create(legRound).Error; err != nil {
				return fmt.Errorf("opening settlement-leg round: %w", err)
			}
			row.VerifiedHeight = height
			verified = true
		}
		return tx.Save(&row).Error
	})
	if err != nil {
		return fmt.Errorf("submitting comparison proof share: %w", err)
	}
	if verified {
		return ctx.EmitJsonEvent(&CompareEvent{
			EventType: "compared", Cmp: req.Cmp, OrderA: a.ID, OrderB: b.ID,
		})
	}
	return ctx.EmitJsonEvent(map[string]any{
		"event_type": "compare_share_submitted", "owner_order_id": owner.ID,
		"deadline_height": deadline,
	})
}

func (ot *OrderBook) QueryCompareCoZk2pShares(ctx *context.ReadContext) {
	req := new(QueryCompareSharesRequest)
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
	var row CompareShareScheme
	if err := ot.db.First(&row, "order_a_id = ? AND order_b_id = ? AND match_round = ?",
		string(req.OrderAID), string(req.OrderBID), req.MatchRound).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			a, b, _, pairErr := ot.loadMatchedPair(req.OrderAID, req.OrderBID)
			if pairErr != nil {
				ctx.Json(http.StatusBadRequest, map[string]string{"error": pairErr.Error()})
				return
			}
			if a.MatchRound != req.MatchRound || b.MatchRound != req.MatchRound {
				ctx.Json(http.StatusBadRequest, map[string]string{
					"error": fmt.Sprintf("stale match round %d", req.MatchRound),
				})
				return
			}
			ctx.JsonOk(CompareSharesResponse{DeadlineHeight: compareProofShareDeadline(a, b)})
			return
		}
		ctx.Json(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	ctx.JsonOk(compareSharesResponse(&row, req.OwnerOrderID == req.OrderAID))
}

// ExpireCompareCoZk2pShares closes a pre-reveal round after its chain-derived
// deadline. No privacy opening has occurred, so both orders are released to
// Pending; MissingOrderID is retained only as an audit fact, not punished.
func (ot *OrderBook) ExpireCompareCoZk2pShares(ctx *context.WriteContext) error {
	ctx.SetLei(30)
	req := new(ExpireCompareSharesRequest)
	if err := ctx.BindJson(req); err != nil {
		return err
	}
	if err := Validator.Struct(req); err != nil {
		return err
	}
	if req.ChainID != ot.chainID {
		return fmt.Errorf("wrong chain_id %d", req.ChainID)
	}
	a, b, _, err := ot.loadMatchedPair(req.OrderAID, req.OrderBID)
	if err != nil {
		return err
	}
	if a.MatchRound != req.MatchRound || b.MatchRound != req.MatchRound {
		return fmt.Errorf("stale match round %d", req.MatchRound)
	}
	deadline := compareProofShareDeadline(a, b)
	owner, _, err := compareShareOwner(a, b, req.OwnerOrderID)
	if err != nil {
		return err
	}
	if err := verifyOrderOwnerSignature(owner, ExpireCompareSharesSigningMessage(req), req.Signature); err != nil {
		return err
	}
	height := uint64(ctx.Block.Height)
	var missing OrderID
	err = ot.db.Transaction(func(tx *gorm.DB) error {
		var row CompareShareScheme
		dbErr := tx.First(&row, "order_a_id = ? AND match_round = ?", string(a.ID), req.MatchRound).Error
		if dbErr == gorm.ErrRecordNotFound {
			row = CompareShareScheme{
				OrderAID: string(a.ID), OrderBID: string(b.ID), MatchRound: req.MatchRound,
				DeadlineHeight: deadline,
			}
		} else if dbErr != nil {
			return fmt.Errorf("loading comparison share round: %w", dbErr)
		}
		if row.OrderBID != string(b.ID) || row.DeadlineHeight != deadline {
			return fmt.Errorf("comparison share state mismatch")
		}
		if row.VerifiedHeight != 0 || row.ExpiredAtHeight != 0 {
			return fmt.Errorf("comparison share round is already closed")
		}
		if height <= row.DeadlineHeight {
			return fmt.Errorf("comparison share deadline has not elapsed")
		}
		if row.ShareA != "" && row.ShareB != "" {
			return fmt.Errorf("cannot expire a round with both proof shares submitted")
		}
		if row.ShareA == "" && row.ShareB != "" {
			missing = a.ID
		} else if row.ShareA != "" && row.ShareB == "" {
			missing = b.ID
		}
		row.ExpiredAtHeight, row.MissingOrderID = height, string(missing)
		if err := tx.Save(&row).Error; err != nil {
			return err
		}
		for _, id := range []OrderID{a.ID, b.ID} {
			if err := tx.Model(&OrderScheme{}).Where("id = ?", string(id)).Updates(map[string]any{
				"status": int(Pending), "match_order": "", "execution_price": "",
			}).Error; err != nil {
				return err
			}
		}
		return tx.Where("order_id IN ?", []string{string(a.ID), string(b.ID)}).
			Delete(&SettleAddrScheme{}).Error
	})
	if err != nil {
		return fmt.Errorf("expiring comparison share round: %w", err)
	}
	return ctx.EmitJsonEvent(map[string]any{
		"event_type": "compare_share_round_expired", "missing_order_id": missing,
		"order_a": a.ID, "order_b": b.ID,
	})
}
