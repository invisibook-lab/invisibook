package core

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"

	"github.com/yu-org/yu/core/context"
	"gorm.io/gorm"
)

const settleCheckpointTimeoutBlocks uint64 = 10

type SubmitSettleCheckpointRequest struct {
	OrderID      OrderID `json:"order_id" validate:"required"`
	MatchOrderID OrderID `json:"match_order_id" validate:"required"`
	MatchRound   uint64  `json:"match_round" validate:"required"`
	Signature    string  `json:"signature" validate:"required"`
}

type AbortSettleRoundRequest struct {
	OrderID      OrderID `json:"order_id" validate:"required"`
	MatchOrderID OrderID `json:"match_order_id" validate:"required"`
	MatchRound   uint64  `json:"match_round" validate:"required"`
	Signature    string  `json:"signature" validate:"required"`
}

type QuerySettleCheckpointRequest struct {
	OrderID      OrderID `json:"order_id" validate:"required"`
	MatchOrderID OrderID `json:"match_order_id" validate:"required"`
	MatchRound   uint64  `json:"match_round" validate:"required"`
}

type SettleCheckpointResponse struct {
	StateCommitment string `json:"state_commitment"`
	MySubmitted     bool   `json:"my_submitted"`
	PeerSubmitted   bool   `json:"peer_submitted"`
	Ready           bool   `json:"ready"`
	DeadlineHeight  uint64 `json:"deadline_height"`
	AbortedOrderID  string `json:"aborted_order_id,omitempty"`
}

func checkpointMessage(domain string, orderID, matchOrderID OrderID, round uint64) []byte {
	buf := make([]byte, 0, 128)
	buf = appendSigningField(buf, domain)
	buf = appendSigningField(buf, string(orderID))
	buf = appendSigningField(buf, string(matchOrderID))
	buf = appendSigningField(buf, strconv.FormatUint(round, 10))
	return buf
}

func SettleCheckpointSigningMessage(req *SubmitSettleCheckpointRequest) []byte {
	return checkpointMessage("invisibook-settle-checkpoint-v1", req.OrderID, req.MatchOrderID, req.MatchRound)
}

func AbortSettleRoundSigningMessage(req *AbortSettleRoundRequest) []byte {
	return checkpointMessage("invisibook-abort-settle-round-v1", req.OrderID, req.MatchOrderID, req.MatchRound)
}

func verifyOrderOwnerSignature(order *Order, message []byte, signature string) error {
	pubkey, err := hex.DecodeString(order.Pubkey)
	if err != nil || len(pubkey) != ed25519.PublicKeySize {
		return fmt.Errorf("order %s has invalid owner pubkey", order.ID)
	}
	sig, err := hex.DecodeString(signature)
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(pubkey, message, sig) {
		return fmt.Errorf("owner signature verification failed for order %s", order.ID)
	}
	return nil
}

func (ot *OrderBook) loadCheckpointPair(orderID, matchOrderID OrderID, round uint64) (*Order, *Order, *Order, *Order, error) {
	mine, err := ot.GetOrder(orderID)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("order %s not found: %w", orderID, err)
	}
	peer, err := ot.GetOrder(matchOrderID)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("order %s not found: %w", matchOrderID, err)
	}
	if mine.Status != Settling || peer.Status != Settling || mine.MatchOrder != peer.ID || peer.MatchOrder != mine.ID {
		return nil, nil, nil, nil, fmt.Errorf("orders are not the same Settling pair")
	}
	if mine.MatchRound != round || peer.MatchRound != round {
		return nil, nil, nil, nil, fmt.Errorf("stale match round %d", round)
	}
	a, b := makerTakerOrder(mine, peer)
	return mine, peer, a, b, nil
}

func (ot *OrderBook) preOpenStateCommitment(a, b *Order) (string, error) {
	cmp, _, err := ot.GetCompareResult(a.ID, b.ID)
	if err != nil {
		return "", fmt.Errorf("comparison result missing: %w", err)
	}
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
		"invisibook-pre-open-state-v1", string(a.ID), string(b.ID),
		strconv.FormatUint(a.MatchRound, 10), a.LockedCommitment, b.LockedCommitment,
		strconv.Itoa(int(a.Kind)), strconv.Itoa(int(b.Kind)), price(a), price(b),
		execution, strconv.Itoa(int(a.Type)), strconv.Itoa(cmp.Cmp),
		addrA.EncryptionPubkey, addrB.EncryptionPubkey,
	} {
		buf = appendSigningField(buf, field)
	}
	digest := sha256.Sum256(buf)
	return hex.EncodeToString(digest[:]), nil
}

func (ot *OrderBook) checkpointRow(a, b *Order) (*SettleCheckpointScheme, error) {
	var row SettleCheckpointScheme
	err := ot.db.First(&row, "order_a_id = ? AND match_round = ?", string(a.ID), a.MatchRound).Error
	return &row, err
}

func checkpointResponse(row *SettleCheckpointScheme, mineIsA bool) SettleCheckpointResponse {
	myHeight, peerHeight := row.BSubmittedHeight, row.ASubmittedHeight
	if mineIsA {
		myHeight, peerHeight = row.ASubmittedHeight, row.BSubmittedHeight
	}
	first := row.ASubmittedHeight
	if first == 0 || (row.BSubmittedHeight != 0 && row.BSubmittedHeight < first) {
		first = row.BSubmittedHeight
	}
	deadline := uint64(0)
	if first != 0 {
		deadline = first + settleCheckpointTimeoutBlocks
	}
	return SettleCheckpointResponse{
		StateCommitment: row.StateCommitment,
		MySubmitted:     myHeight != 0, PeerSubmitted: peerHeight != 0,
		Ready:          row.ASubmittedHeight != 0 && row.BSubmittedHeight != 0,
		DeadlineHeight: deadline, AbortedOrderID: row.AbortedOrderID,
	}
}

func (ot *OrderBook) SubmitSettleCheckpoint(ctx *context.WriteContext) error {
	ctx.SetLei(20)
	LogPayloadSize("SubmitSettleCheckpoint", ctx.GetRequestBytes())
	req := new(SubmitSettleCheckpointRequest)
	if err := ctx.BindJson(req); err != nil {
		return err
	}
	if err := Validator.Struct(req); err != nil {
		return err
	}
	mine, _, a, b, err := ot.loadCheckpointPair(req.OrderID, req.MatchOrderID, req.MatchRound)
	if err != nil {
		return err
	}
	if err := verifyOrderOwnerSignature(mine, SettleCheckpointSigningMessage(req), req.Signature); err != nil {
		return err
	}
	state, err := ot.preOpenStateCommitment(a, b)
	if err != nil {
		return err
	}
	height := uint64(ctx.Block.Height)
	err = ot.db.Transaction(func(tx *gorm.DB) error {
		var row SettleCheckpointScheme
		dbErr := tx.First(&row, "order_a_id = ? AND match_round = ?", string(a.ID), req.MatchRound).Error
		if dbErr == gorm.ErrRecordNotFound {
			row = SettleCheckpointScheme{OrderAID: string(a.ID), OrderBID: string(b.ID), MatchRound: req.MatchRound, StateCommitment: state}
		} else if dbErr != nil {
			return dbErr
		}
		if row.StateCommitment != state || row.OrderBID != string(b.ID) || row.AbortedOrderID != "" {
			return fmt.Errorf("checkpoint state mismatch or round already aborted")
		}
		if mine.ID == a.ID {
			if row.ASubmittedHeight == 0 {
				row.ASubmittedHeight = height
			}
		} else if row.BSubmittedHeight == 0 {
			row.BSubmittedHeight = height
		}
		return tx.Save(&row).Error
	})
	if err != nil {
		return fmt.Errorf("saving settle checkpoint: %w", err)
	}
	ctx.EmitStringEvent("pre-open checkpoint submitted for order %s round %d", req.OrderID, req.MatchRound)
	return nil
}

func (ot *OrderBook) QuerySettleCheckpoint(ctx *context.ReadContext) {
	req := new(QuerySettleCheckpointRequest)
	if err := ctx.BindJson(req); err != nil {
		ctx.Json(http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := Validator.Struct(req); err != nil {
		ctx.Json(http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	mine, _, a, b, err := ot.loadCheckpointPair(req.OrderID, req.MatchOrderID, req.MatchRound)
	if err != nil {
		ctx.Json(http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	row, err := ot.checkpointRow(a, b)
	if err == gorm.ErrRecordNotFound {
		state, stateErr := ot.preOpenStateCommitment(a, b)
		if stateErr != nil {
			ctx.Json(http.StatusBadRequest, map[string]string{"error": stateErr.Error()})
			return
		}
		ctx.JsonOk(SettleCheckpointResponse{StateCommitment: state})
		return
	}
	if err != nil {
		ctx.Json(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	ctx.JsonOk(checkpointResponse(row, mine.ID == a.ID))
}

func (ot *OrderBook) AbortSettleRound(ctx *context.WriteContext) error {
	ctx.SetLei(30)
	req := new(AbortSettleRoundRequest)
	if err := ctx.BindJson(req); err != nil {
		return err
	}
	if err := Validator.Struct(req); err != nil {
		return err
	}
	mine, peer, a, b, err := ot.loadCheckpointPair(req.OrderID, req.MatchOrderID, req.MatchRound)
	if err != nil {
		return err
	}
	if err := verifyOrderOwnerSignature(mine, AbortSettleRoundSigningMessage(req), req.Signature); err != nil {
		return err
	}
	row, err := ot.checkpointRow(a, b)
	if err != nil {
		return fmt.Errorf("checkpoint not found: %w", err)
	}
	mineHeight, peerHeight := row.BSubmittedHeight, row.ASubmittedHeight
	if mine.ID == a.ID {
		mineHeight, peerHeight = row.ASubmittedHeight, row.BSubmittedHeight
	}
	if mineHeight == 0 || peerHeight != 0 {
		return fmt.Errorf("abort requires caller checkpoint and missing peer checkpoint")
	}
	height := uint64(ctx.Block.Height)
	if height <= mineHeight+settleCheckpointTimeoutBlocks {
		return fmt.Errorf("checkpoint deadline has not elapsed")
	}
	err = ot.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&OrderScheme{}).Where("id = ?", string(mine.ID)).Updates(map[string]any{
			"status": int(Pending), "match_order": "", "execution_price": "",
		}).Error; err != nil {
			return err
		}
		if err := tx.Model(&OrderScheme{}).Where("id = ?", string(peer.ID)).Updates(map[string]any{
			"status": int(Frozen), "match_order": "", "execution_price": "",
		}).Error; err != nil {
			return err
		}
		row.AbortedOrderID = string(peer.ID)
		row.AbortedAtHeight = height
		if err := tx.Save(row).Error; err != nil {
			return err
		}
		if err := tx.Where("(order_a_id = ? AND order_b_id = ?) OR (order_a_id = ? AND order_b_id = ?)", string(a.ID), string(b.ID), string(b.ID), string(a.ID)).Delete(&CompareResultScheme{}).Error; err != nil {
			return err
		}
		if err := tx.Where("order_id IN ?", []string{string(a.ID), string(b.ID)}).Delete(&SettleAddrScheme{}).Error; err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("aborting settle round: %w", err)
	}
	mine.Status, mine.MatchOrder, mine.ExecutionPrice = Pending, "", nil
	peer.Status, peer.MatchOrder, peer.ExecutionPrice = Frozen, "", nil
	matched, matchErr := ot.matchOrder(mine)
	if matchErr != nil {
		return fmt.Errorf("rematching surviving order: %w", matchErr)
	}
	return ctx.EmitJsonEvent(map[string]any{"event_type": "settlement_aborted", "survivor": mine, "aborted": peer, "matched": matched})
}
