package core

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"strconv"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"gorm.io/gorm"

	"github.com/yu-org/yu/core/context"
	"github.com/yu-org/yu/core/types"
)

// Settlement per the paper (§V-C/VI, plan rev. 3 Phase 3):
//
//  1. SubmitCompareCoZk / SubmitCompareCoZk2pShare records the verified
//     comparison and moves the pair to Settling. The 2-party path requires
//     one identity-bound proof share from each owner and opens the absolute
//     settlement-leg deadline immediately.
//  2. Each owner calls SubmitSettleLeg with its own π_A (fully filled) or
//     π_B (larger/residual) proof. Each valid leg is buffered within that
//     pre-existing window; the second invokes the internal atomic pair
//     executor below.
//
// Steps 2 and 3 are ordinary single-prover Groth16 proofs — each party
// holds its complete witness after payout keys are exchanged and persisted,
// then the smaller side reveals over the settlement channel. No peer/MPC
// dependency remains after that reveal. The current payout-key exchange is a
// compliant-client WAL invariant, not cryptographic recipient authorization:
// the private payout opening is not yet bound to an owner-signed on-chain
// pre-reveal commitment.

// ────────────────────── Compare submission ──────────────────────

// CompareRequest is the dual-signed comparison result of the collaborative
// settlement's first phase. `Cmp` is sign(q_A − q_B); `ZkProof` is the
// jointly generated π_cmp (snarkjs Groth16 JSON for SubmitCompareCoZk,
// hex-encoded ark-compressed PLONK bytes in the local 2-party session). Order A
// must be the maker (see makerTakerOrder).
type CompareRequest struct {
	OrderAID OrderID `json:"order_a_id" validate:"required"`
	OrderBID OrderID `json:"order_b_id" validate:"required"`
	Cmp      int     `json:"cmp"        validate:"oneof=-1 0 1"`

	// ed25519 signatures (128-char hex) over the compare message, by each
	// order's pubkey. Dual signing is what makes the public result
	// unforgeable by either party alone (paper Property 1(ii)).
	SigA string `json:"sig_a" validate:"required,len=128"`
	SigB string `json:"sig_b" validate:"required,len=128"`

	ZkProof string `json:"zk_proof" validate:"required"`
}

// CompareEvent is emitted when a comparison lands on chain.
type CompareEvent struct {
	EventType string  `json:"event_type"` // "compared"
	Cmp       int     `json:"cmp"`
	OrderA    OrderID `json:"order_a"`
	OrderB    OrderID `json:"order_b"`
}

// compareMessage builds the canonical byte string both traders ed25519-sign
// for a comparison result, domain-separated per proof variant.
func compareMessage(prefix string, req *CompareRequest) []byte {
	msg := prefix + ":" + string(req.OrderAID) + ":" + string(req.OrderBID) +
		":" + strconv.Itoa(req.Cmp)
	return []byte(msg)
}

// CoZkCompareMessage is the signed message for SubmitCompareCoZk. Must stay
// in lockstep with the Rust client.
func CoZkCompareMessage(req *CompareRequest) []byte {
	return compareMessage("invisibook-cozk-compare-v3", req)
}

// CoZk2pCompareMessage is the local session's domain-separated agreement
// message. Chain-facing participation is separately signed per proof share.
func CoZk2pCompareMessage(req *CompareRequest) []byte {
	return compareMessage("invisibook-cozk2p-compare-v3", req)
}

// makerTakerOrder orders a matched pair deterministically by transaction
// time: block height, intra-block index, then order id.
func makerTakerOrder(x, y *Order) (*Order, *Order) {
	if x.BlockHeight < y.BlockHeight {
		return x, y
	}
	if y.BlockHeight < x.BlockHeight {
		return y, x
	}
	if x.IntraBlockIndex < y.IntraBlockIndex {
		return x, y
	}
	if y.IntraBlockIndex < x.IntraBlockIndex {
		return y, x
	}
	if x.ID <= y.ID {
		return x, y
	}
	return y, x
}

// executionPrice returns the immutable execution price persisted when the
// pair matched. The fallback is retained for legacy equal-price rows.
func executionPrice(x, y *Order) uint64 {
	if x.ExecutionPrice != nil && y.ExecutionPrice != nil && x.ExecutionPrice.Cmp(y.ExecutionPrice) == 0 {
		return x.ExecutionPrice.Uint64()
	}
	maker, taker := makerTakerOrder(x, y)
	if maker.Price != nil {
		return maker.Price.Uint64()
	}
	if taker.Price != nil {
		return taker.Price.Uint64()
	}
	return 0
}

// cmpToFrDecimal encodes the three-way comparison result as the decimal
// BN254 field element the circuit outputs (-1 becomes p-1). `cmp` must be
// -1, 0, or 1.
func cmpToFrDecimal(cmp int) (string, error) {
	var e fr.Element
	switch cmp {
	case -1:
		e.SetInt64(-1)
	case 0:
		e.SetZero()
	case 1:
		e.SetOne()
	default:
		return "", fmt.Errorf("cmp must be -1, 0, or 1, got %d", cmp)
	}
	return e.String(), nil
}

// lockToken returns the token an order locks as collateral: Token1 for a
// sell, Token2 for a buy.
func lockToken(ord *Order) TokenID {
	if ord.Type == Buy {
		return ord.Subject.Token2
	}
	return ord.Subject.Token1
}

// recvToken returns the token an order's owner receives at settlement — the
// opposite side of its locked token.
func recvToken(ord *Order) TokenID {
	if ord.Type == Buy {
		return ord.Subject.Token1
	}
	return ord.Subject.Token2
}

// sideSignal renders a trade side as the circuits' `side` public signal:
// "1" for a sell, "0" for a buy. Every circuit that takes a side flag
// (send_order, settle_small, settle_large, settle_cozk) uses this encoding.
func sideSignal(t TradeType) string {
	if t == Sell {
		return "1"
	}
	return "0"
}

// buildCompareSignals lays out settle_cozk.circom's 6 public signals:
// [cmp, locked_a, locked_b, collateral_price_a, collateral_price_b,
// a_is_seller]. Each public order price opens its own collateral; execution
// price is deliberately not part of the quantity comparison.
func buildCompareSignals(req *CompareRequest, orderA, orderB *Order) ([]string, error) {
	cmpDec, err := cmpToFrDecimal(req.Cmp)
	if err != nil {
		return nil, err
	}
	lockedADec, err := HexToDecimal(orderA.LockedCommitment)
	if err != nil {
		return nil, fmt.Errorf("invalid order A collateral commitment: %w", err)
	}
	lockedBDec, err := HexToDecimal(orderB.LockedCommitment)
	if err != nil {
		return nil, fmt.Errorf("invalid order B collateral commitment: %w", err)
	}
	priceA, priceB := collateralPrice(orderA), collateralPrice(orderB)
	return []string{cmpDec, lockedADec, lockedBDec, priceA.String(), priceB.String(),
		sideSignal(orderA.Type)}, nil
}

// verifyCoZkSignature checks an ed25519 signature (128-char hex) by the
// 64-char hex pubkey over msg.
func verifyCoZkSignature(pubkeyHex, sigHex string, msg []byte) error {
	pubkey, err := hex.DecodeString(pubkeyHex)
	if err != nil || len(pubkey) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid pubkey %q", pubkeyHex)
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature encoding")
	}
	if !ed25519.Verify(pubkey, msg, sig) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

// verifyComparePairSignatures checks both traders' signatures over the
// canonical compare message, each by its own order's pubkey.
func verifyComparePairSignatures(req *CompareRequest, orderA, orderB *Order, msg []byte) error {
	if err := verifyCoZkSignature(orderA.Pubkey, req.SigA, msg); err != nil {
		return fmt.Errorf("order A signature: %w", err)
	}
	if err := verifyCoZkSignature(orderB.Pubkey, req.SigB, msg); err != nil {
		return fmt.Errorf("order B signature: %w", err)
	}
	return nil
}

// loadMatchedPair loads the pair (A, B) and enforces every precondition of
// the compare phase: both orders exist, are Matched with each other on
// opposite sides, order A is the maker, and the persisted execution price is
// a valid crossing price.
// Returns the orders plus the execution price.
func (ot *OrderBook) loadMatchedPair(orderAID, orderBID OrderID) (*Order, *Order, uint64, error) {
	orderA, err := ot.GetOrder(orderAID)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("order %s not found: %w", orderAID, err)
	}
	orderB, err := ot.GetOrder(orderBID)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("order %s not found: %w", orderBID, err)
	}
	if orderA.Status != Matched {
		return nil, nil, 0, fmt.Errorf("order %s is not Matched (current: %s)", orderA.ID, orderA.Status.String())
	}
	if orderB.Status != Matched {
		return nil, nil, 0, fmt.Errorf("order %s is not Matched (current: %s)", orderB.ID, orderB.Status.String())
	}
	if orderA.MatchOrder != orderB.ID || orderB.MatchOrder != orderA.ID {
		return nil, nil, 0, fmt.Errorf("orders %s and %s are not matched with each other", orderA.ID, orderB.ID)
	}
	if orderA.Type == orderB.Type {
		return nil, nil, 0, fmt.Errorf("matched orders must be on opposite sides")
	}

	// Role assignment is deterministic: order A must be the maker, so the
	// circuit's a-side always corresponds to the same trader for everyone.
	if maker, _ := makerTakerOrder(orderA, orderB); maker.ID != orderA.ID {
		return nil, nil, 0, fmt.Errorf("order_a %s must be the maker of the pair", orderAID)
	}

	// Defense in depth against malformed legacy rows and silent truncation.
	for _, ord := range []*Order{orderA, orderB} {
		if err := validateOrderTerms(ord.Kind, ord.Price, ord.ProtectionPrice); err != nil {
			return nil, nil, 0, fmt.Errorf("order %s: %w", ord.ID, err)
		}
	}
	if !ordersCross(orderA, orderB) {
		return nil, nil, 0, fmt.Errorf("matched orders do not cross")
	}
	if orderA.ExecutionPrice == nil || orderB.ExecutionPrice == nil ||
		orderA.ExecutionPrice.Cmp(orderB.ExecutionPrice) != 0 ||
		!orderA.ExecutionPrice.IsUint64() || orderA.ExecutionPrice.Sign() <= 0 {
		return nil, nil, 0, fmt.Errorf("matched pair has no valid common execution price")
	}

	return orderA, orderB, executionPrice(orderA, orderB), nil
}

// applyCompareResult records cmp for the pair and moves both orders to
// Settling. Runs only after signatures and π_cmp verified.
func (ot *OrderBook) applyCompareResult(ctx *context.WriteContext, req *CompareRequest) error {
	if err := ot.SaveCompareResult(&CompareResultScheme{
		OrderAID: string(req.OrderAID),
		OrderBID: string(req.OrderBID),
		Cmp:      req.Cmp,
		Height:   uint64(ctx.Block.Height),
	}); err != nil {
		return fmt.Errorf("saving compare result: %w", err)
	}
	if err := ot.UpdateOrderStatus(req.OrderAID, Settling); err != nil {
		return fmt.Errorf("updating order %s: %w", req.OrderAID, err)
	}
	if err := ot.UpdateOrderStatus(req.OrderBID, Settling); err != nil {
		return fmt.Errorf("updating order %s: %w", req.OrderBID, err)
	}
	return ctx.EmitJsonEvent(&CompareEvent{
		EventType: "compared",
		Cmp:       req.Cmp,
		OrderA:    req.OrderAID,
		OrderB:    req.OrderBID,
	})
}

// SubmitCompareCoZk records a comparison proven with the jointly generated
// Groth16 π_cmp (settle_cozk circuit, 6 publics).
func (ot *OrderBook) SubmitCompareCoZk(ctx *context.WriteContext) error {
	ctx.SetLei(100)

	req := new(CompareRequest)
	if err := ctx.BindJson(req); err != nil {
		return err
	}
	if err := Validator.Struct(req); err != nil {
		return err
	}

	orderA, orderB, _, err := ot.loadMatchedPair(req.OrderAID, req.OrderBID)
	if err != nil {
		return err
	}
	if err := verifyComparePairSignatures(req, orderA, orderB, CoZkCompareMessage(req)); err != nil {
		return err
	}
	signals, err := buildCompareSignals(req, orderA, orderB)
	if err != nil {
		return err
	}
	if err := VerifyGroth16(ot.settleCoZkVK, req.ZkProof, signals); err != nil {
		return fmt.Errorf("compare proof verification failed: %w", err)
	}
	return ot.applyCompareResult(ctx, req)
}

// ────────────────────── Settle submissions (π_A / π_B) ──────────────────────

// SettleSmallRequest is the fully filled side's own settlement update: its
// collateral is split between the counterparty's pool note `CmNoteOut`
// (whose opening the counterparty chose and already persisted) and the
// owner's price-improvement `CmRefundOut`.
// Also used by BOTH sides when cmp == 0.
type SettleSmallRequest struct {
	OrderID      OrderID `json:"order_id"       validate:"required"`
	MatchOrderID OrderID `json:"match_order_id" validate:"required"`
	CmNoteOut    string  `json:"cm_note_out"    validate:"required,len=64"`
	CmRefundOut  string  `json:"cm_refund_out"  validate:"required,len=64"`
	// Owner's ed25519 signature over settleSmallSigMessage (the order's
	// pubkey authenticates its settlement update — paper §V-B).
	Signature string `json:"signature" validate:"required,len=128"`
	ZkProof   string `json:"zk_proof"  validate:"required"`
}

// SettleLargeRequest is the partially filled side's own update: pays the fill
// as `CmNoteOut`, returns price improvement as `CmRefundOut`, and relists its
// residual collateral under the fresh commitment `CmLockedResidual`
// (locked-only model: no quantity residual).
type SettleLargeRequest struct {
	OrderID          OrderID `json:"order_id"           validate:"required"`
	MatchOrderID     OrderID `json:"match_order_id"     validate:"required"`
	CmLockedResidual string  `json:"cm_locked_residual" validate:"required,len=64"`
	CmNoteOut        string  `json:"cm_note_out"        validate:"required,len=64"`
	CmRefundOut      string  `json:"cm_refund_out"      validate:"required,len=64"`
	Signature        string  `json:"signature"          validate:"required,len=128"`
	ZkProof          string  `json:"zk_proof"           validate:"required"`
}

// settleSigMessage builds the canonical length-prefixed message an order's
// owner signs for its settle submission.
func settleSigMessage(domain string, fields ...string) []byte {
	msg := make([]byte, 0, 256)
	put := func(f []byte) {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(f)))
		msg = append(msg, l[:]...)
		msg = append(msg, f...)
	}
	put([]byte(domain))
	for _, f := range fields {
		put([]byte(f))
	}
	return msg
}

// SettleSmallSigMessage is the owner-signed message for SettleSmall.
// Lockstep with the Rust client.
func SettleSmallSigMessage(req *SettleSmallRequest) []byte {
	return settleSigMessage("invisibook-settle-small-v2",
		string(req.OrderID), string(req.MatchOrderID), req.CmNoteOut, req.CmRefundOut)
}

// SettleLargeSigMessage is the owner-signed message for SettleLarge.
func SettleLargeSigMessage(req *SettleLargeRequest) []byte {
	return settleSigMessage("invisibook-settle-large-v2",
		string(req.OrderID), string(req.MatchOrderID),
		req.CmLockedResidual, req.CmNoteOut, req.CmRefundOut)
}

// settleSmallBind computes the bind public input welding π_A to this exact
// request (Rust twin: note::settle_small_bind).
func settleSmallBind(chainID uint64, req *SettleSmallRequest) *big.Int {
	return BindHash(
		[]byte(bindDomain),
		u64be(chainID),
		[]byte("settle_small"),
		u32be(bindVersion),
		[]byte(req.OrderID),
		[]byte(req.MatchOrderID),
		[]byte(req.CmNoteOut),
		[]byte(req.CmRefundOut),
	)
}

// settleLargeBind computes the bind public input welding π_B to this exact
// request (Rust twin: note::settle_large_bind).
func settleLargeBind(chainID uint64, req *SettleLargeRequest) *big.Int {
	return BindHash(
		[]byte(bindDomain),
		u64be(chainID),
		[]byte("settle_large"),
		u32be(bindVersion),
		[]byte(req.OrderID),
		[]byte(req.MatchOrderID),
		[]byte(req.CmLockedResidual),
		[]byte(req.CmNoteOut),
		[]byte(req.CmRefundOut),
	)
}

// loadSettlingOrder loads `orderID` and its match for a settle submission:
// both must be Settling and mutually matched, and the pair must have a
// recorded comparison. Returns (mine, match, cmp normalized so that
// NEGATIVE means MINE is smaller).
func (ot *OrderBook) loadSettlingOrder(orderID, matchID OrderID) (*Order, *Order, int, error) {
	mine, err := ot.GetOrder(orderID)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("order %s not found: %w", orderID, err)
	}
	match, err := ot.GetOrder(matchID)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("order %s not found: %w", matchID, err)
	}
	if mine.Status != Settling {
		return nil, nil, 0, fmt.Errorf("order %s is not Settling (current: %s)", mine.ID, mine.Status.String())
	}
	if mine.MatchOrder != match.ID {
		return nil, nil, 0, fmt.Errorf("orders %s and %s are not matched with each other", mine.ID, match.ID)
	}

	if !ordersCross(mine, match) || mine.ExecutionPrice == nil || match.ExecutionPrice == nil ||
		mine.ExecutionPrice.Cmp(match.ExecutionPrice) != 0 {
		return nil, nil, 0, fmt.Errorf("pair has invalid crossing/execution-price state")
	}

	res, mineIsA, err := ot.GetCompareResult(orderID, matchID)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("no comparison recorded for pair %s/%s: %w", orderID, matchID, err)
	}
	cmp := res.Cmp
	if !mineIsA {
		cmp = -cmp
	}
	return mine, match, cmp, nil
}

// settlePublicPrefix builds the leading publics shared by both settle
// circuits: my single locked collateral commitment, price, side, all as
// decimal strings (locked-only model — no quantity commitment, no pad).
func (ot *OrderBook) settlePublicPrefix(mine, match *Order) (locked string, ownPrice, execPrice uint64, side string, err error) {
	locked, err = HexToDecimal(mine.LockedCommitment)
	if err != nil {
		return "", 0, 0, "", fmt.Errorf("invalid locked commitment: %w", err)
	}
	ownPrice = collateralPrice(mine).Uint64()
	execPrice = executionPrice(mine, match)
	return locked, ownPrice, execPrice, sideSignal(mine.Type), nil
}

// verifySmallLeg checks the fully filled side's owner signature and π_A
// against `mine`'s on-chain row (opening the locked collateral and
// transferring all of it). Pure verification — no state change; returns the
// payout note commitment to mint to the counterparty. Used by owner-leg
// verification and the internal atomic executor.
func (ot *OrderBook) verifySmallLeg(mine, match *Order, cmNoteOut, cmRefundOut, sig, proof string) ([]*big.Int, error) {
	req := &SettleSmallRequest{
		OrderID:      mine.ID,
		MatchOrderID: match.ID,
		CmNoteOut:    cmNoteOut,
		CmRefundOut:  cmRefundOut,
		Signature:    sig,
		ZkProof:      proof,
	}
	if err := verifyCoZkSignature(mine.Pubkey, sig, SettleSmallSigMessage(req)); err != nil {
		return nil, fmt.Errorf("owner signature: %w", err)
	}
	// Publics: [locked, price, side, pay_asset, cm_note_out, bind].
	locked, ownPrice, execPrice, side, err := ot.settlePublicPrefix(mine, match)
	if err != nil {
		return nil, err
	}
	payAsset, err := AssetID(lockToken(mine))
	if err != nil {
		return nil, err
	}
	noteDec, err := HexToDecimal(cmNoteOut)
	if err != nil {
		return nil, fmt.Errorf("invalid cm_note_out: %w", err)
	}
	refundDec, err := HexToDecimal(cmRefundOut)
	if err != nil {
		return nil, fmt.Errorf("invalid cm_refund_out: %w", err)
	}
	bind := settleSmallBind(ot.chainID, req)
	signals := []string{locked, fmt.Sprintf("%d", ownPrice), fmt.Sprintf("%d", execPrice), side,
		payAsset.String(), noteDec, refundDec, bind.String()}
	if err := VerifyGroth16(ot.settleSmallVK, proof, signals); err != nil {
		return nil, fmt.Errorf("settle_small proof verification failed: %w", err)
	}
	note, err := ParseFrHex(cmNoteOut)
	if err != nil {
		return nil, err
	}
	refund, err := ParseFrHex(cmRefundOut)
	if err != nil {
		return nil, err
	}
	return []*big.Int{note, refund}, nil
}

// verifyLargeLeg checks the partially filled side's owner signature and π_B
// against `mine`'s row and the counterparty's on-chain collateral
// commitment (opened in-circuit on the OPPOSITE side, so the fill cannot
// be understated). Pure verification — no state change; returns the fill
// note commitment to mint to the counterparty. Used by owner-leg
// verification and the internal atomic executor.
func (ot *OrderBook) verifyLargeLeg(
	mine, match *Order, cmLockedResidual, cmNoteOut, cmRefundOut, sig, proof string,
) ([]*big.Int, error) {
	req := &SettleLargeRequest{
		OrderID:          mine.ID,
		MatchOrderID:     match.ID,
		CmLockedResidual: cmLockedResidual,
		CmNoteOut:        cmNoteOut,
		CmRefundOut:      cmRefundOut,
		Signature:        sig,
		ZkProof:          proof,
	}
	if err := verifyCoZkSignature(mine.Pubkey, sig, SettleLargeSigMessage(req)); err != nil {
		return nil, fmt.Errorf("owner signature: %w", err)
	}
	// Publics: [locked, locked_ctr, price, side, cm_locked_residual,
	// pay_asset, cm_note_out, bind].
	locked, ownPrice, execPrice, side, err := ot.settlePublicPrefix(mine, match)
	if err != nil {
		return nil, err
	}
	lockedCtr, err := HexToDecimal(match.LockedCommitment)
	if err != nil {
		return nil, fmt.Errorf("invalid counterparty locked commitment: %w", err)
	}
	payAsset, err := AssetID(lockToken(mine))
	if err != nil {
		return nil, err
	}
	toDec := func(h, what string) (string, error) {
		d, err := HexToDecimal(h)
		if err != nil {
			return "", fmt.Errorf("invalid %s: %w", what, err)
		}
		return d, nil
	}
	resLockedDec, err := toDec(cmLockedResidual, "cm_locked_residual")
	if err != nil {
		return nil, err
	}
	noteDec, err := toDec(cmNoteOut, "cm_note_out")
	if err != nil {
		return nil, err
	}
	refundDec, err := toDec(cmRefundOut, "cm_refund_out")
	if err != nil {
		return nil, err
	}
	bind := settleLargeBind(ot.chainID, req)
	signals := []string{locked, lockedCtr, fmt.Sprintf("%d", ownPrice),
		collateralPrice(match).String(), fmt.Sprintf("%d", execPrice), side,
		resLockedDec, payAsset.String(), noteDec, refundDec, bind.String()}
	if err := VerifyGroth16(ot.settleLargeVK, proof, signals); err != nil {
		return nil, fmt.Errorf("settle_large proof verification failed: %w", err)
	}
	note, err := ParseFrHex(cmNoteOut)
	if err != nil {
		return nil, err
	}
	refund, err := ParseFrHex(cmRefundOut)
	if err != nil {
		return nil, err
	}
	return []*big.Int{note, refund}, nil
}

// ────────────────────── Writing: SettlePair (atomic) ──────────────────────

// SettlePairLeg carries one side's settle artifacts. It is submitted alone
// by its owner and later assembled internally with the peer leg.
// The residual field is set ONLY for the larger side (π_B); a fully filled
// side (π_A, and both sides when cmp == 0) leaves it empty. Each leg keeps
// its own inner owner signature.
type SettlePairLeg struct {
	CmNoteOut        string `json:"cm_note_out" validate:"required,len=64"`
	CmRefundOut      string `json:"cm_refund_out" validate:"required,len=64"`
	Signature        string `json:"signature"   validate:"required,len=128"`
	ZkProof          string `json:"zk_proof"    validate:"required"`
	CmLockedResidual string `json:"cm_locked_residual,omitempty"`
}

// SettlePairRequest is the internal assembled form consumed after both
// independently submitted legs exist. A and B are the canonical
// maker/taker order ids; recorded cmp decides which leg is larger.
type SettlePairRequest struct {
	OrderAID OrderID       `json:"order_a_id" validate:"required"`
	OrderBID OrderID       `json:"order_b_id" validate:"required"`
	A        SettlePairLeg `json:"a"`
	B        SettlePairLeg `json:"b"`
}

// SettlePairEvent reports where each side's incoming payout note landed:
// A's incoming note is the one B minted, and vice versa.
type SettlePairEvent struct {
	EventType        string  `json:"event_type"` // "settle_pair"
	OrderA           OrderID `json:"order_a"`
	OrderB           OrderID `json:"order_b"`
	ALeafIndex       uint64  `json:"a_leaf_index"` // A's incoming note (B minted it)
	BLeafIndex       uint64  `json:"b_leaf_index"` // B's incoming note (A minted it)
	ARefundLeafIndex uint64  `json:"a_refund_leaf_index"`
	BRefundLeafIndex uint64  `json:"b_refund_leaf_index"`
	RelistedA        *Order  `json:"relisted_a,omitempty"`
	RelistedB        *Order  `json:"relisted_b,omitempty"`
	RematchedA       *Order  `json:"rematched_a,omitempty"`
	RematchedB       *Order  `json:"rematched_b,omitempty"`
}

// loadSettlingPair loads a matched Settling pair (A canonical) and its
// recorded comparison, normalized so `cmpA > 0` means A is the larger side.
func (ot *OrderBook) loadSettlingPair(aID, bID OrderID) (*Order, *Order, int, error) {
	a, b, cmpA, err := ot.loadSettlingOrder(aID, bID)
	if err != nil {
		return nil, nil, 0, err
	}
	if b.Status != Settling {
		return nil, nil, 0, fmt.Errorf("order %s is not Settling (current: %s)", b.ID, b.Status.String())
	}
	if b.MatchOrder != a.ID {
		return nil, nil, 0, fmt.Errorf("orders %s and %s are not matched with each other", a.ID, b.ID)
	}
	return a, b, cmpA, nil
}

// verifyPairLeg verifies one leg with the right circuit for its role and
// returns the payout note commitment to mint. `isLarge` selects π_B (the
// residual collateral commitment required) vs π_A (it must be empty).
func (ot *OrderBook) verifyPairLeg(mine, match *Order, isLarge bool, leg SettlePairLeg) ([]*big.Int, error) {
	if isLarge {
		if len(leg.CmLockedResidual) != 64 {
			return nil, fmt.Errorf("larger leg %s needs the residual collateral commitment", mine.ID)
		}
		return ot.verifyLargeLeg(
			mine, match, leg.CmLockedResidual, leg.CmNoteOut, leg.CmRefundOut, leg.Signature, leg.ZkProof)
	}
	// A fully filled leg transfers its whole collateral — no residual.
	if leg.CmLockedResidual != "" {
		return nil, fmt.Errorf("fully filled leg %s must not carry a residual commitment", mine.ID)
	}
	return ot.verifySmallLeg(mine, match, leg.CmNoteOut, leg.CmRefundOut, leg.Signature, leg.ZkProof)
}

// settlePairFailpoint, when non-nil, runs between the payout mint and the
// order-side updates. TESTS ONLY: failure injection for the crash-
// consistency regression tests. Production code never sets it.
var settlePairFailpoint func() error

// settlementID keys one settlement of a matched pair. A pair settles at
// most once (the fully filled side ends Done and can never be Matched
// again), so `orderA:orderB` is unique per settlement.
func settlementID(a, b OrderID) string {
	return string(a) + ":" + string(b)
}

// executeSettlePair is the crash-consistent settlement pipeline. The
// independently submitted legs are already stored before this internal
// method runs. The orderbook and pool state live in DIFFERENT SQLite
// databases, so one shared transaction is impossible; instead the pipeline
// is journaled and idempotent, so a crash at ANY point is completed by a
// resubmission of the second leg or by startup recovery:
//
//  1. Verify both legs (pure checks, no state).
//  2. Write the settlement journal row (orders.db, PENDING) — the durable
//     intent, carrying everything the order-side updates need.
//  3. Mint both payout notes AT MOST ONCE (accounts.db: one transaction
//     appends the notes and records the settlement id; a retry finds the
//     id and skips the mint).
//  4. Apply the order-side updates and mark the journal DONE in ONE
//     orders.db transaction.
//  5. Post-commit: re-match relisted orders, drop rendezvous rows.
//
// Crash between 3 and 4: the orders stay Settling, so the pair is still
// submittable; the retry skips the mint (step 3 idempotency) and completes
// step 4. `recoverPendingSettlements` runs the same completion on boot.
func (ot *OrderBook) executeSettlePair(req *SettlePairRequest, height uint64) (*SettlePairEvent, error) {
	orderA, orderB, cmpA, err := ot.loadSettlingPair(req.OrderAID, req.OrderBID)
	if err != nil {
		return nil, err
	}

	// cmpA > 0: A larger, B smaller. cmpA < 0: A smaller, B larger.
	// cmpA == 0: both fully filled (both π_A, no residual).
	aIsLarge := cmpA > 0
	bIsLarge := cmpA < 0

	// Verify BOTH legs before touching any state (all-or-nothing).
	if _, err := ot.verifyPairLeg(orderA, orderB, aIsLarge, req.A); err != nil {
		return nil, fmt.Errorf("side A: %w", err)
	}
	if _, err := ot.verifyPairLeg(orderB, orderA, bIsLarge, req.B); err != nil {
		return nil, fmt.Errorf("side B: %w", err)
	}

	// Durable intent FIRST (orders.db): everything the order-side updates
	// need survives a crash between the two databases.
	id := settlementID(orderA.ID, orderB.ID)
	journal := &SettlementJournalScheme{
		SettlementID:   id,
		OrderAID:       string(orderA.ID),
		OrderBID:       string(orderB.ID),
		MatchRound:     orderA.MatchRound,
		CmNoteA:        req.A.CmNoteOut,
		CmNoteB:        req.B.CmNoteOut,
		CmRefundA:      req.A.CmRefundOut,
		CmRefundB:      req.B.CmRefundOut,
		ALarge:         aIsLarge,
		BLarge:         bIsLarge,
		CmLockedResidA: req.A.CmLockedResidual,
		CmLockedResidB: req.B.CmLockedResidual,
		State:          SettlementPending,
		Height:         height,
	}
	if err := ot.UpsertSettlementJournal(journal); err != nil {
		return nil, fmt.Errorf("writing settlement journal: %w", err)
	}

	// Mint BOTH payout notes AT MOST ONCE (accounts.db transaction).
	// cmNoteA is what A mints to B (B's incoming note) and vice versa.
	indices, already, err := ot.Account.MintSettlementNotes(
		id, req.A.CmNoteOut, req.B.CmNoteOut, req.A.CmRefundOut, req.B.CmRefundOut, height,
		fmt.Sprintf("settle-pair:%s", req.OrderAID[:8]))
	if err != nil {
		return nil, fmt.Errorf("minting payout notes: %w", err)
	}
	if already {
		log.Printf("[settle] %s: payout notes already minted, resuming order updates", id[:16])
	}

	// TESTS ONLY: injected crash between the two databases.
	if settlePairFailpoint != nil {
		if ferr := settlePairFailpoint(); ferr != nil {
			return nil, ferr
		}
	}

	// Order-side updates + journal DONE in ONE orders.db transaction.
	if err := ot.finishSettlementOrders(journal); err != nil {
		return nil, fmt.Errorf("applying order updates: %w", err)
	}

	evt := &SettlePairEvent{
		EventType:        "settle_pair",
		OrderA:           orderA.ID,
		OrderB:           orderB.ID,
		ALeafIndex:       indices[1], // A's incoming note = the one B minted
		BLeafIndex:       indices[0], // B's incoming note = the one A minted
		ARefundLeafIndex: indices[2],
		BRefundLeafIndex: indices[3],
	}
	ot.postSettlementCleanup(journal, evt)
	return evt, nil
}

// finishSettlementOrders applies both order-side transitions of a minted
// settlement and marks its journal DONE — in ONE orders.db transaction, so
// a crash never leaves one leg updated and the other not. Idempotent: it
// only acts on a PENDING journal.
func (ot *OrderBook) finishSettlementOrders(j *SettlementJournalScheme) error {
	return ot.db.Transaction(func(tx *gorm.DB) error {
		applyLeg := func(orderID string, isLarge bool, cmLockedRes string) error {
			if isLarge {
				// Relist in place with the residual collateral commitment
				// (fresh blinding), clearing the match link and keeping the
				// original block height (time priority).
				return tx.Model(&OrderScheme{}).Where("id = ?", orderID).
					Updates(map[string]any{
						"locked_commitment": cmLockedRes,
						"match_order":       "",
						"execution_price":   "",
						"status":            int(Pending),
					}).Error
			}
			return tx.Model(&OrderScheme{}).Where("id = ?", orderID).
				Updates(map[string]any{"status": int(Done), "match_order": "", "execution_price": ""}).Error
		}
		if err := applyLeg(j.OrderAID, j.ALarge, j.CmLockedResidA); err != nil {
			return fmt.Errorf("side A order update: %w", err)
		}
		if err := applyLeg(j.OrderBID, j.BLarge, j.CmLockedResidB); err != nil {
			return fmt.Errorf("side B order update: %w", err)
		}
		if j.MatchRound != 0 {
			// This marker commits atomically with the terminal/relisted order
			// states and journal DONE. A crash can no longer leave both stored
			// legs looking incomplete after their settlement already finished.
			if err := tx.Model(&SettleLegRoundScheme{}).
				Where("order_a_id = ? AND order_b_id = ? AND match_round = ? AND expired_at_height = 0 AND leg_a_json <> '' AND leg_b_json <> ''",
					j.OrderAID, j.OrderBID, j.MatchRound).
				Update("completed_height", j.Height).Error; err != nil {
				return fmt.Errorf("marking settlement-leg round complete: %w", err)
			}
		}
		return tx.Model(&SettlementJournalScheme{}).
			Where("settlement_id = ?", j.SettlementID).
			Updates(map[string]any{"state": SettlementDone, "match_round": j.MatchRound}).Error
	})
}

// postSettlementCleanup runs the non-critical steps after the settlement
// committed: re-match relisted orders (fills evt when non-nil) and drop the
// rendezvous rows. Failures here never undo the settlement.
func (ot *OrderBook) postSettlementCleanup(j *SettlementJournalScheme, evt *SettlePairEvent) {
	rematch := func(orderID string, isLarge bool) (*Order, *Order) {
		if !isLarge {
			return nil, nil
		}
		relisted, err := ot.GetOrder(OrderID(orderID))
		if err != nil {
			log.Printf("[settle] re-reading relisted order %s: %v", orderID, err)
			return nil, nil
		}
		rematched, err := ot.matchOrder(relisted, j.Height)
		if err != nil {
			log.Printf("[settle] re-matching relisted order %s: %v", orderID, err)
			return relisted, nil
		}
		return relisted, rematched
	}
	ra, ma := rematch(j.OrderAID, j.ALarge)
	rb, mb := rematch(j.OrderBID, j.BLarge)
	if evt != nil {
		evt.RelistedA, evt.RematchedA = ra, ma
		evt.RelistedB, evt.RematchedB = rb, mb
	}
	ot.deleteSettlementRendezvous(j)
}

func (ot *OrderBook) deleteSettlementRendezvous(j *SettlementJournalScheme) {
	_ = ot.DeleteSettleAddr(OrderID(j.OrderAID))
	_ = ot.DeleteSettleAddr(OrderID(j.OrderBID))
}

// recoverPendingSettlements completes settlements interrupted between the
// payout mint (accounts.db) and the order-side updates (orders.db): for
// every PENDING journal row whose notes are minted, it applies the order
// updates; a PENDING row whose notes never minted is dropped (nothing
// happened — the pair is still Settling and can be resubmitted).
func (ot *OrderBook) recoverPendingSettlements() {
	if ot.Account == nil {
		log.Printf("[settle] recovery skipped: account tripod not wired yet")
		return
	}
	rows, err := ot.PendingSettlementJournals()
	if err != nil {
		log.Printf("[settle] recovery scan failed: %v", err)
		return
	}
	for i := range rows {
		j := rows[i]
		seen, err := ot.Account.SettlementMinted(j.SettlementID)
		if err != nil {
			log.Printf("[settle] recovery: reading mint record of %s: %v", j.SettlementID, err)
			continue
		}
		if seen == nil {
			// The crash happened before the mint: nothing to complete.
			if err := ot.db.Delete(&SettlementJournalScheme{},
				"settlement_id = ?", j.SettlementID).Error; err != nil {
				log.Printf("[settle] recovery: dropping stale journal %s: %v", j.SettlementID, err)
			}
			continue
		}
		if j.MatchRound == 0 {
			// Legacy journals predate the explicit round column. Pending crash
			// recovery still has Settling order rows from which it can be inferred.
			if order, orderErr := ot.GetOrder(OrderID(j.OrderAID)); orderErr == nil {
				j.MatchRound = order.MatchRound
			}
		}
		if err := ot.finishSettlementOrders(&j); err != nil {
			log.Printf("[settle] recovery: completing %s: %v", j.SettlementID, err)
			continue
		}
		// Recovery may run long after j.Height. Re-matching with that historic
		// height would create a fresh pair whose MatchHeight+10 comparison
		// deadline is already elapsed. Keep each relisted survivor Pending and
		// let a later SendOrder match it at the then-current block height.
		ot.deleteSettlementRendezvous(&j)
		log.Printf("[settle] recovered settlement %s after crash", j.SettlementID)
	}
}

// InitChain runs on every boot (yu behavior): complete any settlement that
// crashed between the pool mint and the order-side updates.
func (ot *OrderBook) InitChain(block *types.Block) {
	ot.recoverPendingSettlements()
}
