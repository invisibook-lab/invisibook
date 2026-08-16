package core

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"

	"github.com/yu-org/yu/core/context"
)

// Settlement per the paper (§V-C/VI, plan rev. 3 Phase 3):
//
//  1. SubmitCompareCoZk / SubmitCompareCoZk2p — the ONLY collaborative
//     step. Both traders jointly proved `cmp = sign(q_A − q_B)` against
//     their on-chain order commitments (π_cmp) and both signed the result;
//     the chain records cmp and moves the pair to Settling.
//  2. SettleSmall — the fully filled side's own update (paper π_A): its
//     whole collateral becomes a pool note paid to the counterparty.
//  3. SettleLarge — the partially filled side's own update (paper π_B):
//     pays the fill as a pool note, relists its residual under fresh
//     commitments.
//
// Steps 2 and 3 are ordinary single-prover Groth16 proofs — each party
// holds its complete witness after the comparison (the smaller side
// revealed its opening over the settlement channel).

// ────────────────────── Compare submission ──────────────────────

// CompareRequest is the dual-signed comparison result of the collaborative
// settlement's first phase. `Cmp` is sign(q_A − q_B); `ZkProof` is the
// jointly generated π_cmp (snarkjs Groth16 JSON for SubmitCompareCoZk,
// hex-encoded ark-compressed PLONK bytes for SubmitCompareCoZk2p). Order A
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
	return compareMessage("invisibook-cozk-compare-v2", req)
}

// CoZk2pCompareMessage is the signed message for SubmitCompareCoZk2p.
func CoZk2pCompareMessage(req *CompareRequest) []byte {
	return compareMessage("invisibook-cozk2p-compare-v2", req)
}

// makerTakerOrder orders a matched pair deterministically: the maker is the
// order with the lower block height; on a tie, the lexicographically smaller
// order ID. Both orders must be non-nil.
func makerTakerOrder(x, y *Order) (*Order, *Order) {
	if x.BlockHeight < y.BlockHeight {
		return x, y
	}
	if y.BlockHeight < x.BlockHeight {
		return y, x
	}
	if x.ID <= y.ID {
		return x, y
	}
	return y, x
}

// executionPrice returns the price a matched pair settles at: the maker's
// price (earlier block height); on the same height, the lower of the two
// (favorable to the buyer). Both orders must have a non-nil price.
func executionPrice(x, y *Order) uint64 {
	if x.BlockHeight < y.BlockHeight {
		return x.Price.Uint64()
	}
	if y.BlockHeight < x.BlockHeight {
		return y.Price.Uint64()
	}
	p, q := x.Price.Uint64(), y.Price.Uint64()
	if p < q {
		return p
	}
	return q
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

// buildCompareSignals lays out settle_cozk.circom's 3 public signals:
// [cmp, order_a_commitment, order_b_commitment].
func buildCompareSignals(req *CompareRequest, orderA, orderB *Order) ([]string, error) {
	cmpDec, err := cmpToFrDecimal(req.Cmp)
	if err != nil {
		return nil, err
	}
	orderADec, err := HexToDecimal(string(orderA.Amount))
	if err != nil {
		return nil, fmt.Errorf("invalid order A commitment: %w", err)
	}
	orderBDec, err := HexToDecimal(string(orderB.Amount))
	if err != nil {
		return nil, fmt.Errorf("invalid order B commitment: %w", err)
	}
	return []string{cmpDec, orderADec, orderBDec}, nil
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
// opposite sides, order A is the maker, prices are in range and equal.
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

	// Defense in depth against silent truncation in executionPrice: SendOrder
	// rejects out-of-range prices at ingress, but rows written before that
	// check existed would still reach the circuits as a different number.
	for _, ord := range []*Order{orderA, orderB} {
		if err := validateOrderPrice(ord.Price); err != nil {
			return nil, nil, 0, fmt.Errorf("order %s: %w", ord.ID, err)
		}
	}

	// Equal-price requirement: collateral was locked at the order's own
	// price, and the settle circuits equate it with the execution price
	// with strict equality (no price-improvement change output).
	if orderA.Price == nil || orderB.Price == nil || orderA.Price.Cmp(orderB.Price) != 0 {
		return nil, nil, 0, fmt.Errorf("co-zk settlement requires equal order prices")
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
// Groth16 π_cmp (settle_cozk circuit, 3 publics).
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
// entire collateral transfers to the counterparty as the pool note
// `CmNoteOut` (whose opening the counterparty chose and already persisted).
// Also used by BOTH sides when cmp == 0.
type SettleSmallRequest struct {
	OrderID      OrderID `json:"order_id"       validate:"required"`
	MatchOrderID OrderID `json:"match_order_id" validate:"required"`
	CmNoteOut    string  `json:"cm_note_out"    validate:"required,len=64"`
	// Owner's ed25519 signature over settleSmallSigMessage (the order's
	// pubkey authenticates its settlement update — paper §V-B).
	Signature string `json:"signature" validate:"required,len=128"`
	ZkProof   string `json:"zk_proof"  validate:"required"`
}

// SettleLargeRequest is the partially filled side's own update: pays the
// fill as `CmNoteOut` and relists its residual order under the fresh
// commitments `CmQResidual` / `CmLockedResidual`.
type SettleLargeRequest struct {
	OrderID          OrderID `json:"order_id"           validate:"required"`
	MatchOrderID     OrderID `json:"match_order_id"     validate:"required"`
	CmQResidual      string  `json:"cm_q_residual"      validate:"required,len=64"`
	CmLockedResidual string  `json:"cm_locked_residual" validate:"required,len=64"`
	CmNoteOut        string  `json:"cm_note_out"        validate:"required,len=64"`
	Signature        string  `json:"signature"          validate:"required,len=128"`
	ZkProof          string  `json:"zk_proof"           validate:"required"`
}

// SettleEvent is emitted after a settle submission lands. `NoteLeafIndex`
// tells the counterparty where its payout note sits (no probing needed).
type SettleEvent struct {
	EventType     string  `json:"event_type"` // "settle_small" | "settle_large"
	Order         OrderID `json:"order"`
	NoteLeafIndex uint64  `json:"note_leaf_index"`
	Relisted      *Order  `json:"relisted,omitempty"`
	Matched       *Order  `json:"matched,omitempty"`
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
	return settleSigMessage("invisibook-settle-small-v1",
		string(req.OrderID), string(req.MatchOrderID), req.CmNoteOut)
}

// SettleLargeSigMessage is the owner-signed message for SettleLarge.
func SettleLargeSigMessage(req *SettleLargeRequest) []byte {
	return settleSigMessage("invisibook-settle-large-v1",
		string(req.OrderID), string(req.MatchOrderID),
		req.CmQResidual, req.CmLockedResidual, req.CmNoteOut)
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
		[]byte(req.CmQResidual),
		[]byte(req.CmLockedResidual),
		[]byte(req.CmNoteOut),
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
// circuits: my order commitment, my two locked collateral commitments,
// price, side, all as decimal strings.
func (ot *OrderBook) settlePublicPrefix(mine, match *Order) (cmQ string, locked []string, price uint64, side string, err error) {
	cmQ, err = HexToDecimal(string(mine.Amount))
	if err != nil {
		return "", nil, 0, "", fmt.Errorf("invalid order commitment: %w", err)
	}
	locked, err = lockedSlotsDec(mine)
	if err != nil {
		return "", nil, 0, "", fmt.Errorf("locked commitment: %w", err)
	}
	price = executionPrice(mine, match)
	side = "0"
	if mine.Type == Sell {
		side = "1"
	}
	return cmQ, locked, price, side, nil
}

// verifySmallLeg checks the fully filled side's owner signature and π_A
// against `mine`'s on-chain row (opening cm_q, transferring the whole
// collateral). Pure verification — no state change; returns the payout note
// commitment to mint to the counterparty. Shared by SettleSmall and
// SettlePair. `mine` and `match` must be a matched Settling pair.
func (ot *OrderBook) verifySmallLeg(mine, match *Order, cmNoteOut, sig, proof string) (*big.Int, error) {
	req := &SettleSmallRequest{
		OrderID:      mine.ID,
		MatchOrderID: match.ID,
		CmNoteOut:    cmNoteOut,
		Signature:    sig,
		ZkProof:      proof,
	}
	if err := verifyCoZkSignature(mine.Pubkey, sig, SettleSmallSigMessage(req)); err != nil {
		return nil, fmt.Errorf("owner signature: %w", err)
	}
	// Publics: [cm_q, locked_0, locked_1, price, side, pay_asset,
	// cm_note_out, bind].
	cmQ, locked, price, side, err := ot.settlePublicPrefix(mine, match)
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
	bind := settleSmallBind(ot.chainID, req)
	signals := []string{cmQ, locked[0], locked[1], fmt.Sprintf("%d", price), side,
		payAsset.String(), noteDec, bind.String()}
	if err := VerifyGroth16(ot.settleSmallVK, proof, signals); err != nil {
		return nil, fmt.Errorf("settle_small proof verification failed: %w", err)
	}
	return ParseFrHex(cmNoteOut)
}

// verifyLargeLeg checks the partially filled side's owner signature and π_B
// against `mine`'s row and the counterparty's on-chain commitment (opening
// both quantities, so the fill cannot be understated). Pure verification —
// no state change; returns the fill note commitment to mint to the
// counterparty. Shared by SettleLarge and SettlePair.
func (ot *OrderBook) verifyLargeLeg(
	mine, match *Order, cmQResidual, cmLockedResidual, cmNoteOut, sig, proof string,
) (*big.Int, error) {
	req := &SettleLargeRequest{
		OrderID:          mine.ID,
		MatchOrderID:     match.ID,
		CmQResidual:      cmQResidual,
		CmLockedResidual: cmLockedResidual,
		CmNoteOut:        cmNoteOut,
		Signature:        sig,
		ZkProof:          proof,
	}
	if err := verifyCoZkSignature(mine.Pubkey, sig, SettleLargeSigMessage(req)); err != nil {
		return nil, fmt.Errorf("owner signature: %w", err)
	}
	// Publics: [cm_q, cm_q_ctr, locked_0, locked_1, price, side,
	// cm_q_residual, cm_locked_residual, pay_asset, cm_note_out, bind].
	cmQ, locked, price, side, err := ot.settlePublicPrefix(mine, match)
	if err != nil {
		return nil, err
	}
	cmQCtr, err := HexToDecimal(string(match.Amount))
	if err != nil {
		return nil, fmt.Errorf("invalid counterparty order commitment: %w", err)
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
	resQDec, err := toDec(cmQResidual, "cm_q_residual")
	if err != nil {
		return nil, err
	}
	resLockedDec, err := toDec(cmLockedResidual, "cm_locked_residual")
	if err != nil {
		return nil, err
	}
	noteDec, err := toDec(cmNoteOut, "cm_note_out")
	if err != nil {
		return nil, err
	}
	bind := settleLargeBind(ot.chainID, req)
	signals := []string{cmQ, cmQCtr, locked[0], locked[1], fmt.Sprintf("%d", price), side,
		resQDec, resLockedDec, payAsset.String(), noteDec, bind.String()}
	if err := VerifyGroth16(ot.settleLargeVK, proof, signals); err != nil {
		return nil, fmt.Errorf("settle_large proof verification failed: %w", err)
	}
	return ParseFrHex(cmNoteOut)
}

// SettleSmall applies the fully filled side's settlement: verifies the
// owner's signature and π_A, spends the collateral, appends the payout note
// to the pool, and closes the order.
func (ot *OrderBook) SettleSmall(ctx *context.WriteContext) error {
	ctx.SetLei(100)

	req := new(SettleSmallRequest)
	if err := ctx.BindJson(req); err != nil {
		return err
	}
	if err := Validator.Struct(req); err != nil {
		return err
	}

	mine, match, cmp, err := ot.loadSettlingOrder(req.OrderID, req.MatchOrderID)
	if err != nil {
		return err
	}
	// SettleSmall is for the smaller side — or both sides on equality.
	if cmp > 0 {
		return fmt.Errorf("order %s is the larger side; submit SettleLarge", req.OrderID)
	}
	cmNote, err := ot.verifySmallLeg(mine, match, req.CmNoteOut, req.Signature, req.ZkProof)
	if err != nil {
		return err
	}

	// Mutate: the collateral commitment lives only on the order row (it
	// leaves the book when the order closes), so settlement mints the payout
	// note and closes the order — no cash to spend.
	settleBy := fmt.Sprintf("settle-small:%s", req.OrderID[:8])
	indices, err := ot.Account.ApplyPoolMutation(PoolMutation{
		NoteCms: []*big.Int{cmNote},
		Height:  uint64(ctx.Block.Height),
		Source:  "settle",
		By:      settleBy,
	})
	if err != nil {
		return fmt.Errorf("minting payout note: %w", err)
	}
	if err := ot.UpdateOrderStatus(mine.ID, Done); err != nil {
		return fmt.Errorf("closing order: %w", err)
	}
	_ = ot.DeleteSettleAddr(mine.ID)

	return ctx.EmitJsonEvent(&SettleEvent{
		EventType:     "settle_small",
		Order:         mine.ID,
		NoteLeafIndex: indices[0],
	})
}

// SettleLarge applies the partially filled side's settlement: verifies the
// owner's signature and π_B, spends the collateral, appends the fill note
// to the pool, and relists the residual order under fresh commitments
// (keeping its block height, i.e. its time priority).
func (ot *OrderBook) SettleLarge(ctx *context.WriteContext) error {
	ctx.SetLei(100)

	req := new(SettleLargeRequest)
	if err := ctx.BindJson(req); err != nil {
		return err
	}
	if err := Validator.Struct(req); err != nil {
		return err
	}

	mine, match, cmp, err := ot.loadSettlingOrder(req.OrderID, req.MatchOrderID)
	if err != nil {
		return err
	}
	if cmp <= 0 {
		return fmt.Errorf("order %s is not the larger side; submit SettleSmall", req.OrderID)
	}
	cmNote, err := ot.verifyLargeLeg(
		mine, match, req.CmQResidual, req.CmLockedResidual, req.CmNoteOut, req.Signature, req.ZkProof)
	if err != nil {
		return err
	}

	// Mutate: mint the fill note, relist the residual (the collateral
	// commitment is order-bound, so relisting just swaps it — no cash).
	settleBy := fmt.Sprintf("settle-large:%s", req.OrderID[:8])
	indices, err := ot.Account.ApplyPoolMutation(PoolMutation{
		NoteCms: []*big.Int{cmNote},
		Height:  uint64(ctx.Block.Height),
		Source:  "settle",
		By:      settleBy,
	})
	if err != nil {
		return fmt.Errorf("minting fill note: %w", err)
	}
	relisted, rematched, err := ot.relistWithRemainder(
		mine, CipherText(req.CmQResidual), CipherText(req.CmLockedResidual), req.ZkProof)
	if err != nil {
		return err
	}
	_ = ot.DeleteSettleAddr(mine.ID)

	return ctx.EmitJsonEvent(&SettleEvent{
		EventType:     "settle_large",
		Order:         mine.ID,
		NoteLeafIndex: indices[0],
		Relisted:      relisted,
		Matched:       rematched,
	})
}

// relistWithRemainder keeps the surviving larger order on the book: swaps
// its quantity and collateral commitments to the residual, clears the match
// linkage, and returns it to Pending (retaining its original block height,
// i.e. its time priority). It then immediately attempts a re-match against
// the book. Returns the updated order and the counter order it re-matched
// with (nil if none).
func (ot *OrderBook) relistWithRemainder(
	ord *Order, newOrderCommitment, newLockedCommitment CipherText, zkProof string,
) (*Order, *Order, error) {
	if err := ot.UpdateOrderAmount(ord.ID, newOrderCommitment); err != nil {
		return nil, nil, fmt.Errorf("failed to update order amount: %w", err)
	}
	if err := ot.UpdateOrderLockedCommitment(ord.ID, string(newLockedCommitment)); err != nil {
		return nil, nil, fmt.Errorf("failed to update order collateral: %w", err)
	}
	if err := ot.UpdateOrderMatchOrder(ord.ID, ""); err != nil {
		return nil, nil, fmt.Errorf("failed to clear match order: %w", err)
	}
	if err := ot.UpdateOrderStatus(ord.ID, Pending); err != nil {
		return nil, nil, fmt.Errorf("failed to relist order: %w", err)
	}

	updated, err := ot.GetOrder(ord.ID)
	if err != nil {
		return nil, nil, fmt.Errorf("re-reading relisted order: %w", err)
	}
	rematched, err := ot.matchOrder(updated)
	if err != nil {
		return nil, nil, fmt.Errorf("re-matching relisted order: %w", err)
	}
	return updated, rematched, nil
}

// ────────────────────── Writing: SettlePair (atomic) ──────────────────────

// SettlePairLeg carries one side's settle artifacts inside a SettlePair.
// The residual fields are set ONLY for the larger side (π_B); a fully filled
// side (π_A, and both sides when cmp == 0) leaves them empty. Each leg keeps
// its own owner signature, so SettlePair needs no new signed message — it
// reuses SettleSmall/SettleLarge's per-leg messages.
type SettlePairLeg struct {
	CmNoteOut        string `json:"cm_note_out" validate:"required,len=64"`
	Signature        string `json:"signature"   validate:"required,len=128"`
	ZkProof          string `json:"zk_proof"    validate:"required"`
	CmQResidual      string `json:"cm_q_residual,omitempty"`
	CmLockedResidual string `json:"cm_locked_residual,omitempty"`
}

// SettlePairRequest settles BOTH sides of a matched pair in one atomic
// writing: both proofs are verified and both payout notes are minted in a
// single pool mutation, so neither side can be paid without the other (the
// fair-exchange guarantee the two independent SettleSmall/SettleLarge
// writings lack). A and B are the canonical maker/taker order ids; the
// recorded cmp decides which leg is the larger one.
type SettlePairRequest struct {
	OrderAID OrderID       `json:"order_a_id" validate:"required"`
	OrderBID OrderID       `json:"order_b_id" validate:"required"`
	A        SettlePairLeg `json:"a"`
	B        SettlePairLeg `json:"b"`
}

// SettlePairEvent reports where each side's incoming payout note landed:
// A's incoming note is the one B minted, and vice versa.
type SettlePairEvent struct {
	EventType  string  `json:"event_type"` // "settle_pair"
	OrderA     OrderID `json:"order_a"`
	OrderB     OrderID `json:"order_b"`
	ALeafIndex uint64  `json:"a_leaf_index"` // A's incoming note (B minted it)
	BLeafIndex uint64  `json:"b_leaf_index"` // B's incoming note (A minted it)
	RelistedA  *Order  `json:"relisted_a,omitempty"`
	RelistedB  *Order  `json:"relisted_b,omitempty"`
	RematchedA *Order  `json:"rematched_a,omitempty"`
	RematchedB *Order  `json:"rematched_b,omitempty"`
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
// returns the payout note commitment to mint. `isLarge` selects π_B (residual
// fields required) vs π_A (residual fields must be empty).
func (ot *OrderBook) verifyPairLeg(mine, match *Order, isLarge bool, leg SettlePairLeg) (*big.Int, error) {
	if isLarge {
		if len(leg.CmQResidual) != 64 || len(leg.CmLockedResidual) != 64 {
			return nil, fmt.Errorf("larger leg %s needs both residual commitments", mine.ID)
		}
		return ot.verifyLargeLeg(
			mine, match, leg.CmQResidual, leg.CmLockedResidual, leg.CmNoteOut, leg.Signature, leg.ZkProof)
	}
	// A fully filled leg transfers its whole collateral — no residual.
	if leg.CmQResidual != "" || leg.CmLockedResidual != "" {
		return nil, fmt.Errorf("fully filled leg %s must not carry residual commitments", mine.ID)
	}
	return ot.verifySmallLeg(mine, match, leg.CmNoteOut, leg.Signature, leg.ZkProof)
}

// SettlePair verifies both sides' settle proofs and applies both settlements
// atomically: both payout notes are minted in ONE pool mutation, then the
// fully filled side(s) close and the larger side (if any) relists its
// residual. Either the whole pair settles or nothing does — closing the
// "one leg lands, the other does not" fair-exchange gap of the separate
// SettleSmall/SettleLarge writings.
func (ot *OrderBook) SettlePair(ctx *context.WriteContext) error {
	ctx.SetLei(100)

	req := new(SettlePairRequest)
	if err := ctx.BindJson(req); err != nil {
		return err
	}
	if err := Validator.Struct(req); err != nil {
		return err
	}

	orderA, orderB, cmpA, err := ot.loadSettlingPair(req.OrderAID, req.OrderBID)
	if err != nil {
		return err
	}

	// cmpA > 0: A larger, B smaller. cmpA < 0: A smaller, B larger.
	// cmpA == 0: both fully filled (both π_A, no residual).
	aIsLarge := cmpA > 0
	bIsLarge := cmpA < 0

	// Verify BOTH legs before touching any state (all-or-nothing).
	cmNoteA, err := ot.verifyPairLeg(orderA, orderB, aIsLarge, req.A)
	if err != nil {
		return fmt.Errorf("side A: %w", err)
	}
	cmNoteB, err := ot.verifyPairLeg(orderB, orderA, bIsLarge, req.B)
	if err != nil {
		return fmt.Errorf("side B: %w", err)
	}

	// Mint BOTH payout notes in a single pool mutation — the atomicity that
	// makes settlement fair (both paid or neither). cmNoteA is what A mints
	// to B (B's incoming note); cmNoteB is what B mints to A.
	indices, err := ot.Account.ApplyPoolMutation(PoolMutation{
		NoteCms: []*big.Int{cmNoteA, cmNoteB},
		Height:  uint64(ctx.Block.Height),
		Source:  "settle",
		By:      fmt.Sprintf("settle-pair:%s", req.OrderAID[:8]),
	})
	if err != nil {
		return fmt.Errorf("minting payout notes: %w", err)
	}

	evt := &SettlePairEvent{
		EventType:  "settle_pair",
		OrderA:     orderA.ID,
		OrderB:     orderB.ID,
		ALeafIndex: indices[1], // A's incoming note = the one B minted
		BLeafIndex: indices[0], // B's incoming note = the one A minted
	}

	// Order transitions: relist the larger side, close each fully filled one.
	applyLeg := func(mine, match *Order, isLarge bool, leg SettlePairLeg) (*Order, *Order, error) {
		if isLarge {
			relisted, rematched, err := ot.relistWithRemainder(
				mine, CipherText(leg.CmQResidual), CipherText(leg.CmLockedResidual), leg.ZkProof)
			if err != nil {
				return nil, nil, err
			}
			_ = ot.DeleteSettleAddr(mine.ID)
			return relisted, rematched, nil
		}
		if err := ot.UpdateOrderStatus(mine.ID, Done); err != nil {
			return nil, nil, fmt.Errorf("closing order %s: %w", mine.ID, err)
		}
		_ = ot.DeleteSettleAddr(mine.ID)
		return nil, nil, nil
	}

	if evt.RelistedA, evt.RematchedA, err = applyLeg(orderA, orderB, aIsLarge, req.A); err != nil {
		return err
	}
	if evt.RelistedB, evt.RematchedB, err = applyLeg(orderB, orderA, bIsLarge, req.B); err != nil {
		return err
	}

	return ctx.EmitJsonEvent(evt)
}
