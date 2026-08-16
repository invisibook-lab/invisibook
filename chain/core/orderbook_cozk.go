package core

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"strconv"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"

	"github.com/yu-org/yu/core/context"
)

// ────────────────────── Writing: SettleOrdersCoZk ──────────────────────

// CoZkSettleRequest is the single-submission settlement message of the co-zk
// protocol (docs/cozk_design.md). Both traders jointly generated `ZkProof`
// via MPC and both signed the canonical settlement message, so either party
// (or anyone relaying on their behalf) may submit it. The same request shape
// serves both collaborative variants: SettleOrdersCoZk (3-party, Groth16)
// and SettleOrdersCoZk2p (2-party, PLONK) — only the proof format and the
// signed message's domain prefix differ.
//
// Order A must be the maker (see makerTakerOrder). `Cmp` is the public
// three-way comparison sign(a - b) of the two hidden order amounts. The six
// commitments are the circuit's public outputs; the chain rebuilds the full
// public-input vector from them plus on-chain state.
type CoZkSettleRequest struct {
	OrderAID OrderID `json:"order_a_id" validate:"required"`
	OrderBID OrderID `json:"order_b_id" validate:"required"`
	Cmp      int     `json:"cmp"        validate:"oneof=-1 0 1"`

	NewOrderACommitment  string `json:"new_order_a_commitment"  validate:"required,len=64"`
	NewOrderBCommitment  string `json:"new_order_b_commitment"  validate:"required,len=64"`
	NewLockedACommitment string `json:"new_locked_a_commitment" validate:"required,len=64"`
	NewLockedBCommitment string `json:"new_locked_b_commitment" validate:"required,len=64"`
	RecvACommitment      string `json:"recv_a_commitment"       validate:"required,len=64"`
	RecvBCommitment      string `json:"recv_b_commitment"       validate:"required,len=64"`

	// ed25519 signatures (128-char hex) over CoZkSettleMessage, by each
	// order's pubkey.
	SigA string `json:"sig_a" validate:"required,len=128"`
	SigB string `json:"sig_b" validate:"required,len=128"`

	// The collaboratively produced proof: snarkjs-format Groth16 JSON for
	// SettleOrdersCoZk, hex-encoded ark-compressed PLONK bytes for
	// SettleOrdersCoZk2p.
	ZkProof string `json:"zk_proof" validate:"required"`
}

// CoZkSettleEvent is emitted after a successful co-zk settlement. `Relisted`
// carries the surviving larger order (already updated and back to Pending),
// and `Matched` its immediate re-match if one happened.
type CoZkSettleEvent struct {
	EventType string `json:"event_type"` // "cozk_settled" or "cozk2p_settled"
	Cmp       int    `json:"cmp"`
	OrderA    *Order `json:"order_a"`
	OrderB    *Order `json:"order_b"`
	Relisted  *Order `json:"relisted,omitempty"`
	Matched   *Order `json:"matched,omitempty"`
}

// coZkSettleMessage builds the canonical byte string both traders
// ed25519-sign, domain-separated by `prefix` so a signature for one settle
// variant can never authorize the other.
func coZkSettleMessage(prefix string, req *CoZkSettleRequest) []byte {
	msg := prefix + ":" + string(req.OrderAID) + ":" + string(req.OrderBID) +
		":" + strconv.Itoa(req.Cmp) +
		":" + req.NewOrderACommitment + ":" + req.NewOrderBCommitment +
		":" + req.NewLockedACommitment + ":" + req.NewLockedBCommitment +
		":" + req.RecvACommitment + ":" + req.RecvBCommitment
	return []byte(msg)
}

// CoZkSettleMessage builds the message signed for SettleOrdersCoZk. Must stay
// in lockstep with the Rust client (lib/chain settle_cozk_message).
func CoZkSettleMessage(req *CoZkSettleRequest) []byte {
	return coZkSettleMessage("invisibook-cozk-settle", req)
}

// CoZk2pSettleMessage builds the message signed for SettleOrdersCoZk2p (the
// 2-party PLONK path); the distinct prefix domain-separates the variants.
func CoZk2pSettleMessage(req *CoZkSettleRequest) []byte {
	return coZkSettleMessage("invisibook-cozk2p-settle", req)
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

// buildSettleCoZkPublicSignals lays out the 15 public signals of
// settle_cozk.circom in witness order (outputs first, then public inputs):
//
//	[cmp, new_order_a, new_order_b, new_locked_a, new_locked_b, recv_a,
//	 recv_b, order_a_commitment, order_b_commitment, price, a_is_seller,
//	 locked_a_hashes[2], locked_b_hashes[2]]
func buildSettleCoZkPublicSignals(
	req *CoZkSettleRequest, orderA, orderB *Order, price uint64, aIsSeller bool, acc *Account,
) ([]string, error) {
	cmpDec, err := cmpToFrDecimal(req.Cmp)
	if err != nil {
		return nil, err
	}
	hexFields := []struct {
		name string
		hex  string
	}{
		{"new_order_a_commitment", req.NewOrderACommitment},
		{"new_order_b_commitment", req.NewOrderBCommitment},
		{"new_locked_a_commitment", req.NewLockedACommitment},
		{"new_locked_b_commitment", req.NewLockedBCommitment},
		{"recv_a_commitment", req.RecvACommitment},
		{"recv_b_commitment", req.RecvBCommitment},
		{"order_a_commitment", string(orderA.Amount)},
		{"order_b_commitment", string(orderB.Amount)},
	}
	decs := make([]string, 0, len(hexFields))
	for _, f := range hexFields {
		dec, err := HexToDecimal(f.hex)
		if err != nil {
			return nil, fmt.Errorf("invalid %s: %w", f.name, err)
		}
		decs = append(decs, dec)
	}
	aIsSellerStr := "0"
	if aIsSeller {
		aIsSellerStr = "1"
	}
	lockedA, err := lockedInputHashesPadded(orderA, acc, 2, lockToken(orderA))
	if err != nil {
		return nil, fmt.Errorf("order A locked inputs: %w", err)
	}
	lockedB, err := lockedInputHashesPadded(orderB, acc, 2, lockToken(orderB))
	if err != nil {
		return nil, fmt.Errorf("order B locked inputs: %w", err)
	}

	signals := []string{cmpDec}
	signals = append(signals, decs[:6]...)                            // new/recv commitments
	signals = append(signals, decs[6], decs[7])                       // order commitments
	signals = append(signals, fmt.Sprintf("%d", price), aIsSellerStr) // price, a_is_seller
	signals = append(signals, lockedA...)
	signals = append(signals, lockedB...)
	return signals, nil
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

// verifyCoZkPairSignatures checks both traders' ed25519 signatures over the
// canonical settlement message, each by its own order's pubkey.
func verifyCoZkPairSignatures(req *CoZkSettleRequest, orderA, orderB *Order, msg []byte) error {
	if err := verifyCoZkSignature(orderA.Pubkey, req.SigA, msg); err != nil {
		return fmt.Errorf("order A signature: %w", err)
	}
	if err := verifyCoZkSignature(orderB.Pubkey, req.SigB, msg); err != nil {
		return fmt.Errorf("order B signature: %w", err)
	}
	return nil
}

// loadCoZkMatchedPair loads the pair referenced by `req` and enforces every
// precondition shared by the co-zk settle variants: both orders exist, are
// Matched with each other on opposite sides, order A is the maker of the
// pair, and both quote the same price. Returns the orders plus the execution
// price and whether A is the token1 seller.
func (ot *OrderBook) loadCoZkMatchedPair(req *CoZkSettleRequest) (*Order, *Order, uint64, bool, error) {
	orderA, err := ot.GetOrder(req.OrderAID)
	if err != nil {
		return nil, nil, 0, false, fmt.Errorf("order %s not found: %w", req.OrderAID, err)
	}
	orderB, err := ot.GetOrder(req.OrderBID)
	if err != nil {
		return nil, nil, 0, false, fmt.Errorf("order %s not found: %w", req.OrderBID, err)
	}
	if orderA.Status != Matched {
		return nil, nil, 0, false, fmt.Errorf("order %s is not Matched (current: %s)", orderA.ID, orderA.Status.String())
	}
	if orderB.Status != Matched {
		return nil, nil, 0, false, fmt.Errorf("order %s is not Matched (current: %s)", orderB.ID, orderB.Status.String())
	}
	if orderA.MatchOrder != orderB.ID || orderB.MatchOrder != orderA.ID {
		return nil, nil, 0, false, fmt.Errorf("orders %s and %s are not matched with each other", orderA.ID, orderB.ID)
	}
	if orderA.Type == orderB.Type {
		return nil, nil, 0, false, fmt.Errorf("matched orders must be on opposite sides")
	}

	// Role assignment is deterministic: order A must be the maker, so the
	// circuit's a-side always corresponds to the same trader for everyone.
	if maker, _ := makerTakerOrder(orderA, orderB); maker.ID != orderA.ID {
		return nil, nil, 0, false, fmt.Errorf("order_a %s must be the maker of the pair", req.OrderAID)
	}

	// Defense in depth against silent truncation in executionPrice: SendOrder
	// rejects out-of-range prices at ingress, but rows written before that
	// check existed (or restored from a backup) would still reach the circuit
	// as a different number than the book matched on.
	for _, ord := range []*Order{orderA, orderB} {
		if err := validateOrderPrice(ord.Price); err != nil {
			return nil, nil, 0, false, fmt.Errorf("order %s: %w", ord.ID, err)
		}
	}

	// Equal-price requirement. The buyer's locked collateral was fixed at
	// order creation to amount*buyer_price, but the joint circuits constrain
	// it to amount*exec_price with strict equality and have no buyer-change
	// output. That only holds when exec_price == buyer_price, i.e. when both
	// orders quote the same price. A cross-price (marketable) match would make
	// the joint proof unsatisfiable, so we reject it here (it can still settle
	// via the legacy change-producing path) rather than let the pair wedge.
	if orderA.Price == nil || orderB.Price == nil || orderA.Price.Cmp(orderB.Price) != 0 {
		return nil, nil, 0, false, fmt.Errorf("co-zk settlement requires equal order prices; use the legacy settle path for cross-price matches")
	}

	return orderA, orderB, executionPrice(orderA, orderB), orderA.Type == Sell, nil
}

// SettleOrdersCoZk settles a matched pair with ONE jointly generated Groth16
// proof: verifies both traders' signatures over the settlement message and
// the proof against on-chain state, then spends both locked collaterals,
// mints both receive cashes, marks the fully-filled side(s) Done (removing
// them from the book), and relists the surviving larger order in place with
// its remainder commitments — keeping its original block height so it retains
// time priority.
func (ot *OrderBook) SettleOrdersCoZk(ctx *context.WriteContext) error {
	ctx.SetLei(100)

	req := new(CoZkSettleRequest)
	if err := ctx.BindJson(req); err != nil {
		return err
	}
	if err := Validator.Struct(req); err != nil {
		return err
	}

	orderA, orderB, price, aIsSeller, err := ot.loadCoZkMatchedPair(req)
	if err != nil {
		return err
	}

	// Both traders must have signed the settlement message.
	if err := verifyCoZkPairSignatures(req, orderA, orderB, CoZkSettleMessage(req)); err != nil {
		return err
	}

	// Verify the jointly generated proof against the reconstructed publics.
	signals, err := buildSettleCoZkPublicSignals(req, orderA, orderB, price, aIsSeller, ot.Account)
	if err != nil {
		return fmt.Errorf("building settle_cozk public signals: %w", err)
	}
	if err := VerifyGroth16(ot.settleCoZkVK, req.ZkProof, signals); err != nil {
		return fmt.Errorf("settle_cozk proof verification failed: %w", err)
	}

	return ot.applyCoZkSettlement(ctx, req, orderA, orderB, "cozk")
}

// applyCoZkSettlement performs the state mutation shared by the co-zk settle
// variants, to be called only after all signature and proof checks passed:
// spends both locked collaterals, mints both receive cashes, updates the book
// according to `req.Cmp`, and emits the settlement event. `variant` ("cozk"
// or "cozk2p") tags the spend attribution and the emitted event type.
func (ot *OrderBook) applyCoZkSettlement(
	ctx *context.WriteContext, req *CoZkSettleRequest, orderA, orderB *Order, variant string,
) error {
	// Pre-flight the cash IDs we are about to mint. computeCashID is
	// content-addressed over client-chosen commitments, so a caller could set
	// a recv/locked commitment that collides with an existing cash and make a
	// CreateCash fail *after* collateral is already spent (the per-tripod
	// SQLite writes below are not one atomic transaction — the same
	// non-atomicity the legacy settle path has). Checking for collisions
	// before any irreversible write keeps a malformed request from freezing
	// collateral. `newCashIDs` are the recv cashes plus the surviving order's
	// relisted locked cash (if any).
	mintIDs := []string{
		computeCashID(orderA.Pubkey, recvToken(orderA), CipherText(req.RecvACommitment)),
		computeCashID(orderB.Pubkey, recvToken(orderB), CipherText(req.RecvBCommitment)),
	}
	switch req.Cmp {
	case 1:
		mintIDs = append(mintIDs, computeCashID(orderA.Pubkey, lockToken(orderA), CipherText(req.NewLockedACommitment)))
	case -1:
		mintIDs = append(mintIDs, computeCashID(orderB.Pubkey, lockToken(orderB), CipherText(req.NewLockedBCommitment)))
	}
	for _, id := range mintIDs {
		if ot.Account.CashExists(id) {
			return fmt.Errorf("cash %s to be minted already exists; refusing to settle", id)
		}
	}

	// All checks passed — mutate state.
	settleBy := fmt.Sprintf("%s-settle:%s:%s", variant, orderA.ID[:8], orderB.ID[:8])
	if err := ot.Account.SpendCash(orderA.InputCashIDs, settleBy); err != nil {
		return fmt.Errorf("failed to spend cash for order %s: %w", orderA.ID, err)
	}
	if err := ot.Account.SpendCash(orderB.InputCashIDs, settleBy); err != nil {
		return fmt.Errorf("failed to spend cash for order %s: %w", orderB.ID, err)
	}

	// Mint both receive cashes; the receiving party chose the blinding, so
	// each party can open (and later spend) its own new UTXO.
	for _, mint := range []struct {
		ord        *Order
		commitment string
	}{
		{orderA, req.RecvACommitment},
		{orderB, req.RecvBCommitment},
	} {
		token := recvToken(mint.ord)
		cash := &Cash{
			ID:      computeCashID(mint.ord.Pubkey, token, CipherText(mint.commitment)),
			Pubkey:  mint.ord.Pubkey,
			Token:   token,
			Amount:  CipherText(mint.commitment),
			ZkProof: req.ZkProof,
			Status:  Active,
		}
		if err := ot.Account.CreateCash(cash); err != nil {
			return fmt.Errorf("failed to create recv cash for order %s: %w", mint.ord.ID, err)
		}
	}

	// Update the book according to the public comparison result.
	var relisted, rematched *Order
	var err error
	fullyFilled := func(ord *Order) error {
		if err := ot.UpdateOrderStatus(ord.ID, Done); err != nil {
			return fmt.Errorf("failed to close order %s: %w", ord.ID, err)
		}
		return nil
	}
	switch req.Cmp {
	case 0:
		// Equal amounts: both orders fully fill and leave the book.
		if err := fullyFilled(orderA); err != nil {
			return err
		}
		if err := fullyFilled(orderB); err != nil {
			return err
		}
	case -1:
		// a < b: A fully fills, B survives with remainder b - a.
		if err := fullyFilled(orderA); err != nil {
			return err
		}
		relisted, rematched, err = ot.relistWithRemainder(
			orderB, CipherText(req.NewOrderBCommitment), CipherText(req.NewLockedBCommitment), req.ZkProof)
		if err != nil {
			return err
		}
	case 1:
		// a > b: B fully fills, A survives with remainder a - b.
		if err := fullyFilled(orderB); err != nil {
			return err
		}
		relisted, rematched, err = ot.relistWithRemainder(
			orderA, CipherText(req.NewOrderACommitment), CipherText(req.NewLockedACommitment), req.ZkProof)
		if err != nil {
			return err
		}
	}

	// Clean up any leftover legacy rendezvous/submission rows for the pair.
	_ = ot.DeleteSettleAddr(orderA.ID)
	_ = ot.DeleteSettleAddr(orderB.ID)

	finalA, err := ot.GetOrder(orderA.ID)
	if err != nil {
		return fmt.Errorf("re-reading order %s: %w", orderA.ID, err)
	}
	finalB, err := ot.GetOrder(orderB.ID)
	if err != nil {
		return fmt.Errorf("re-reading order %s: %w", orderB.ID, err)
	}
	event := &CoZkSettleEvent{
		EventType: variant + "_settled",
		Cmp:       req.Cmp,
		OrderA:    finalA,
		OrderB:    finalB,
		Relisted:  relisted,
		Matched:   rematched,
	}
	if err := ctx.EmitJsonEvent(event); err != nil {
		return fmt.Errorf("failed to emit cozk settle event: %w", err)
	}
	return nil
}

// relistWithRemainder keeps the surviving larger order on the book: mints its
// new Locked collateral cash, swaps the order's amount commitment and input
// cash list, clears the match linkage, and returns it to Pending (retaining
// its original block height, i.e. its time priority). It then immediately
// attempts a re-match against the book. Returns the updated order and the
// counter order it re-matched with (nil if none).
func (ot *OrderBook) relistWithRemainder(
	ord *Order, newOrderCommitment, newLockedCommitment CipherText, zkProof string,
) (*Order, *Order, error) {
	token := lockToken(ord)
	newLockedID := computeCashID(ord.Pubkey, token, newLockedCommitment)
	lockedCash := &Cash{
		ID:      newLockedID,
		Pubkey:  ord.Pubkey,
		Token:   token,
		Amount:  newLockedCommitment,
		ZkProof: zkProof,
		Status:  Locked,
		By:      string(ord.ID),
	}
	if err := ot.Account.CreateCash(lockedCash); err != nil {
		return nil, nil, fmt.Errorf("failed to create remainder locked cash: %w", err)
	}

	if err := ot.UpdateOrderAmount(ord.ID, newOrderCommitment); err != nil {
		return nil, nil, fmt.Errorf("failed to update order amount: %w", err)
	}
	if err := ot.UpdateOrderInputCashIDs(ord.ID, []string{newLockedID}); err != nil {
		return nil, nil, fmt.Errorf("failed to update order input cash: %w", err)
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
	// The remainder goes straight back into the matching engine so it can
	// pair with any compatible resting order.
	rematched, err := ot.matchOrder(updated)
	if err != nil {
		return nil, nil, fmt.Errorf("re-matching relisted order: %w", err)
	}
	return updated, rematched, nil
}
