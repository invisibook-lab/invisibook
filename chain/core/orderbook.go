package core

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/http"

	"gorm.io/gorm"

	"github.com/yu-org/yu/core/context"
	"github.com/yu-org/yu/core/tripod"
)

// ────────────────────── Events ──────────────────────

// OrderEvent is emitted as a JSON event after SendOrder succeeds.
// EventType is "created" when the order is stored, and "matched" when a
// counterparty is found (both the new order and the matched order are included).
type OrderEvent struct {
	EventType string `json:"event_type"`
	Order     *Order `json:"order"`
	Matched   *Order `json:"matched,omitempty"`
}

// ────────────────────── Tripod ──────────────────────

// OrderBook is the tripod that owns the order table: it accepts new orders,
// runs the matching engine, and settles matched pairs. It depends on the
// Account tripod (injected via the `tripod` struct tag) for Cash state changes.
type OrderBook struct {
	*tripod.Tripod
	Account        *Account `tripod:"account"`
	db             *gorm.DB
	chainID        uint64
	splitVK        *CircuitVK
	settleCoZkVK   *CircuitVK
	settleCoZk2pVK *PlonkVK
	settleSmallVK  *CircuitVK
	settleLargeVK  *CircuitVK
	sendOrderVK    *CircuitVK
	claimFeesVK    *CircuitVK
}

// NewOrderBook constructs the OrderBook tripod and registers its writings and
// readings. `cfg` must carry a valid SQLite DSN plus readable VK paths.
// DB init and VK loading panic on failure.
func NewOrderBook(cfg *OrderBookConfig) *OrderBook {
	tri := tripod.NewTripodWithName("orderbook")
	splitVK, err := LoadVK("split", cfg.SplitVKPath)
	if err != nil {
		panic(fmt.Sprintf("loading split VK: %v", err))
	}
	settleCoZkVK, err := LoadVK("settle_cozk", cfg.SettleCoZkVKPath)
	if err != nil {
		panic(fmt.Sprintf("loading settle_cozk VK: %v", err))
	}
	settleCoZk2pVK, err := LoadPlonkVK("settle_cozk2p", cfg.SettleCoZk2pVKPath)
	if err != nil {
		panic(fmt.Sprintf("loading settle_cozk2p VK: %v", err))
	}
	settleSmallVK, err := LoadVK("settle_small", cfg.SettleSmallVKPath)
	if err != nil {
		panic(fmt.Sprintf("loading settle_small VK: %v", err))
	}
	settleLargeVK, err := LoadVK("settle_large", cfg.SettleLargeVKPath)
	if err != nil {
		panic(fmt.Sprintf("loading settle_large VK: %v", err))
	}
	sendOrderVK, err := LoadVK("send_order", cfg.SendOrderVKPath)
	if err != nil {
		panic(fmt.Sprintf("loading send_order VK: %v", err))
	}
	claimFeesVK, err := LoadVK("claim_fees", cfg.ClaimFeesVKPath)
	if err != nil {
		panic(fmt.Sprintf("loading claim_fees VK: %v", err))
	}
	// Fail-closed in production: a nil VK means LoadVK/LoadPlonkVK found an
	// empty path and verification would be silently skipped. Refuse to boot
	// so a misconfigured node never accepts unverified settlements.
	if cfg.RequireProofs {
		for name, missing := range map[string]bool{
			"split":         splitVK == nil,
			"settle_cozk":   settleCoZkVK == nil,
			"settle_cozk2p": settleCoZk2pVK == nil,
			"settle_small":  settleSmallVK == nil,
			"settle_large":  settleLargeVK == nil,
			"send_order":    sendOrderVK == nil,
			"claim_fees":    claimFeesVK == nil,
		} {
			if missing {
				panic(fmt.Sprintf("require_proofs is set but %s VK path is empty; refusing to start with proof verification disabled", name))
			}
		}
	}
	ot := &OrderBook{
		Tripod:         tri,
		db:             InitOrderDB(cfg.DBPath, ParseGormLogLevel(cfg.DBLogLevel)),
		chainID:        cfg.ChainID,
		splitVK:        splitVK,
		settleCoZkVK:   settleCoZkVK,
		settleCoZk2pVK: settleCoZk2pVK,
		settleSmallVK:  settleSmallVK,
		settleLargeVK:  settleLargeVK,
		sendOrderVK:    sendOrderVK,
		claimFeesVK:    claimFeesVK,
	}
	ot.SetWritings(ot.SendOrder, ot.SubmitCompareCoZk, ot.SubmitCompareCoZk2p,
		ot.SettleSmall, ot.SettleLarge, ot.SettlePair, ot.ClaimFees, ot.RegisterSettleAddr)
	ot.SetReadings(ot.QueryOrders, ot.QuerySettleAddr, ot.QueryFees)
	return ot
}

// ────────────────────── Writing: SendOrder ──────────────────────

// SendOrderRequest (v2) is the JSON payload accepted by SendOrder. Placing
// an order spends up to two pool notes (by nullifier), commits the order
// quantity as `Amount` (cm_q), locks its collateral as `LockedCommitment`,
// destroys the plaintext `Fee`, and mints a change note — all proven by the
// send_order circuit. The order ID is SHA-256 over the input nullifiers,
// and the ed25519 signature covers the whole request.
type SendOrderRequest struct {
	ID               OrderID    `json:"id"                 validate:"required"`
	Type             TradeType  `json:"type"               validate:"oneof=0 1"`
	Subject          TradePair  `json:"subject"`
	Price            *big.Int   `json:"price,omitempty"`
	Amount           CipherText `json:"amount"             validate:"required,len=64"` // cm_q
	Pubkey           string     `json:"pubkey"             validate:"required"`
	Signature        string     `json:"signature"          validate:"required"`
	Anchor           string     `json:"anchor"             validate:"required,len=64"`
	InputNullifiers  []string   `json:"input_nullifiers"   validate:"required,len=2,dive,len=64"`
	LockedCommitment string     `json:"locked_commitment"  validate:"required,len=64"`
	Fee              uint64     `json:"fee"`
	ChangeCommitment string     `json:"change_commitment"  validate:"required,len=64"`
	ZkProof          string     `json:"zk_proof"           validate:"required"`
}

// validateOrderPrice rejects prices the settlement circuits cannot represent.
// A nil price is allowed: such an order simply never matches (see matchOrder).
//
// The settlement relation takes `price` as a public input and multiplies it by
// 64-bit amounts. That arithmetic is only integer-exact while the products stay
// below the BN254 modulus, which the circuits get from price < 2^64 — they
// deliberately do not re-range-check a public input, so the bound has to hold
// here. Every path from an Order to the circuit funnels through
// big.Int.Uint64(), which truncates SILENTLY, so without this check the book
// would match on one price and settle on another.
//
// Zero and negative prices are rejected as well: neither is a meaningful order,
// and at price 0 a buy side backs its order with no collateral at all.
func validateOrderPrice(price *big.Int) error {
	if price == nil {
		return nil
	}
	if price.Sign() <= 0 {
		return fmt.Errorf("price must be positive, got %s", price)
	}
	if !price.IsUint64() {
		return fmt.Errorf("price %s does not fit in 64 bits", price)
	}
	return nil
}

// SendOrder spends the input notes, verifies the send_order proof (which
// enforces admission-time full collateralization), mints the change note,
// accrues the fee to the block producer, stores the order, and matches it.
func (ot *OrderBook) SendOrder(ctx *context.WriteContext) error {
	ctx.SetLei(100)

	req := new(SendOrderRequest)
	if err := ctx.BindJson(req); err != nil {
		return err
	}
	if err := Validator.Struct(req); err != nil {
		return err
	}
	if err := validateOrderPrice(req.Price); err != nil {
		return fmt.Errorf("order %s: %w", req.ID, err)
	}
	if req.Price == nil {
		return fmt.Errorf("order %s: send_order requires a price", req.ID)
	}

	// The order ID is the hash of the input nullifiers.
	if expectedID := ComputeOrderID(req.InputNullifiers); req.ID != expectedID {
		return fmt.Errorf("order ID mismatch: got %s, expected %s", req.ID, expectedID)
	}

	// Verify the owner's ed25519 signature over the full request (the order
	// pubkey is public per the paper; the signature authenticates its later
	// settlement messages, and stops anyone from re-pricing a signed order).
	pubkeyBytes, err := hex.DecodeString(req.Pubkey)
	if err != nil || len(pubkeyBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid pubkey: must be %d-byte ed25519 key as 64-char hex", ed25519.PublicKeySize)
	}
	sigBytes, err := hex.DecodeString(req.Signature)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature: must be %d-byte ed25519 sig as 128-char hex", ed25519.SignatureSize)
	}
	if !ed25519.Verify(pubkeyBytes, SendOrderSigningMessage(req), sigBytes) {
		return fmt.Errorf("signature verification failed for order %s", req.ID)
	}

	// Collateral token: Buy → token2, Sell → token1.
	lockAsset := req.Subject.Token1
	if req.Type == Buy {
		lockAsset = req.Subject.Token2
	}
	assetID, err := AssetID(lockAsset)
	if err != nil {
		return err
	}

	// Cheap checks first (zcashd ordering): canonical field elements,
	// request-internal duplicate nullifier, spent set, anchor known.
	for _, h := range []string{req.Anchor, req.InputNullifiers[0], req.InputNullifiers[1],
		string(req.Amount), req.LockedCommitment, req.ChangeCommitment} {
		if _, perr := ParseFrHex(h); perr != nil {
			return fmt.Errorf("non-canonical field element %q: %w", h, perr)
		}
	}
	if req.InputNullifiers[0] == req.InputNullifiers[1] {
		return fmt.Errorf("duplicate nullifier in request")
	}
	for _, nf := range req.InputNullifiers {
		spent, serr := ot.Account.NullifierSpent(nf)
		if serr != nil {
			return serr
		}
		if spent {
			return fmt.Errorf("nullifier %s already spent", nf)
		}
	}
	known, err := ot.Account.AnchorKnown(req.Anchor)
	if err != nil {
		return err
	}
	if !known {
		return fmt.Errorf("unknown anchor %s", req.Anchor)
	}

	// Rebuild the send_order public vector:
	// [anchor, nf_0, nf_1, lock_asset_id, cm_q, locked_commitment, fee,
	//  cm_change, price, side, bind].
	toDec := func(h, what string) (string, error) {
		d, derr := HexToDecimal(h)
		if derr != nil {
			return "", fmt.Errorf("invalid %s: %w", what, derr)
		}
		return d, nil
	}
	anchorDec, err := toDec(req.Anchor, "anchor")
	if err != nil {
		return err
	}
	nf0Dec, err := toDec(req.InputNullifiers[0], "nullifiers[0]")
	if err != nil {
		return err
	}
	nf1Dec, err := toDec(req.InputNullifiers[1], "nullifiers[1]")
	if err != nil {
		return err
	}
	cmQDec, err := toDec(string(req.Amount), "amount")
	if err != nil {
		return err
	}
	lockedDec, err := toDec(req.LockedCommitment, "locked_commitment")
	if err != nil {
		return err
	}
	changeDec, err := toDec(req.ChangeCommitment, "change_commitment")
	if err != nil {
		return err
	}
	side := "0"
	if req.Type == Sell {
		side = "1"
	}
	bind := sendOrderBind(ot.chainID, req)
	signals := []string{
		anchorDec, nf0Dec, nf1Dec, assetID.String(), cmQDec, lockedDec,
		fmt.Sprintf("%d", req.Fee), changeDec,
		req.Price.String(), side, bind.String(),
	}
	if err := VerifyGroth16(ot.sendOrderVK, req.ZkProof, signals); err != nil {
		return fmt.Errorf("send_order proof verification failed: %w", err)
	}

	// Publish nullifiers + mint the change note atomically.
	cmChange, err := ParseFrHex(req.ChangeCommitment)
	if err != nil {
		return fmt.Errorf("change_commitment: %w", err)
	}
	if _, err := ot.Account.ApplyPoolMutation(PoolMutation{
		Nullifiers: req.InputNullifiers,
		NoteCms:    []*big.Int{cmChange},
		Height:     uint64(ctx.Block.Height),
		Source:     "send-order-change",
		By:         fmt.Sprintf("send-order:%s", req.ID[:8]),
	}); err != nil {
		return fmt.Errorf("spending order inputs: %w", err)
	}

	// Accrue the fee to the block producer (native token).
	if req.Fee > 0 {
		producer := hex.EncodeToString(ctx.Block.MinerPubkey)
		if err := ot.AccrueFee(producer, string(NativeToken.Name), req.Fee); err != nil {
			return fmt.Errorf("accruing fee: %w", err)
		}
	}

	order := &Order{
		ID:               req.ID,
		Type:             req.Type,
		Subject:          req.Subject,
		Price:            req.Price,
		Amount:           req.Amount,
		Pubkey:           req.Pubkey,
		LockedCommitment: req.LockedCommitment,
		Fee:              req.Fee,
		BlockHeight:      uint32(ctx.Block.Height),
		IntraBlockIndex:  uint32(ctx.TxnIndex),
		Status:           Pending,
	}
	if err := ot.InsertOrder(order); err != nil {
		return fmt.Errorf("failed to insert order: %w", err)
	}
	if err := ctx.EmitJsonEvent(&OrderEvent{EventType: "created", Order: order}); err != nil {
		return fmt.Errorf("failed to emit order created event: %w", err)
	}

	matched, err := ot.matchOrder(order)
	if err != nil {
		return fmt.Errorf("failed to match order: %w", err)
	}
	if matched != nil {
		if err := ctx.EmitJsonEvent(&OrderEvent{EventType: "matched", Order: order, Matched: matched}); err != nil {
			return fmt.Errorf("failed to emit order matched event: %w", err)
		}
	}
	return nil
}

// lockedSlotsHex returns the order's collateral commitment as the 2-slot
// shape the settle circuits expect: [LockedCommitment, P2(0,0) pad].
func lockedSlotsHex(ord *Order) []string {
	return []string{ord.LockedCommitment, PoseidonZeroCommitmentHex}
}

// lockedSlotsDec is lockedSlotsHex rendered as the decimal-string
// commitments snarkjs verifiers consume.
func lockedSlotsDec(ord *Order) ([]string, error) {
	hexes := lockedSlotsHex(ord)
	out := make([]string, 0, len(hexes))
	for i, h := range hexes {
		dec, err := HexToDecimal(h)
		if err != nil {
			return nil, fmt.Errorf("locked commitment hex at slot %d: %w", i, err)
		}
		out = append(out, dec)
	}
	return out, nil
}

// ────────────────────── Writing: RegisterSettleAddr ──────────────────────

// RegisterSettleAddrRequest is the JSON payload for registering an MPC settle
// address. Each party sends its QUIC listen address so the counterparty can
// discover it on-chain.
// NOTE: This on-chain address exchange is temporary. In production, peer
// addresses will be exchanged via Tor or similar anonymous overlay network.
type RegisterSettleAddrRequest struct {
	OrderID      OrderID `json:"order_id"       validate:"required"`
	MatchOrderID OrderID `json:"match_order_id" validate:"required"`
	Addr         string  `json:"addr"           validate:"required"`
}

// RegisterSettleAddr stores the caller's QUIC address for MPC peer discovery.
func (ot *OrderBook) RegisterSettleAddr(ctx *context.WriteContext) error {
	ctx.SetLei(10)

	req := new(RegisterSettleAddrRequest)
	if err := ctx.BindJson(req); err != nil {
		return err
	}
	if err := Validator.Struct(req); err != nil {
		return err
	}

	// Validate order exists, is Matched, and match_order agrees.
	order, err := ot.GetOrder(req.OrderID)
	if err != nil {
		return fmt.Errorf("order %s not found: %w", req.OrderID, err)
	}
	if order.Status != Matched {
		return fmt.Errorf("order %s is not Matched (current: %s)", order.ID, order.Status.String())
	}
	if order.MatchOrder != req.MatchOrderID {
		return fmt.Errorf("order %s match_order is %s, not %s", order.ID, order.MatchOrder, req.MatchOrderID)
	}

	entry := &SettleAddrScheme{
		OrderID:      string(req.OrderID),
		MatchOrderID: string(req.MatchOrderID),
		Addr:         req.Addr,
	}
	if err := ot.UpsertSettleAddr(entry); err != nil {
		return fmt.Errorf("failed to upsert settle addr: %w", err)
	}

	ctx.EmitStringEvent("settle addr registered for order %s: %s", req.OrderID, req.Addr)
	return nil
}

// ────────────────────── Reading: QuerySettleAddr ──────────────────────

// QuerySettleAddrRequest is the JSON payload for querying the counterparty's
// registered MPC settle address.
type QuerySettleAddrRequest struct {
	OrderID      OrderID `json:"order_id"       validate:"required"`
	MatchOrderID OrderID `json:"match_order_id" validate:"required"`
}

// QuerySettleAddr looks up the counterparty's registered QUIC address by
// querying the match_order_id's entry.
func (ot *OrderBook) QuerySettleAddr(ctx *context.ReadContext) {
	req := new(QuerySettleAddrRequest)
	if err := ctx.BindJson(req); err != nil {
		ctx.Json(http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	// Look up counterparty's addr by their order ID (the match_order_id).
	entry, err := ot.GetSettleAddr(req.MatchOrderID)
	if err != nil {
		// Not yet registered — return empty addr.
		ctx.JsonOk(map[string]string{"addr": ""})
		return
	}
	ctx.JsonOk(map[string]string{"addr": entry.Addr})
}

// ────────────────────── Reading: QueryOrders ──────────────────────

// QueryOrdersRequest defines optional filter criteria for querying orders.
// All fields are pointers — nil means "don't filter by this field".
// Limit and Offset provide pagination; Limit=0 means no limit.
type QueryOrdersRequest struct {
	ID     *OrderID   `json:"id,omitempty"`
	Type   *TradeType `json:"type,omitempty"`
	Token1 *TokenID   `json:"token1,omitempty"`
	Token2 *TokenID   `json:"token2,omitempty"`
	Status *OrderStat `json:"status,omitempty"`
	Limit  int        `json:"limit,omitempty"`
	Offset int        `json:"offset,omitempty"`
}

// QueryOrders returns orders matching the given filter criteria with pagination.
func (ot *OrderBook) QueryOrders(ctx *context.ReadContext) {
	req := new(QueryOrdersRequest)
	if err := ctx.BindJson(req); err != nil {
		ctx.Json(http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	filter := OrderFilter{
		ID:     req.ID,
		Type:   req.Type,
		Token1: req.Token1,
		Token2: req.Token2,
		Status: req.Status,
		Limit:  req.Limit,
		Offset: req.Offset,
	}

	orders, err := ot.FindOrdersByFilter(filter)
	if err != nil {
		ctx.Json(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	ctx.JsonOk(map[string]interface{}{"orders": orders})
}

// ────────────────────── Matching Logic ──────────────────────

// matchOrder finds the best counterparty for the incoming order using three
// priority levels:
//
//  1. Price Priority: best price first (lowest sell for buyer, highest buy for seller)
//  2. Block Height Priority: earlier block (lower height) wins when prices tie
//  3. Gas Fee Priority: higher handling fee wins when prices and block heights tie
//
// If matched, both orders' Status is set to Matched and MatchOrder is set to each other.
func (ot *OrderBook) matchOrder(order *Order) (*Order, error) {
	if order.Price == nil {
		return nil, nil // cannot match without a price
	}

	// Determine counter side
	counterType := Sell
	if order.Type == Sell {
		counterType = Buy
	}

	candidates, err := ot.FindPendingCounterOrders(order.Subject, counterType)
	if err != nil {
		return nil, err
	}

	var bestMatch *Order
	for _, candidate := range candidates {
		if candidate.Price == nil {
			continue
		}

		// Price compatibility check
		if order.Type == Buy && candidate.Price.Cmp(order.Price) > 0 {
			continue // sell price > buy price → incompatible
		}
		if order.Type == Sell && candidate.Price.Cmp(order.Price) < 0 {
			continue // buy price < sell price → incompatible
		}

		if bestMatch == nil {
			bestMatch = candidate
			continue
		}

		// ── Priority 1: Price ──
		priceCmp := candidate.Price.Cmp(bestMatch.Price)
		if order.Type == Buy {
			// Buying: lower sell price is better
			if priceCmp < 0 {
				bestMatch = candidate
				continue
			} else if priceCmp > 0 {
				continue
			}
		} else {
			// Selling: higher buy price is better
			if priceCmp > 0 {
				bestMatch = candidate
				continue
			} else if priceCmp < 0 {
				continue
			}
		}

		// ── Priority 2: Block Height (lower = earlier = better) ──
		if candidate.BlockHeight < bestMatch.BlockHeight {
			bestMatch = candidate
			continue
		} else if candidate.BlockHeight > bestMatch.BlockHeight {
			continue
		}

		// ── Priority 3: Fee (higher = better) ──
		if candidate.Fee > bestMatch.Fee {
			bestMatch = candidate
			continue
		} else if candidate.Fee < bestMatch.Fee {
			continue
		}

		// ── Priority 4: Intra-block transaction index (smaller = earlier) ──
		if candidate.IntraBlockIndex < bestMatch.IntraBlockIndex {
			bestMatch = candidate
		}
	}

	if bestMatch == nil {
		return nil, nil
	}

	// Update both orders to Matched and set MatchOrder to each other
	order.Status = Matched
	order.MatchOrder = bestMatch.ID
	bestMatch.Status = Matched
	bestMatch.MatchOrder = order.ID

	if err := ot.UpdateOrderStatus(order.ID, Matched); err != nil {
		return nil, err
	}
	if err := ot.UpdateOrderMatchOrder(order.ID, bestMatch.ID); err != nil {
		return nil, err
	}
	if err := ot.UpdateOrderStatus(bestMatch.ID, Matched); err != nil {
		return nil, err
	}
	if err := ot.UpdateOrderMatchOrder(bestMatch.ID, order.ID); err != nil {
		return nil, err
	}

	return bestMatch, nil
}
