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
	splitVK        *CircuitVK
	settleCoZkVK   *CircuitVK
	settleCoZk2pVK *PlonkVK
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
	// Fail-closed in production: a nil VK means LoadVK/LoadPlonkVK found an
	// empty path and verification would be silently skipped. Refuse to boot
	// so a misconfigured node never accepts unverified settlements.
	if cfg.RequireProofs {
		for name, missing := range map[string]bool{
			"split":         splitVK == nil,
			"settle_cozk":   settleCoZkVK == nil,
			"settle_cozk2p": settleCoZk2pVK == nil,
		} {
			if missing {
				panic(fmt.Sprintf("require_proofs is set but %s VK path is empty; refusing to start with proof verification disabled", name))
			}
		}
	}
	ot := &OrderBook{
		Tripod:         tri,
		db:             InitOrderDB(cfg.DBPath, ParseGormLogLevel(cfg.DBLogLevel)),
		splitVK:        splitVK,
		settleCoZkVK:   settleCoZkVK,
		settleCoZk2pVK: settleCoZk2pVK,
	}
	ot.SetWritings(ot.SendOrder, ot.SettleOrdersCoZk, ot.SettleOrdersCoZk2p, ot.RegisterSettleAddr)
	ot.SetReadings(ot.QueryOrders, ot.QuerySettleAddr)
	return ot
}

// ────────────────────── Writing: SendOrder ──────────────────────

// CashChangeOutput describes a change Cash the client wants minted back
// after a split. The client pre-generates the ID and encrypts the change amount.
type CashChangeOutput struct {
	CashID string     `json:"cash_id" validate:"required"` // client-generated
	Amount CipherText `json:"amount"  validate:"required"` // encrypted change amount
}

// SendOrderRequest is the JSON payload accepted by SendOrder. The client
// pre-computes the order ID (SHA-256 over input cash IDs), ed25519-signs the
// canonical signing message covering every field (see SendOrderSigningMessage),
// and lists the input Cash they want to lock or split.
//
// `ZkProof` is required only in split mode (when `Change != nil`): it proves
// `sum(input_commitments) == sum(output_commitments)` where outputs are
// `[Amount, Change.Amount]`. Non-split lock-the-whole-cash requests don't
// reshuffle value (the commitment is unchanged) so no proof is needed.
type SendOrderRequest struct {
	ID           OrderID           `json:"id"             validate:"required"`
	Type         TradeType         `json:"type"           validate:"oneof=0 1"`
	Subject      TradePair         `json:"subject"`
	Price        *big.Int          `json:"price,omitempty"`
	Amount       CipherText        `json:"amount"         validate:"required"`
	Pubkey       string            `json:"pubkey"         validate:"required"` // sender's ed25519 pubkey (64-char hex)
	Signature    string            `json:"signature"      validate:"required"` // ed25519 sig over SendOrderSigningMessage (128-char hex)
	InputCashIDs []string          `json:"input_cash_ids" validate:"required,min=1,max=2,unique"`
	HandlingFee  []string          `json:"handling_fee"   validate:"required,min=1"` // must be plaintext.
	Change       *CashChangeOutput `json:"change,omitempty"`
	ZkProof      string            `json:"zk_proof,omitempty"` // required when Change != nil
	// For buy orders in split mode: the actual cash commitment (poseidon(usdt_total, r_cash)).
	// Split proof and locked cash use this instead of Amount (which stores the token1 qty commitment).
	// When empty, falls back to Amount (sell orders or no-split mode).
	LockedCommitment CipherText `json:"locked_commitment,omitempty"`
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

// SendOrder creates a new order, locks the input Cash, stores it via SQL, and attempts to match it.
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

	// Validate that the client-submitted ID is the correct hash of the input cash IDs.
	if expectedID := ComputeOrderID(req.InputCashIDs); req.ID != expectedID {
		return fmt.Errorf("order ID mismatch: got %s, expected %s", req.ID, expectedID)
	}

	// Verify the sender's ed25519 signature over the canonical signing message.
	// The message covers every request field (price, pair, amount, fees, change,
	// ...), not just the order ID — otherwise any observer could resubmit the
	// signed ID with altered fields and open an attacker-priced order backed by
	// the victim's cash.
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

	// Determine expected token for the input Cash:
	// Buy(Token1/Token2) → paying with Token2
	// Sell(Token1/Token2) → selling Token1
	expectedToken := req.Subject.Token1
	if req.Type == Buy {
		expectedToken = req.Subject.Token2
	}

	// Validate each input Cash: exists, Active, pubkey matches, token matches
	for _, cashID := range req.InputCashIDs {
		cash, err := ot.Account.GetCash(cashID)
		if err != nil {
			return fmt.Errorf("input cash %s not found: %w", cashID, err)
		}
		if cash.Status != Active {
			return fmt.Errorf("input cash %s is not Active (current: %s)", cashID, cash.Status.String())
		}
		if cash.Pubkey != req.Pubkey {
			return fmt.Errorf("input cash %s pubkey mismatch: got %s, expected %s", cashID, cash.Pubkey, req.Pubkey)
		}
		if cash.Token != expectedToken {
			return fmt.Errorf("input cash %s token mismatch: got %s, expected %s", cashID, cash.Token, expectedToken)
		}
	}

	// Lock or split the input Cash
	var orderInputCashIDs []string
	if req.Change != nil {
		// Split mode requires a zk proof of conservation:
		//   sum(input_commitments) == sum(output_commitments)
		// where outputs are [LockedCommitment (or Amount), Change.Amount].
		if req.ZkProof == "" {
			return fmt.Errorf("split mode requires zk_proof")
		}

		// For buy orders, LockedCommitment holds the actual cash commitment
		// (poseidon(usdt_total, r_cash)), while Amount holds the token1 qty
		// commitment for MPC. For sell orders (or when omitted), fall back to Amount.
		cashCommitment := req.Amount
		if req.LockedCommitment != "" {
			cashCommitment = req.LockedCommitment
		}

		// Rebuild the public-input vector in the order split.circom declares them:
		//   public[0..N] = input_hashes  (zero-padded to N=2)
		//   public[N..N+M] = output_hashes  (M=2: locked + change)
		const splitN = 2
		publicSignals := make([]string, 0, splitN+2)
		for i := 0; i < splitN; i++ {
			var hex string
			if i < len(req.InputCashIDs) {
				// We already fetched + validated each input Cash above, but we
				// re-read here to keep the declaration order tight; the row is
				// hot in cache so the cost is negligible.
				cash, err := ot.Account.GetCash(req.InputCashIDs[i])
				if err != nil {
					return fmt.Errorf("input cash %s lookup failed: %w", req.InputCashIDs[i], err)
				}
				hex = string(cash.Amount)
			} else {
				hex = PoseidonZeroCommitmentHex
			}
			dec, err := HexToDecimal(hex)
			if err != nil {
				return fmt.Errorf("invalid input commitment hex at slot %d: %w", i, err)
			}
			publicSignals = append(publicSignals, dec)
		}
		lockedDec, err := HexToDecimal(string(cashCommitment))
		if err != nil {
			return fmt.Errorf("invalid locked commitment: %w", err)
		}
		changeDec, err := HexToDecimal(string(req.Change.Amount))
		if err != nil {
			return fmt.Errorf("invalid Change.Amount: %w", err)
		}
		publicSignals = append(publicSignals, lockedDec, changeDec)

		if err := VerifyGroth16(ot.splitVK, req.ZkProof, publicSignals); err != nil {
			return fmt.Errorf("split proof verification failed: %w", err)
		}

		// Spend originals, create one locked cash + one active change cash.
		if err := ot.Account.SpendCash(req.InputCashIDs, string(req.ID)); err != nil {
			return fmt.Errorf("failed to spend cash for split: %w", err)
		}
		lockedCashID := computeCashID(req.Pubkey, expectedToken, cashCommitment)
		if err := ot.Account.CreateCash(&Cash{
			ID: lockedCashID, Pubkey: req.Pubkey, Token: expectedToken,
			Amount: cashCommitment, ZkProof: req.ZkProof, Status: Locked, By: string(req.ID),
		}); err != nil {
			return fmt.Errorf("failed to create locked split cash: %w", err)
		}
		if err := ot.Account.CreateCash(&Cash{
			ID: req.Change.CashID, Pubkey: req.Pubkey, Token: expectedToken,
			Amount: req.Change.Amount, ZkProof: req.ZkProof, Status: Active,
		}); err != nil {
			return fmt.Errorf("failed to create change cash: %w", err)
		}
		orderInputCashIDs = []string{lockedCashID}
	} else {
		// Normal mode: lock entire cash (existing behavior, no proof needed).
		if err := ot.Account.LockCash(req.InputCashIDs, string(req.ID)); err != nil {
			return fmt.Errorf("failed to lock cash: %w", err)
		}
		orderInputCashIDs = req.InputCashIDs
	}

	order := &Order{
		ID:           req.ID,
		Type:         req.Type,
		Subject:      req.Subject,
		Price:        req.Price,
		Amount:       req.Amount,
		Pubkey:       req.Pubkey,
		InputCashIDs: orderInputCashIDs,
		HandlingFee:  req.HandlingFee,
		BlockHeight:  uint32(ctx.Block.Height),
		Status:       Pending,
	}

	if err := ot.InsertOrder(order); err != nil {
		return fmt.Errorf("failed to insert order: %w", err)
	}

	if err := ctx.EmitJsonEvent(&OrderEvent{EventType: "created", Order: order}); err != nil {
		return fmt.Errorf("failed to emit order created event: %w", err)
	}

	// Attempt to match
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

// lockedInputHexesPadded fetches each locked input cash for `ord`, asserts
// it's the expected token, and returns N 64-char hex commitments (pad with
// PoseidonZeroCommitmentHex when ord has fewer than N inputs).
func lockedInputHexesPadded(ord *Order, acc *Account, n int, expectedToken TokenID) ([]string, error) {
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		if i >= len(ord.InputCashIDs) {
			out = append(out, PoseidonZeroCommitmentHex)
			continue
		}
		cash, err := acc.GetCash(ord.InputCashIDs[i])
		if err != nil {
			return nil, fmt.Errorf("locked cash %s not found: %w", ord.InputCashIDs[i], err)
		}
		if cash.Token != expectedToken {
			return nil, fmt.Errorf("locked cash %s token %s != expected %s", cash.ID, cash.Token, expectedToken)
		}
		out = append(out, string(cash.Amount))
	}
	return out, nil
}

// lockedInputHashesPadded is lockedInputHexesPadded rendered as the
// decimal-string commitments snarkjs verifiers consume.
func lockedInputHashesPadded(ord *Order, acc *Account, n int, expectedToken TokenID) ([]string, error) {
	hexes, err := lockedInputHexesPadded(ord, acc, n, expectedToken)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(hexes))
	for i, h := range hexes {
		dec, err := HexToDecimal(h)
		if err != nil {
			return nil, fmt.Errorf("input commitment hex at slot %d: %w", i, err)
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

		// ── Priority 3: Handling Fee (higher = better) ──
		if totalFee(candidate.HandlingFee) > totalFee(bestMatch.HandlingFee) {
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

// totalFee sums the handling fee strings as uint64 values.
func totalFee(fees []string) uint64 {
	var sum uint64
	for _, f := range fees {
		var v uint64
		if _, err := fmt.Sscanf(f, "%d", &v); err == nil {
			sum += v
		}
	}
	return sum
}
