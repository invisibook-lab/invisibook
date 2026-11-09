package core

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/http"
	"strconv"

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
	settleCoZkVK, err := LoadVK("settle_cozk", cfg.SettleCoZkVKPath)
	if err != nil {
		panic(fmt.Sprintf("loading settle_cozk VK: %v", err))
	}
	settleCoZk2pVK, err := LoadPlonkVK("settle_cozk2p", cfg.SettleCoZk2pVKPath)
	if err != nil {
		panic(fmt.Sprintf("loading settle_cozk2p VK: %v", err))
	}
	// A node configured for collaborative settlement must be able to verify
	// it. Booting a stub binary here would accept orders that can never
	// settle ("starts but cannot settle") — refuse instead.
	if settleCoZk2pVK != nil && !PlonkVerifierAvailable() {
		panic("a PLONK VK path is configured but this binary was built " +
			"without the cozk2p PLONK verifier; build with `make build-chain` " +
			"(go build -tags cozk2p) or remove the PLONK VKs from the config")
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
		settleCoZkVK:   settleCoZkVK,
		settleCoZk2pVK: settleCoZk2pVK,
		settleSmallVK:  settleSmallVK,
		settleLargeVK:  settleLargeVK,
		sendOrderVK:    sendOrderVK,
		claimFeesVK:    claimFeesVK,
	}
	// Each owner submits only its own identity-bound settlement leg. Comparison
	// verification has already opened the absolute leg deadline; the chain
	// invokes the internal atomic pair executor only after both owner proofs
	// verify. The old
	// one-shot compare/SettlePair and unilateral writings are not registered.
	ot.SetWritings(ot.SendOrder, ot.SubmitCompareCoZk2pShare,
		ot.SubmitSettleLeg, ot.FinalizeSettleLegs, ot.ClaimFees, ot.RegisterSettleAddr,
		ot.ExpireCompareCoZk2pShares, ot.ExpireSettleLegs)
	ot.SetReadings(ot.QueryOrders, ot.QuerySettleAddr, ot.QueryFees,
		ot.QueryCompareCoZk2pShares, ot.QuerySettleLegs)
	return ot
}

// ────────────────────── Writing: SendOrder ──────────────────────

// SendOrderRequest (v4) is the JSON payload accepted by SendOrder. Placing
// an order spends separate two-slot note banks for collateral and native fees, locks its collateral
// as `LockedCommitment` (the order's ONLY commitment — locked-only model),
// destroys the plaintext `Fee`, and mints collateral/fee change notes — all proven by the
// send_order circuit. The order ID is SHA-256 over the input nullifiers,
// and the ed25519 signature covers the whole request.
type SendOrderRequest struct {
	ID                         OrderID   `json:"id"                 validate:"required"`
	Kind                       OrderKind `json:"kind"               validate:"oneof=0 1"`
	Type                       TradeType `json:"type"               validate:"oneof=0 1"`
	Subject                    TradePair `json:"subject"`
	Price                      *big.Int  `json:"price,omitempty"`
	ProtectionPrice            *big.Int  `json:"protection_price,omitempty"`
	Pubkey                     string    `json:"pubkey"             validate:"required"`
	Signature                  string    `json:"signature"          validate:"required"`
	Anchor                     string    `json:"anchor"             validate:"required,len=64"`
	CollateralNullifiers       []string  `json:"collateral_nullifiers" validate:"required,len=2,dive,len=64"`
	FeeNullifiers              []string  `json:"fee_nullifiers"        validate:"required,len=2,dive,len=64"`
	LockedCommitment           string    `json:"locked_commitment"  validate:"required,len=64"`
	Fee                        uint64    `json:"fee"`
	CollateralChangeCommitment string    `json:"collateral_change_commitment" validate:"required,len=64"`
	FeeChangeCommitment        string    `json:"fee_change_commitment"        validate:"required,len=64"`
	ZkProof                    string    `json:"zk_proof"           validate:"required"`
}

// validateOrderPrice rejects non-nil prices the settlement circuits cannot
// represent. validateOrderTerms separately decides which order kind may use a
// nil limit price.
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

// validateOrderTerms enforces the unambiguous v4 representation. Limit
// orders carry a limit price and no protection price. Market orders carry no
// limit price and use a public protection price solely for collateralization
// and slippage bounds.
func validateOrderTerms(kind OrderKind, price, protection *big.Int) error {
	switch kind {
	case Limit:
		if price == nil || protection != nil {
			return fmt.Errorf("limit order requires price and forbids protection_price")
		}
		return validateOrderPrice(price)
	case Market:
		if price != nil || protection == nil {
			return fmt.Errorf("market order requires protection_price and forbids price")
		}
		return validateOrderPrice(protection)
	default:
		return fmt.Errorf("unknown order kind %d", kind)
	}
}

func collateralPrice(order *Order) *big.Int {
	if order.Kind == Market {
		return order.ProtectionPrice
	}
	return order.Price
}

// SendOrder spends the input notes, verifies the send_order proof (which
// enforces admission-time full collateralization), mints both change notes,
// accrues the fee to the block producer, stores the order, and matches it.
func (ot *OrderBook) SendOrder(ctx *context.WriteContext) error {
	ctx.SetLei(100)
	LogPayloadSize("SendOrder", ctx.GetRequestBytes())

	req := new(SendOrderRequest)
	if err := ctx.BindJson(req); err != nil {
		return err
	}
	if err := Validator.Struct(req); err != nil {
		return err
	}
	if err := validateOrderTerms(req.Kind, req.Price, req.ProtectionPrice); err != nil {
		return fmt.Errorf("order %s: %w", req.ID, err)
	}

	// The order ID is the hash of the input nullifiers.
	allNullifiers := append(append([]string{}, req.CollateralNullifiers...), req.FeeNullifiers...)
	if expectedID := ComputeOrderID(allNullifiers); req.ID != expectedID {
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
	nativeAssetID, err := AssetID(NativeToken.Name)
	if err != nil {
		return err
	}

	// Cheap checks first (zcashd ordering): canonical field elements,
	// request-internal duplicate nullifier, spent set, anchor known.
	for _, h := range append([]string{req.Anchor, req.LockedCommitment,
		req.CollateralChangeCommitment, req.FeeChangeCommitment}, allNullifiers...) {
		if _, perr := ParseFrHex(h); perr != nil {
			return fmt.Errorf("non-canonical field element %q: %w", h, perr)
		}
	}
	seenNullifiers := make(map[string]struct{}, len(allNullifiers))
	for _, nf := range allNullifiers {
		if _, exists := seenNullifiers[nf]; exists {
			return fmt.Errorf("duplicate nullifier in request")
		}
		seenNullifiers[nf] = struct{}{}
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
	// [anchor, coll_nf_0, coll_nf_1, fee_nf_0, fee_nf_1,
	//  lock_asset_id, native_asset_id, locked_commitment, fee,
	//  cm_coll_change, cm_fee_change, collateral_price, side, bind].
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
	nfDec := make([]string, 4)
	for i, nf := range allNullifiers {
		nfDec[i], err = toDec(nf, fmt.Sprintf("nullifiers[%d]", i))
		if err != nil {
			return err
		}
	}
	lockedDec, err := toDec(req.LockedCommitment, "locked_commitment")
	if err != nil {
		return err
	}
	collChangeDec, err := toDec(req.CollateralChangeCommitment, "collateral_change_commitment")
	if err != nil {
		return err
	}
	feeChangeDec, err := toDec(req.FeeChangeCommitment, "fee_change_commitment")
	if err != nil {
		return err
	}
	side := sideSignal(req.Type)
	bind := sendOrderBind(ot.chainID, req)
	collateralPrice := req.Price
	if req.Kind == Market {
		collateralPrice = req.ProtectionPrice
	}
	signals := []string{
		anchorDec, nfDec[0], nfDec[1], nfDec[2], nfDec[3], assetID.String(),
		nativeAssetID.String(), lockedDec, fmt.Sprintf("%d", req.Fee), collChangeDec,
		feeChangeDec, collateralPrice.String(), side, bind.String(),
	}
	if err := VerifyGroth16(ot.sendOrderVK, req.ZkProof, signals); err != nil {
		return fmt.Errorf("send_order proof verification failed: %w", err)
	}

	// Publish nullifiers + mint both change notes atomically.
	cmCollateralChange, err := ParseFrHex(req.CollateralChangeCommitment)
	if err != nil {
		return fmt.Errorf("collateral_change_commitment: %w", err)
	}
	cmFeeChange, err := ParseFrHex(req.FeeChangeCommitment)
	if err != nil {
		return fmt.Errorf("fee_change_commitment: %w", err)
	}
	if _, err := ot.Account.ApplyPoolMutation(PoolMutation{
		Nullifiers: allNullifiers,
		NoteCms:    []*big.Int{cmCollateralChange, cmFeeChange},
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
		Kind:             req.Kind,
		Type:             req.Type,
		Subject:          req.Subject,
		Price:            req.Price,
		ProtectionPrice:  req.ProtectionPrice,
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

	matched, err := ot.matchOrder(order, uint64(ctx.Block.Height))
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

// ────────────────────── Writing: RegisterSettleAddr ──────────────────────

// RegisterSettleAddrRequest is the JSON payload for registering an MPC settle
// address. Each party sends its QUIC listen address so the counterparty can
// discover it on-chain.
// NOTE: This on-chain address exchange is temporary. In production, peer
// addresses will be exchanged via Tor or similar anonymous overlay network.
type RegisterSettleAddrRequest struct {
	OrderID          OrderID `json:"order_id"          validate:"required"`
	MatchOrderID     OrderID `json:"match_order_id"    validate:"required"`
	MatchRound       uint64  `json:"match_round"       validate:"required"`
	Addr             string  `json:"addr"              validate:"required"`
	EncryptionPubkey string  `json:"encryption_pubkey" validate:"required,len=64"`
	Signature        string  `json:"signature"         validate:"required"`
}

func SettleAddrSigningMessage(req *RegisterSettleAddrRequest) []byte {
	buf := make([]byte, 0, 192)
	for _, field := range []string{"invisibook-settle-addr-v2", string(req.OrderID),
		string(req.MatchOrderID), strconv.FormatUint(req.MatchRound, 10), req.Addr, req.EncryptionPubkey} {
		buf = appendSigningField(buf, field)
	}
	return buf
}

// RegisterSettleAddr stores the caller's QUIC address for MPC peer discovery.
func (ot *OrderBook) RegisterSettleAddr(ctx *context.WriteContext) error {
	ctx.SetLei(10)
	LogPayloadSize("RegisterSettleAddr", ctx.GetRequestBytes())

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
	if order.MatchRound != req.MatchRound {
		return fmt.Errorf("stale match round %d", req.MatchRound)
	}
	if _, err := hex.DecodeString(req.EncryptionPubkey); err != nil {
		return fmt.Errorf("invalid encryption_pubkey: %w", err)
	}
	if err := verifyOrderOwnerSignature(order, SettleAddrSigningMessage(req), req.Signature); err != nil {
		return err
	}

	entry := &SettleAddrScheme{
		OrderID:          string(req.OrderID),
		MatchOrderID:     string(req.MatchOrderID),
		MatchRound:       req.MatchRound,
		Addr:             req.Addr,
		EncryptionPubkey: req.EncryptionPubkey,
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
	ctx.JsonOk(map[string]any{"addr": entry.Addr, "encryption_pubkey": entry.EncryptionPubkey,
		"match_round": entry.MatchRound})
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

// matchOrder finds the counterparty for the incoming order.
//
// Crossing candidates follow conventional priority: market flag, best
// price, block height, fee, intra-block index, then order id. A market order
// has no execution price of its own; market/market therefore cannot match.
//
// If matched, both orders' Status is set to Matched and MatchOrder is set
// to each other.
func (ot *OrderBook) matchOrder(order *Order, matchHeight uint64) (*Order, error) {
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
		if !ordersCross(order, candidate) {
			continue
		}

		if bestMatch == nil {
			bestMatch = candidate
			continue
		}

		if betterCounter(candidate, bestMatch) {
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
	round := order.MatchRound
	if bestMatch.MatchRound > round {
		round = bestMatch.MatchRound
	}
	round++
	order.MatchRound = round
	bestMatch.MatchRound = round
	order.MatchHeight = matchHeight
	bestMatch.MatchHeight = matchHeight
	exec := matchExecutionPrice(order, bestMatch)
	order.ExecutionPrice = new(big.Int).Set(exec)
	bestMatch.ExecutionPrice = new(big.Int).Set(exec)

	if err := ot.db.Transaction(func(tx *gorm.DB) error {
		for _, o := range []*Order{order, bestMatch} {
			updates := map[string]interface{}{
				"status": int(Matched), "match_order": string(o.MatchOrder),
				"match_round": o.MatchRound, "match_height": o.MatchHeight,
				"execution_price": o.ExecutionPrice.String(),
			}
			if err := tx.Model(&OrderScheme{}).Where("id = ?", string(o.ID)).Updates(updates).Error; err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}

	return bestMatch, nil
}

func ordersCross(x, y *Order) bool {
	if x.Type == y.Type || (x.Kind == Market && y.Kind == Market) {
		return false
	}
	var buy, sell *Order
	if x.Type == Buy {
		buy, sell = x, y
	} else {
		buy, sell = y, x
	}
	buyCap, sellFloor := collateralPrice(buy), collateralPrice(sell)
	return buyCap != nil && sellFloor != nil && buyCap.Cmp(sellFloor) >= 0
}

func betterCounter(a, b *Order) bool {
	if a.Kind != b.Kind {
		return a.Kind == Market
	}
	if a.Kind == Limit {
		cmp := a.Price.Cmp(b.Price)
		if cmp != 0 {
			if a.Type == Sell {
				return cmp < 0
			}
			return cmp > 0
		}
	}
	if a.BlockHeight != b.BlockHeight {
		return a.BlockHeight < b.BlockHeight
	}
	if a.Fee != b.Fee {
		return a.Fee > b.Fee
	}
	if a.IntraBlockIndex != b.IntraBlockIndex {
		return a.IntraBlockIndex < b.IntraBlockIndex
	}
	return a.ID < b.ID
}

func matchExecutionPrice(x, y *Order) *big.Int {
	maker, taker := makerTakerOrder(x, y)
	if maker.Price != nil {
		return maker.Price
	}
	return taker.Price
}
