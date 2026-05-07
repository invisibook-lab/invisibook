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
	Account         *Account `tripod:"account"`
	db              *gorm.DB
	splitVK         *CircuitVK
	settleLargerVK  *CircuitVK
	settleSmallerVK *CircuitVK
}

// NewOrderBook constructs the OrderBook tripod and registers its writings and
// readings. `cfg` must carry a valid SQLite DSN plus readable
// `SplitVKPath` / `SettleLargerVKPath` / `SettleSmallerVKPath`. DB init and
// VK loading panic on failure — the chain will not start without all three
// circuits' verifying keys in memory.
func NewOrderBook(cfg *OrderBookConfig) *OrderBook {
	tri := tripod.NewTripodWithName("orderbook")
	splitVK, err := LoadVK("split", cfg.SplitVKPath)
	if err != nil {
		panic(fmt.Sprintf("loading split VK: %v", err))
	}
	settleLargerVK, err := LoadVK("settle_larger", cfg.SettleLargerVKPath)
	if err != nil {
		panic(fmt.Sprintf("loading settle_larger VK: %v", err))
	}
	settleSmallerVK, err := LoadVK("settle_smaller", cfg.SettleSmallerVKPath)
	if err != nil {
		panic(fmt.Sprintf("loading settle_smaller VK: %v", err))
	}
	ot := &OrderBook{
		Tripod:          tri,
		db:              InitOrderDB(cfg.DBPath),
		splitVK:         splitVK,
		settleLargerVK:  settleLargerVK,
		settleSmallerVK: settleSmallerVK,
	}
	ot.SetWritings(ot.SendOrder, ot.SettleOrder)
	ot.SetReadings(ot.QueryOrders)
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
// pre-computes the order ID (SHA-256 over input cash IDs), signs it with their
// ed25519 key, and lists the input Cash they want to lock or split.
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
	Signature    string            `json:"signature"      validate:"required"` // ed25519 sig over order ID bytes (128-char hex)
	InputCashIDs []string          `json:"input_cash_ids" validate:"required,min=1,max=2"`
	HandlingFee  []string          `json:"handling_fee"   validate:"required,min=1"` // must be plaintext.
	Change       *CashChangeOutput `json:"change,omitempty"`
	ZkProof      string            `json:"zk_proof,omitempty"` // required when Change != nil
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

	// Validate that the client-submitted ID is the correct hash of the input cash IDs.
	if expectedID := ComputeOrderID(req.InputCashIDs); req.ID != expectedID {
		return fmt.Errorf("order ID mismatch: got %s, expected %s", req.ID, expectedID)
	}

	// Verify the sender's ed25519 signature over the order ID bytes.
	pubkeyBytes, err := hex.DecodeString(req.Pubkey)
	if err != nil || len(pubkeyBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid pubkey: must be %d-byte ed25519 key as 64-char hex", ed25519.PublicKeySize)
	}
	sigBytes, err := hex.DecodeString(req.Signature)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature: must be %d-byte ed25519 sig as 128-char hex", ed25519.SignatureSize)
	}
	if !ed25519.Verify(pubkeyBytes, []byte(req.ID), sigBytes) {
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
		// where outputs are [Amount (locked), Change.Amount].
		if req.ZkProof == "" {
			return fmt.Errorf("split mode requires zk_proof")
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
		lockedDec, err := HexToDecimal(string(req.Amount))
		if err != nil {
			return fmt.Errorf("invalid locked Amount: %w", err)
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
		lockedCashID := computeCashID(req.Pubkey, expectedToken, req.Amount)
		if err := ot.Account.CreateCash(&Cash{
			ID: lockedCashID, Pubkey: req.Pubkey, Token: expectedToken,
			Amount: req.Amount, ZkProof: req.ZkProof, Status: Locked, By: string(req.ID),
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

// ────────────────────── Writing: SettleOrder ──────────────────────

// SettleSide is which side of the asymmetric settle protocol a leg is on.
// "larger" → has change cash + cross-leg ratio check (settle_larger circuit).
// "smaller" → fully fills with no change (settle_smaller circuit).
type SettleSide string

const (
	SideLarger  SettleSide = "larger"
	SideSmaller SettleSide = "smaller"
)

// SettleTokenLeg is one half of a settlement: the side responsible for moving
// `Token` from one party to the other. `Side` selects the verifier and which
// fields are required (larger fields vs smaller fields). Each side produces its
// own proof; chain pairs them via cross-leg match-commitment equality.
type SettleTokenLeg struct {
	Side  SettleSide `json:"side"  validate:"required,oneof=larger smaller"`
	Token TokenID    `json:"token" validate:"required"`

	// Required when Side == "larger":
	MyMatchCommitment    string `json:"my_match_commitment,omitempty"    validate:"omitempty,len=64"`
	OtherMatchCommitment string `json:"other_match_commitment,omitempty" validate:"omitempty,len=64"`
	Price                uint64 `json:"price,omitempty"`
	IsToken2Sender       bool   `json:"is_token2_sender,omitempty"`
	ChangeCommitment     string `json:"change_commitment,omitempty"      validate:"omitempty,len=64"`
	ChangePubkey         string `json:"change_pubkey,omitempty"`

	// Required when Side == "smaller":
	MatchCommitment string `json:"match_commitment,omitempty" validate:"omitempty,len=64"`

	// Required for both sides:
	RecvCommitment string `json:"recv_commitment" validate:"required,len=64"`
	RecvPubkey     string `json:"recv_pubkey"     validate:"required,len=64"`
	ZkProof        string `json:"zk_proof"        validate:"required"`
}

// SettleOrderRequest carries one leg per token group (always 2 legs).
type SettleOrderRequest struct {
	OrderIDs []OrderID        `json:"order_ids" validate:"required,len=2"`
	Legs     []SettleTokenLeg `json:"legs"      validate:"required,len=2,dive"`
}

// SettleOrder verifies each leg's zk proof, enforces the cross-leg
// match-commitment equality (replaces an on-chain ratio check that fill is
// hidden from), spends the locked Cash of both orders, mints the output Cash
// per leg, and marks both orders Done.
func (ot *OrderBook) SettleOrder(ctx *context.WriteContext) error {
	ctx.SetLei(100)

	req := new(SettleOrderRequest)
	if err := ctx.BindJson(req); err != nil {
		return err
	}
	if err := Validator.Struct(req); err != nil {
		return err
	}

	// Retrieve both orders and validate they are a matched pair
	order0, err := ot.GetOrder(req.OrderIDs[0])
	if err != nil {
		return fmt.Errorf("order %s not found: %w", req.OrderIDs[0], err)
	}
	order1, err := ot.GetOrder(req.OrderIDs[1])
	if err != nil {
		return fmt.Errorf("order %s not found: %w", req.OrderIDs[1], err)
	}
	if order0.Status != Matched {
		return fmt.Errorf("order %s is not Matched (current: %s)", order0.ID, order0.Status.String())
	}
	if order1.Status != Matched {
		return fmt.Errorf("order %s is not Matched (current: %s)", order1.ID, order1.Status.String())
	}
	if order0.MatchOrder != order1.ID || order1.MatchOrder != order0.ID {
		return fmt.Errorf("orders %s and %s are not matched with each other", order0.ID, order1.ID)
	}
	expectedPrice := order0.Price.Uint64()
	if order0.Price.Uint64() != order1.Price.Uint64() {
		return fmt.Errorf("matched orders %s and %s disagree on price", order0.ID, order1.ID)
	}

	// Index each leg's matched order (the order whose locked input is in this leg's token).
	// One order locks Token1 (Sell side) or Token2 (Buy side); chain looks up which by token.
	orderForLeg := map[TokenID]*Order{}
	for _, ord := range []*Order{order0, order1} {
		if len(ord.InputCashIDs) == 0 {
			return fmt.Errorf("order %s has no locked input cash", ord.ID)
		}
		// Peek at the first locked cash to identify the order's lock token.
		// All input cashes of an order share the same Token (enforced at SendOrder time).
		firstCash, err := ot.Account.GetCash(ord.InputCashIDs[0])
		if err != nil {
			return fmt.Errorf("locked cash %s not found: %w", ord.InputCashIDs[0], err)
		}
		orderForLeg[firstCash.Token] = ord
	}

	// Verify each leg's proof and collect cross-leg match commitments.
	var (
		largerLeg, smallerLeg                 *SettleTokenLeg
		largerOrder, smallerOrder             *Order
		largerCounterpartyMatchCommitmentHex  string // = larger.OtherMatchCommitment (the smaller-side fill commitment)
		smallerOwnMatchCommitmentHex          string // = smaller.MatchCommitment
	)
	for i := range req.Legs {
		leg := &req.Legs[i]
		ord, ok := orderForLeg[leg.Token]
		if !ok {
			return fmt.Errorf("leg token %s does not match either order's locked token", leg.Token)
		}

		// Build per-leg public-input vector + verify against the right VK.
		switch leg.Side {
		case SideLarger:
			if leg.MyMatchCommitment == "" || leg.OtherMatchCommitment == "" || leg.ChangeCommitment == "" {
				return fmt.Errorf("larger leg %s missing required commitment field(s)", leg.Token)
			}
			if leg.Price != expectedPrice {
				return fmt.Errorf("larger leg %s price %d != order price %d", leg.Token, leg.Price, expectedPrice)
			}
			// Validate IsToken2Sender flag matches Token (Token1 sender → false, Token2 sender → true)
			isT2 := leg.Token == ord.Subject.Token2
			if leg.IsToken2Sender != isT2 {
				return fmt.Errorf("larger leg %s IsToken2Sender %v inconsistent with token", leg.Token, leg.IsToken2Sender)
			}
			signals, err := buildSettleLargerPublicSignals(leg, ord, ot.Account)
			if err != nil {
				return fmt.Errorf("larger leg %s public signals: %w", leg.Token, err)
			}
			if err := VerifyGroth16(ot.settleLargerVK, leg.ZkProof, signals); err != nil {
				return fmt.Errorf("larger leg %s proof verification failed: %w", leg.Token, err)
			}
			if largerLeg != nil {
				return fmt.Errorf("two larger legs but the design requires at most two with side != larger")
			}
			largerLeg = leg
			largerOrder = ord
			largerCounterpartyMatchCommitmentHex = leg.OtherMatchCommitment

		case SideSmaller:
			if leg.MatchCommitment == "" {
				return fmt.Errorf("smaller leg %s missing match_commitment", leg.Token)
			}
			signals, err := buildSettleSmallerPublicSignals(leg, ord, ot.Account)
			if err != nil {
				return fmt.Errorf("smaller leg %s public signals: %w", leg.Token, err)
			}
			if err := VerifyGroth16(ot.settleSmallerVK, leg.ZkProof, signals); err != nil {
				return fmt.Errorf("smaller leg %s proof verification failed: %w", leg.Token, err)
			}
			if smallerLeg != nil {
				return fmt.Errorf("two smaller legs but each side must own one token group")
			}
			smallerLeg = leg
			smallerOrder = ord
			smallerOwnMatchCommitmentHex = leg.MatchCommitment
		}
	}

	// Cross-leg consistency: the larger side's commitment to the smaller side's
	// fill must equal the smaller side's own match commitment. This is the
	// chain's substitute for an on-chain `fill_t2 == fill_t1 * price` check
	// (which can't be done because both fills are private).
	if largerLeg != nil && smallerLeg != nil {
		if largerCounterpartyMatchCommitmentHex != smallerOwnMatchCommitmentHex {
			return fmt.Errorf(
				"cross-leg mismatch: larger.other_match_commitment != smaller.match_commitment",
			)
		}
	} else {
		// Both legs are "larger" (exact-fill case where neither side has change=0 and fill==locked
		// for both). Each leg's other_match_commitment must equal the OTHER leg's my_match_commitment.
		if req.Legs[0].Side != SideLarger || req.Legs[1].Side != SideLarger {
			return fmt.Errorf("legs must be one larger + one smaller, or both larger")
		}
		if req.Legs[0].MyMatchCommitment != req.Legs[1].OtherMatchCommitment ||
			req.Legs[1].MyMatchCommitment != req.Legs[0].OtherMatchCommitment {
			return fmt.Errorf("dual-larger cross-leg mismatch: my/other commitments must mirror across legs")
		}
	}
	_, _ = largerOrder, smallerOrder // available for future telemetry; silence unused

	// All proofs verified — mutate state.
	settleBy := fmt.Sprintf("settle:%s:%s", order0.ID[:8], order1.ID[:8])
	if err := ot.Account.SpendCash(order0.InputCashIDs, settleBy); err != nil {
		return fmt.Errorf("failed to spend cash for order %s: %w", order0.ID, err)
	}
	if err := ot.Account.SpendCash(order1.InputCashIDs, settleBy); err != nil {
		return fmt.Errorf("failed to spend cash for order %s: %w", order1.ID, err)
	}

	// Mint outputs per leg: counterparty receive + (larger only) change
	for i := range req.Legs {
		leg := &req.Legs[i]
		recvCash := &Cash{
			ID:      computeCashID(leg.RecvPubkey, leg.Token, CipherText(leg.RecvCommitment)),
			Pubkey:  leg.RecvPubkey,
			Token:   leg.Token,
			Amount:  CipherText(leg.RecvCommitment),
			ZkProof: leg.ZkProof,
			Status:  Active,
		}
		if err := ot.Account.CreateCash(recvCash); err != nil {
			return fmt.Errorf("failed to create recv cash for leg %s: %w", leg.Token, err)
		}
		if leg.Side == SideLarger && leg.ChangeCommitment != PoseidonZeroCommitmentHex {
			senderOrder := orderForLeg[leg.Token]
			changePubkey := leg.ChangePubkey
			if changePubkey == "" {
				changePubkey = senderOrder.Pubkey
			}
			changeCash := &Cash{
				ID:      computeCashID(changePubkey, leg.Token, CipherText(leg.ChangeCommitment)),
				Pubkey:  changePubkey,
				Token:   leg.Token,
				Amount:  CipherText(leg.ChangeCommitment),
				ZkProof: leg.ZkProof,
				Status:  Active,
			}
			if err := ot.Account.CreateCash(changeCash); err != nil {
				return fmt.Errorf("failed to create change cash for leg %s: %w", leg.Token, err)
			}
		}
	}

	// Mark both orders as Done
	if err := ot.UpdateOrderStatus(order0.ID, Done); err != nil {
		return fmt.Errorf("failed to settle order %s: %w", order0.ID, err)
	}
	if err := ot.UpdateOrderStatus(order1.ID, Done); err != nil {
		return fmt.Errorf("failed to settle order %s: %w", order1.ID, err)
	}

	ctx.EmitStringEvent("orders settled: %s <-> %s, %d legs", order0.ID, order1.ID, len(req.Legs))
	return nil
}

// buildSettleLargerPublicSignals lays out 8 signals matching settle_larger.circom's
// `public [my_match_commitment, other_match_commitment, price, is_token2_sender,
//          input_hashes, change_commitment, counterparty_recv_commitment]`.
// `input_hashes` is N=2; chain pads with PoseidonZeroCommitment when the order
// has fewer locked cashes (the prover does the same — see wallet.rs::pad_to).
func buildSettleLargerPublicSignals(leg *SettleTokenLeg, ord *Order, acc *Account) ([]string, error) {
	myMatchDec, err := HexToDecimal(leg.MyMatchCommitment)
	if err != nil {
		return nil, err
	}
	otherMatchDec, err := HexToDecimal(leg.OtherMatchCommitment)
	if err != nil {
		return nil, err
	}
	changeDec, err := HexToDecimal(leg.ChangeCommitment)
	if err != nil {
		return nil, err
	}
	recvDec, err := HexToDecimal(leg.RecvCommitment)
	if err != nil {
		return nil, err
	}
	inputHashesDec, err := lockedInputHashesPadded(ord, acc, 2, leg.Token)
	if err != nil {
		return nil, err
	}
	isT2 := "0"
	if leg.IsToken2Sender {
		isT2 = "1"
	}
	signals := []string{
		myMatchDec,
		otherMatchDec,
		fmt.Sprintf("%d", leg.Price),
		isT2,
	}
	signals = append(signals, inputHashesDec...)
	signals = append(signals, changeDec, recvDec)
	return signals, nil
}

// buildSettleSmallerPublicSignals lays out 4 signals matching
// settle_smaller.circom's `public [match_commitment, input_hashes,
// counterparty_recv_commitment]`.
func buildSettleSmallerPublicSignals(leg *SettleTokenLeg, ord *Order, acc *Account) ([]string, error) {
	matchDec, err := HexToDecimal(leg.MatchCommitment)
	if err != nil {
		return nil, err
	}
	recvDec, err := HexToDecimal(leg.RecvCommitment)
	if err != nil {
		return nil, err
	}
	inputHashesDec, err := lockedInputHashesPadded(ord, acc, 2, leg.Token)
	if err != nil {
		return nil, err
	}
	signals := []string{matchDec}
	signals = append(signals, inputHashesDec...)
	signals = append(signals, recvDec)
	return signals, nil
}

// lockedInputHashesPadded fetches each locked input cash for `ord`, asserts
// it's the expected token, and returns N decimal-string commitments (pad with
// PoseidonZeroCommitment when ord has fewer than N inputs).
func lockedInputHashesPadded(ord *Order, acc *Account, n int, expectedToken TokenID) ([]string, error) {
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		var hex string
		if i < len(ord.InputCashIDs) {
			cash, err := acc.GetCash(ord.InputCashIDs[i])
			if err != nil {
				return nil, fmt.Errorf("locked cash %s not found: %w", ord.InputCashIDs[i], err)
			}
			if cash.Token != expectedToken {
				return nil, fmt.Errorf("locked cash %s token %s != expected %s", cash.ID, cash.Token, expectedToken)
			}
			hex = string(cash.Amount)
		} else {
			hex = PoseidonZeroCommitmentHex
		}
		dec, err := HexToDecimal(hex)
		if err != nil {
			return nil, fmt.Errorf("input commitment hex at slot %d: %w", i, err)
		}
		out = append(out, dec)
	}
	return out, nil
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
