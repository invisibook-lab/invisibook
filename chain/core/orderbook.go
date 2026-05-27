package core

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
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
	settleLargerVK *CircuitVK
}

// NewOrderBook constructs the OrderBook tripod and registers its writings and
// readings. `cfg` must carry a valid SQLite DSN plus readable `SplitVKPath`
// and `SettleLargerVKPath`. DB init and VK loading panic on failure.
// Only the larger party submits a ZK proof; the smaller party confirms
// settlement without proof, so no settle_smaller VK is needed.
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
	ot := &OrderBook{
		Tripod:         tri,
		db:             InitOrderDB(cfg.DBPath, ParseGormLogLevel(cfg.DBLogLevel)),
		splitVK:        splitVK,
		settleLargerVK: settleLargerVK,
	}
	ot.SetWritings(ot.SendOrder, ot.CompareOrders, ot.SettleOrders, ot.RegisterSettleAddr)
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
	// For buy orders in split mode: the actual cash commitment (poseidon(usdt_total, r_cash)).
	// Split proof and locked cash use this instead of Amount (which stores the token1 qty commitment).
	// When empty, falls back to Amount (sell orders or no-split mode).
	LockedCommitment CipherText `json:"locked_commitment,omitempty"`
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

// ────────────────────── Writing: CompareOrders ──────────────────────

// SettleSide is which side of the asymmetric settle protocol a leg is on.
// "larger" → has change cash + cross-leg ratio check (settle_larger circuit).
// "smaller" → fully fills with no change (settle_smaller circuit).
type SettleSide string

const (
	SideLarger SettleSide = "larger"
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

// MpcShareData carries one party's authenticated SPDZ share produced by the
// off-chain MPC settle protocol. Both parties' shares are combined on-chain to
// verify the MAC relationship: (mac_A + mac_B) == (delta_A + delta_B) * (share_A + share_B).
type MpcShareData struct {
	CmpShare      string `json:"cmp_share"       validate:"required"`
	CmpMac        string `json:"cmp_mac"         validate:"required"`
	RSmallerShare string `json:"r_smaller_share"  validate:"required"`
	RSmallerMac   string `json:"r_smaller_mac"    validate:"required"`
	MacKeyShare   string `json:"mac_key_share"    validate:"required"`
}

// CompareOrderRequest is a per-party MPC share submission for the comparison
// phase. Each party submits their order ID, the counterparty's order ID, and
// their MPC share. When both arrive, the chain verifies the MAC, reconstructs
// cmp and r_smaller, and sets both orders to Settling.
type CompareOrderRequest struct {
	OrderID      OrderID      `json:"order_id"       validate:"required"`
	MatchOrderID OrderID      `json:"match_order_id" validate:"required"`
	MpcShare     MpcShareData `json:"mpc_share"      validate:"required"`
}

// CompareOrders accepts a per-party MPC share submission. When both parties
// have submitted, the chain verifies the MAC, reconstructs the comparison
// result and r_smaller, then sets both orders to Settling status.
func (ot *OrderBook) CompareOrders(ctx *context.WriteContext) error {
	ctx.SetLei(100)

	req := new(CompareOrderRequest)
	if err := ctx.BindJson(req); err != nil {
		return err
	}
	if err := Validator.Struct(req); err != nil {
		return err
	}

	// Retrieve and validate both orders are a matched pair.
	myOrder, err := ot.GetOrder(req.OrderID)
	if err != nil {
		return fmt.Errorf("order %s not found: %w", req.OrderID, err)
	}
	matchOrder, err := ot.GetOrder(req.MatchOrderID)
	if err != nil {
		return fmt.Errorf("order %s not found: %w", req.MatchOrderID, err)
	}
	if myOrder.Status != Matched {
		return fmt.Errorf("order %s is not Matched (current: %s)", myOrder.ID, myOrder.Status.String())
	}
	if matchOrder.Status != Matched {
		return fmt.Errorf("order %s is not Matched (current: %s)", matchOrder.ID, matchOrder.Status.String())
	}
	if myOrder.MatchOrder != matchOrder.ID || matchOrder.MatchOrder != myOrder.ID {
		return fmt.Errorf("orders %s and %s are not matched with each other", myOrder.ID, matchOrder.ID)
	}

	// Prevent duplicate submission from the same party.
	if _, err := ot.GetCompareSubmission(req.OrderID); err == nil {
		return fmt.Errorf("order %s has already submitted a compare request", req.OrderID)
	}

	// Check whether the counterparty has already submitted.
	counterSub, err := ot.GetCompareSubmission(req.MatchOrderID)
	if err != nil {
		// Counterparty not yet submitted — store this submission and return.
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("failed to check counterparty compare submission: %w", err)
		}
		shareJSON, _ := json.Marshal(req.MpcShare)
		sub := &CompareSubmissionScheme{
			OrderID:      string(req.OrderID),
			MatchOrderID: string(req.MatchOrderID),
			MpcShareJSON: string(shareJSON),
		}
		if err := ot.SaveCompareSubmission(sub); err != nil {
			return fmt.Errorf("failed to store compare submission: %w", err)
		}
		ctx.EmitStringEvent("compare submission stored for order %s, waiting for counterparty %s", req.OrderID, req.MatchOrderID)
		return nil
	}

	// Both parties have now submitted — verify MAC and reconstruct values.
	var counterShare MpcShareData
	if err := json.Unmarshal([]byte(counterSub.MpcShareJSON), &counterShare); err != nil {
		return fmt.Errorf("failed to parse counterparty MPC share: %w", err)
	}

	// MPC MAC verification.
	if err := VerifyMpcMac(&req.MpcShare, &counterShare); err != nil {
		return fmt.Errorf("MPC MAC verification failed: %w", err)
	}

	// Reconstruct cmp and validate it is 0 or 1.
	cmp, err := ReconstructCmp(&req.MpcShare, &counterShare)
	if err != nil {
		return fmt.Errorf("failed to reconstruct cmp: %w", err)
	}
	if err := ValidateCmp(&cmp); err != nil {
		return err
	}

	// Determine which order is smaller based on cmp.
	// MPC convention: party0 = Buy side, party1 = Sell side.
	// cmp=1 means v_buy >= v_sell, so Sell side is smaller.
	// cmp=0 means v_buy < v_sell, so Buy side is smaller.
	var one fr.Element
	one.SetOne()
	cmpIsOne := cmp == one

	// Map order types to determine smaller side.
	myIsSmaller := false
	matchIsSmaller := false
	if cmpIsOne {
		// Sell side is smaller
		if myOrder.Type == Sell {
			myIsSmaller = true
		} else {
			matchIsSmaller = true
		}
	} else {
		// Buy side is smaller
		if myOrder.Type == Buy {
			myIsSmaller = true
		} else {
			matchIsSmaller = true
		}
	}

	// Update both orders to Settling.
	if err := ot.UpdateOrderStatus(myOrder.ID, Settling); err != nil {
		return fmt.Errorf("failed to update order %s to Settling: %w", myOrder.ID, err)
	}
	if err := ot.UpdateOrderComparison(myOrder.ID, myIsSmaller); err != nil {
		return fmt.Errorf("failed to update comparison for order %s: %w", myOrder.ID, err)
	}
	if err := ot.UpdateOrderStatus(matchOrder.ID, Settling); err != nil {
		return fmt.Errorf("failed to update order %s to Settling: %w", matchOrder.ID, err)
	}
	if err := ot.UpdateOrderComparison(matchOrder.ID, matchIsSmaller); err != nil {
		return fmt.Errorf("failed to update comparison for order %s: %w", matchOrder.ID, err)
	}

	// Clean up pending compare submissions.
	_ = ot.DeleteCompareSubmission(req.OrderID)
	_ = ot.DeleteCompareSubmission(req.MatchOrderID)

	ctx.EmitStringEvent("orders compared: %s <-> %s (cmp=%s)", myOrder.ID, matchOrder.ID, cmp.String())
	return nil
}

// ────────────────────── Writing: SettleOrders ──────────────────────

// SettleOrderRequest is a per-party settlement submission. The larger party
// (IsSmaller=false) must include a ZK `Leg`; the smaller party
// (IsSmaller=true) confirms settlement without proof (Leg is nil).
type SettleOrderRequest struct {
	OrderID      OrderID        `json:"order_id"       validate:"required"`
	MatchOrderID OrderID        `json:"match_order_id" validate:"required"`
	Leg          *SettleTokenLeg `json:"leg,omitempty"`
}

// SettleOrders accepts a per-party settlement submission. The larger party
// (IsSmaller=false) must include a ZK Leg; the smaller party (IsSmaller=true)
// confirms without proof (Leg is nil). When both arrive, the chain verifies
// only the larger party's proof, spends locked Cash, mints outputs, and marks
// both orders Done.
func (ot *OrderBook) SettleOrders(ctx *context.WriteContext) error {
	ctx.SetLei(100)

	req := new(SettleOrderRequest)
	if err := ctx.BindJson(req); err != nil {
		return err
	}
	if err := Validator.Struct(req); err != nil {
		return err
	}

	// Retrieve and validate both orders are Settling and mutually reference each other.
	myOrder, err := ot.GetOrder(req.OrderID)
	if err != nil {
		return fmt.Errorf("order %s not found: %w", req.OrderID, err)
	}
	matchOrder, err := ot.GetOrder(req.MatchOrderID)
	if err != nil {
		return fmt.Errorf("order %s not found: %w", req.MatchOrderID, err)
	}
	if myOrder.Status != Settling {
		return fmt.Errorf("order %s is not Settling (current: %s)", myOrder.ID, myOrder.Status.String())
	}
	if matchOrder.Status != Settling {
		return fmt.Errorf("order %s is not Settling (current: %s)", matchOrder.ID, matchOrder.Status.String())
	}
	if myOrder.MatchOrder != matchOrder.ID || matchOrder.MatchOrder != myOrder.ID {
		return fmt.Errorf("orders %s and %s are not matched with each other", myOrder.ID, matchOrder.ID)
	}

	// Validate leg requirement: larger must provide a leg, smaller must not.
	if !myOrder.IsSmaller && req.Leg == nil {
		return fmt.Errorf("order %s is the larger party and must provide a settlement leg", myOrder.ID)
	}
	if myOrder.IsSmaller && req.Leg != nil {
		return fmt.Errorf("order %s is the smaller party and should not provide a settlement leg", myOrder.ID)
	}

	// Validate side assignment if leg is provided.
	if req.Leg != nil && req.Leg.Side != SideLarger {
		return fmt.Errorf("order %s submitted side=%s but only larger is accepted",
			myOrder.ID, req.Leg.Side)
	}

	// Prevent duplicate submission from the same party.
	if _, err := ot.GetSettleSubmission(req.OrderID); err == nil {
		return fmt.Errorf("order %s has already submitted a settle request", req.OrderID)
	}

	// Check whether the counterparty has already submitted.
	counterSub, err := ot.GetSettleSubmission(req.MatchOrderID)
	if err != nil {
		// Counterparty not yet submitted — store this submission and return.
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("failed to check counterparty settle submission: %w", err)
		}
		legJSON := ""
		if req.Leg != nil {
			b, _ := json.Marshal(req.Leg)
			legJSON = string(b)
		}
		sub := &SettleSubmissionScheme{
			OrderID:      string(req.OrderID),
			MatchOrderID: string(req.MatchOrderID),
			LegJSON:      legJSON,
		}
		if err := ot.SaveSettleSubmission(sub); err != nil {
			return fmt.Errorf("failed to store settle submission: %w", err)
		}
		ctx.EmitStringEvent("settle submission stored for order %s, waiting for counterparty %s", req.OrderID, req.MatchOrderID)
		return nil
	}

	// Both parties have now submitted — identify larger/smaller and get the leg.
	var largerLeg *SettleTokenLeg
	var largerOrder, smallerOrder *Order

	if myOrder.IsSmaller {
		// I am smaller; counterparty (larger) stored their leg.
		smallerOrder = myOrder
		largerOrder = matchOrder
		if counterSub.LegJSON == "" {
			return fmt.Errorf("counterparty %s is larger but has no stored leg", matchOrder.ID)
		}
		largerLeg = new(SettleTokenLeg)
		if err := json.Unmarshal([]byte(counterSub.LegJSON), largerLeg); err != nil {
			return fmt.Errorf("failed to parse counterparty leg: %w", err)
		}
	} else {
		// I am larger; my leg is in the request.
		largerOrder = myOrder
		smallerOrder = matchOrder
		largerLeg = req.Leg
	}

	// Price agreement check.
	expectedPrice := myOrder.Price.Uint64()
	if myOrder.Price.Uint64() != matchOrder.Price.Uint64() {
		return fmt.Errorf("matched orders %s and %s disagree on price", myOrder.ID, matchOrder.ID)
	}

	// Validate the larger leg fields.
	if largerLeg.MyMatchCommitment == "" || largerLeg.OtherMatchCommitment == "" || largerLeg.ChangeCommitment == "" {
		return fmt.Errorf("larger leg missing required commitment field(s)")
	}
	if largerLeg.Price != expectedPrice {
		return fmt.Errorf("larger leg price %d != order price %d", largerLeg.Price, expectedPrice)
	}
	isT2 := largerLeg.Token == largerOrder.Subject.Token2
	if largerLeg.IsToken2Sender != isT2 {
		return fmt.Errorf("larger leg IsToken2Sender %v inconsistent with token", largerLeg.IsToken2Sender)
	}

	// Verify the larger leg's ZK proof.
	signals, err := buildSettleLargerPublicSignals(largerLeg, largerOrder, ot.Account)
	if err != nil {
		return fmt.Errorf("larger leg public signals: %w", err)
	}
	if err := VerifyGroth16(ot.settleLargerVK, largerLeg.ZkProof, signals); err != nil {
		return fmt.Errorf("larger leg proof verification failed: %w", err)
	}

	// Determine the smaller party's locked token.
	if len(smallerOrder.InputCashIDs) == 0 {
		return fmt.Errorf("order %s has no locked input cash", smallerOrder.ID)
	}
	smallerFirstCash, err := ot.Account.GetCash(smallerOrder.InputCashIDs[0])
	if err != nil {
		return fmt.Errorf("locked cash %s not found: %w", smallerOrder.InputCashIDs[0], err)
	}
	smallerToken := smallerFirstCash.Token

	// All verification passed — mutate state.
	settleBy := fmt.Sprintf("settle:%s:%s", myOrder.ID[:8], matchOrder.ID[:8])
	if err := ot.Account.SpendCash(myOrder.InputCashIDs, settleBy); err != nil {
		return fmt.Errorf("failed to spend cash for order %s: %w", myOrder.ID, err)
	}
	if err := ot.Account.SpendCash(matchOrder.InputCashIDs, settleBy); err != nil {
		return fmt.Errorf("failed to spend cash for order %s: %w", matchOrder.ID, err)
	}

	// Mint recv from larger leg: smaller party receives larger's token.
	recvForSmaller := &Cash{
		ID:      computeCashID(largerLeg.RecvPubkey, largerLeg.Token, CipherText(largerLeg.RecvCommitment)),
		Pubkey:  largerLeg.RecvPubkey,
		Token:   largerLeg.Token,
		Amount:  CipherText(largerLeg.RecvCommitment),
		ZkProof: largerLeg.ZkProof,
		Status:  Active,
	}
	if err := ot.Account.CreateCash(recvForSmaller); err != nil {
		return fmt.Errorf("failed to create recv cash for smaller party: %w", err)
	}

	// Mint change from larger leg (if non-zero).
	if largerLeg.ChangeCommitment != PoseidonZeroCommitmentHex {
		changePubkey := largerLeg.ChangePubkey
		if changePubkey == "" {
			changePubkey = largerOrder.Pubkey
		}
		changeCash := &Cash{
			ID:      computeCashID(changePubkey, largerLeg.Token, CipherText(largerLeg.ChangeCommitment)),
			Pubkey:  changePubkey,
			Token:   largerLeg.Token,
			Amount:  CipherText(largerLeg.ChangeCommitment),
			ZkProof: largerLeg.ZkProof,
			Status:  Active,
		}
		if err := ot.Account.CreateCash(changeCash); err != nil {
			return fmt.Errorf("failed to create change cash: %w", err)
		}
	}

	// Mint recv for larger party from smaller's token. The commitment is the
	// larger leg's `OtherMatchCommitment`, which is proven correct by the
	// larger party's ZK proof. The larger party knows the match random
	// (derived via ECDH) so they can later spend this cash.
	recvForLarger := &Cash{
		ID:      computeCashID(largerOrder.Pubkey, smallerToken, CipherText(largerLeg.OtherMatchCommitment)),
		Pubkey:  largerOrder.Pubkey,
		Token:   smallerToken,
		Amount:  CipherText(largerLeg.OtherMatchCommitment),
		ZkProof: largerLeg.ZkProof,
		Status:  Active,
	}
	if err := ot.Account.CreateCash(recvForLarger); err != nil {
		return fmt.Errorf("failed to create recv cash for larger party: %w", err)
	}

	// Mark both orders as Done.
	if err := ot.UpdateOrderStatus(myOrder.ID, Done); err != nil {
		return fmt.Errorf("failed to settle order %s: %w", myOrder.ID, err)
	}
	if err := ot.UpdateOrderStatus(matchOrder.ID, Done); err != nil {
		return fmt.Errorf("failed to settle order %s: %w", matchOrder.ID, err)
	}

	// Clean up pending settle submissions.
	_ = ot.DeleteSettleSubmission(req.OrderID)
	_ = ot.DeleteSettleSubmission(req.MatchOrderID)

	// Clean up settle address entries.
	_ = ot.DeleteSettleAddr(req.OrderID)
	_ = ot.DeleteSettleAddr(req.MatchOrderID)

	ctx.EmitStringEvent("orders settled: %s <-> %s", myOrder.ID, matchOrder.ID)
	return nil
}

// buildSettleLargerPublicSignals lays out 8 signals matching settle_larger.circom's
// `public [my_match_commitment, other_match_commitment, price, is_token2_sender,
//
//	input_hashes, change_commitment, counterparty_recv_commitment]`.
//
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
