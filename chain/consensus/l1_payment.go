package consensus

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	"github.com/yu-org/yu/common"
	"github.com/yu-org/yu/core/keypair"
)

// mockPayerAddr stands in for the miner's L1 address until a real CKB client
// derives it from the miner's public key.
// TODO: derive the payer address from the miner pubkey once CKB is wired in.
const mockPayerAddr = "0xMOCK_PAYER"

// ErrPaymentNotFound reports that no record matching a declared payment could
// be found on L1. Callers wrap it with the offending transaction hash.
var ErrPaymentNotFound = errors.New("no matching payment record on L1")

// MinerPubkeyHex renders a miner's compressed secp256k1 public key as hex.
// The raw 33-byte encoding is used rather than yu's BytesWithType, whose
// secp256k1 branch tags the key as sr25519, and because it is exactly the
// byte string CKB hashes into a lock's args.
func MinerPubkeyHex(pubkey keypair.PubKey) string {
	return hex.EncodeToString(pubkey.Bytes())
}

// PaymentDeclaration is a miner's statement that it paid `Amount` of L1 token
// for the L2 block at `BlockHeight`, evidenced by the L1 transaction `TxHash`.
// One declaration binds exactly one height.
type PaymentDeclaration struct {
	// BlockHeight is the L2 block height this payment competes for.
	BlockHeight common.BlockNum `json:"block_height"`
	// Amount is the payment amount as a decimal string, e.g. "5000".
	Amount string `json:"amount"`
	// TxHash is the L1 transaction hash serving as proof of payment.
	TxHash string `json:"tx_hash"`
}

// L1PaymentInput is a declaration that passed validation, held by the
// PaymentBook until the consensus loop reaches its height.
type L1PaymentInput struct {
	// BlockHeight is the L2 block height this payment competes for.
	BlockHeight common.BlockNum
	// Amount is the parsed payment amount.
	Amount *big.Int
	// TxHash is the L1 transaction hash serving as proof of payment.
	TxHash string
}

// RejectedDeclaration explains why one declaration in a batch was refused.
type RejectedDeclaration struct {
	BlockHeight common.BlockNum `json:"block_height"`
	Error       string          `json:"error"`
}

// PaymentBook holds the miner's per-height payment declarations until the
// consensus loop consumes them.
//
// Declarations are keyed by the L2 height they pay for, so a miner can queue a
// whole schedule ahead of time without entries overwriting one another. All
// methods are safe for concurrent use: the HTTP handler writes while the
// consensus loop reads.
type PaymentBook struct {
	mu sync.Mutex
	// byHeight maps an L2 block height to the declaration paying for it.
	byHeight map[common.BlockNum]*L1PaymentInput
	// consumed is the highest height already handed to the consensus loop.
	// Declarations at or below it arrive too late to be of any use.
	consumed common.BlockNum
}

// NewPaymentBook returns an empty PaymentBook.
func NewPaymentBook() *PaymentBook {
	return &PaymentBook{byHeight: make(map[common.BlockNum]*L1PaymentInput)}
}

// DeclareBatch validates the shape of every declaration and stores them only
// if all of them are valid, so a batch containing one bad entry never takes
// partial effect. Confirming the payments on L1 is the caller's job and
// happens before this point.
// Returns nil when the whole batch was accepted, otherwise the list of
// rejections and no state change. Re-declaring a height that has not been
// consumed yet replaces the previous entry.
func (b *PaymentBook) DeclareBatch(decls []PaymentDeclaration) []RejectedDeclaration {
	b.mu.Lock()
	defer b.mu.Unlock()

	var rejected []RejectedDeclaration
	validated := make([]*L1PaymentInput, 0, len(decls))
	// seen catches a batch that declares the same height twice, which would
	// otherwise silently keep whichever entry happened to be stored last.
	seen := make(map[common.BlockNum]bool, len(decls))

	for _, d := range decls {
		input, err := b.validate(d, seen)
		if err != nil {
			rejected = append(rejected, RejectedDeclaration{BlockHeight: d.BlockHeight, Error: err.Error()})
			continue
		}
		seen[d.BlockHeight] = true
		validated = append(validated, input)
	}

	if len(rejected) > 0 {
		return rejected
	}
	for _, input := range validated {
		b.byHeight[input.BlockHeight] = input
	}
	return nil
}

// validate checks one declaration against the book's current state.
// `seen` holds the heights already validated in the same batch. The caller
// must hold b.mu.
func (b *PaymentBook) validate(d PaymentDeclaration, seen map[common.BlockNum]bool) (*L1PaymentInput, error) {
	if d.BlockHeight <= b.consumed {
		return nil, fmt.Errorf("height %d is not in the future (already at %d)", d.BlockHeight, b.consumed)
	}
	if seen[d.BlockHeight] {
		return nil, fmt.Errorf("height %d declared twice in the same batch", d.BlockHeight)
	}
	if d.TxHash == "" {
		return nil, errors.New("tx_hash is required")
	}
	amount, ok := new(big.Int).SetString(d.Amount, 10)
	if !ok {
		return nil, fmt.Errorf("amount %q is not a decimal integer", d.Amount)
	}
	if amount.Sign() <= 0 {
		return nil, fmt.Errorf("amount %q must be positive", d.Amount)
	}
	return &L1PaymentInput{BlockHeight: d.BlockHeight, Amount: amount, TxHash: d.TxHash}, nil
}

// Take removes and returns the declaration for `height`, or nil when the miner
// declared nothing for it. Every entry at or below `height` is dropped at the
// same time: once the chain has moved past a height its declaration can never
// be used again.
func (b *PaymentBook) Take(height common.BlockNum) *L1PaymentInput {
	b.mu.Lock()
	defer b.mu.Unlock()

	input := b.byHeight[height]
	for h := range b.byHeight {
		if h <= height {
			delete(b.byHeight, h)
		}
	}
	if height > b.consumed {
		b.consumed = height
	}
	return input
}

// Pending reports how many future declarations the book still holds. Intended
// for status reporting and tests.
func (b *PaymentBook) Pending() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.byHeight)
}

// PayL1TokenRequest is the request body for POST /pay_l1_token. One request may
// declare payments for any number of future L2 heights.
type PayL1TokenRequest struct {
	Payments []PaymentDeclaration `json:"payments"`
}

// PayL1TokenResponse reports which heights the book accepted, or why the batch
// was refused.
type PayL1TokenResponse struct {
	Accepted []common.BlockNum     `json:"accepted,omitempty"`
	Rejected []RejectedDeclaration `json:"rejected,omitempty"`
}

// PaymentServer wraps the gin HTTP server for L1 payment declarations.
//
// It confirms every declaration against L1 before storing it, so a miner
// learns immediately — in the HTTP response — that a payment it claims cannot
// be found. By the time the consensus loop reaches the height, the declaration
// it finds in the book has already been proven to exist on L1.
type PaymentServer struct {
	book        *PaymentBook
	verifier    L1PaymentVerifier
	minerPubkey string
}

// NewPaymentServer builds a PaymentServer.
// `book` must be the same instance the consensus tripod reads from;
// `verifier` queries the L1 this chain is anchored to;
// `minerPubkey` is this node's hex-encoded compressed public key, needed so
// the record checked against L1 is exactly the one that will later go into
// the block.
func NewPaymentServer(book *PaymentBook, verifier L1PaymentVerifier, minerPubkey string) *PaymentServer {
	return &PaymentServer{book: book, verifier: verifier, minerPubkey: minerPubkey}
}

// PayL1Token handles POST /pay_l1_token requests. Each declaration is first
// checked for shape, then looked up on L1; the whole batch is accepted or
// rejected together, and a rejected batch leaves the book untouched and
// reports one reason per offending height.
func (ps *PaymentServer) PayL1Token(c *gin.Context) {
	var req PayL1TokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if len(req.Payments) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "payments must not be empty"})
		return
	}

	// Confirm every payment exists on L1 before the book is touched, so a
	// batch containing one unfindable payment never takes partial effect.
	if rejected := ps.verifyOnL1(c.Request.Context(), req.Payments); rejected != nil {
		logrus.Warnf("PaymentServer: rejected batch of %d declaration(s): %d not found on L1",
			len(req.Payments), len(rejected))
		c.JSON(http.StatusBadRequest, PayL1TokenResponse{Rejected: rejected})
		return
	}

	if rejected := ps.book.DeclareBatch(req.Payments); rejected != nil {
		logrus.Warnf("PaymentServer: rejected batch of %d declaration(s)", len(req.Payments))
		c.JSON(http.StatusBadRequest, PayL1TokenResponse{Rejected: rejected})
		return
	}

	accepted := make([]common.BlockNum, 0, len(req.Payments))
	for _, d := range req.Payments {
		accepted = append(accepted, d.BlockHeight)
	}
	logrus.Infof("PaymentServer: accepted %d payment declaration(s), all confirmed on L1", len(accepted))
	c.JSON(http.StatusOK, PayL1TokenResponse{Accepted: accepted})
}

// verifyOnL1 looks up every declaration on L1, returning one rejection per
// payment that cannot be found. Returns nil when all of them exist.
// Malformed amounts are left to DeclareBatch to report, so each failure is
// described by whichever check is closest to it.
func (ps *PaymentServer) verifyOnL1(ctx context.Context, decls []PaymentDeclaration) []RejectedDeclaration {
	var rejected []RejectedDeclaration
	for _, d := range decls {
		amount, ok := new(big.Int).SetString(d.Amount, 10)
		if !ok {
			continue
		}
		payment := NewL1Payment(d.TxHash, amount, ps.minerPubkey)
		if err := ConfirmPayment(ctx, ps.verifier, payment, ps.minerPubkey); err != nil {
			rejected = append(rejected, RejectedDeclaration{
				BlockHeight: d.BlockHeight,
				Error:       err.Error(),
			})
		}
	}
	return rejected
}

// Router builds the gin engine exposing the payment endpoints.
func (ps *PaymentServer) Router() *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())
	r.POST("/pay_l1_token", ps.PayL1Token)
	return r
}

// Start serves the payment endpoints on `listenAddr` (e.g. "127.0.0.1:8081")
// in a background goroutine.
func (ps *PaymentServer) Start(listenAddr string) {
	r := ps.Router()
	go func() {
		logrus.Infof("PaymentServer: listening on %s", listenAddr)
		if err := r.Run(listenAddr); err != nil {
			logrus.Errorf("PaymentServer: failed to start: %v", err)
		}
	}()
}

// L1Payment represents a payment proof from L1.
type L1Payment struct {
	// TxHash is the L1 transaction hash.
	TxHash string `json:"tx_hash"`
	// Amount is the payment amount in the smallest unit.
	Amount *big.Int `json:"amount"`
	// Payer is the miner's L1 address.
	Payer string `json:"payer"`
	// MinerPubkey identifies which miner made this payment.
	MinerPubkey string `json:"miner_pubkey"`
}

// NewL1Payment builds an L1Payment from a validated declaration.
// `amount` must not be nil; `txHash` is the hash the miner declared.
func NewL1Payment(txHash string, amount *big.Int, minerPubkey string) *L1Payment {
	return &L1Payment{
		TxHash:      txHash,
		Amount:      new(big.Int).Set(amount),
		Payer:       mockPayerAddr,
		MinerPubkey: minerPubkey,
	}
}

// L1PaymentVerifier abstracts L1 payment verification.
// Implement this interface for each supported L1 (e.g. CKB).
type L1PaymentVerifier interface {
	// VerifyPayment looks up `payment` on L1 and returns nil when a matching
	// record exists. It returns an error describing what went wrong otherwise
	// — typically a transaction that cannot be found.
	VerifyPayment(ctx context.Context, payment *L1Payment) error
}

// ConfirmPayment checks a claimed L1 payment: that the claim is well formed,
// that it is bound to `minerPubkey` — the identity that must have paid for it
// — and that a matching transaction can be found on L1.
//
// Every path that accepts a payment claim goes through here, so the checks a
// miner's own declaration passes when it is submitted are exactly the checks
// another node applies to that miner's block when it arrives over P2P:
//
//   - POST /pay_l1_token, before a declaration enters the payment book
//   - StartBlock, for each candidate block received from another miner
//
// `verifier` must not be nil; `minerPubkey` is the hex-encoded compressed
// public key of the block producer the payment has to belong to.
func ConfirmPayment(ctx context.Context, verifier L1PaymentVerifier, payment *L1Payment, minerPubkey string) error {
	if payment == nil {
		return errors.New("payment is missing")
	}
	if payment.Amount == nil {
		return errors.New("payment amount is missing")
	}
	// A payment made by some other identity proves nothing about this block
	// producer, so a miner cannot claim someone else's transaction.
	if payment.MinerPubkey != minerPubkey {
		return fmt.Errorf("payment is bound to %s, not to the block producer %s",
			payment.MinerPubkey, minerPubkey)
	}
	return verifier.VerifyPayment(ctx, payment)
}

// MockL1PaymentVerifier is a mock verifier used in Phase 1 / testing.
// A nil KnownTxHashes accepts every payment; a non-nil one accepts only the
// listed hashes, which lets tests drive the payment-not-found path.
type MockL1PaymentVerifier struct {
	KnownTxHashes map[string]bool
}

// VerifyPayment accepts everything unless KnownTxHashes restricts it.
func (m *MockL1PaymentVerifier) VerifyPayment(_ context.Context, payment *L1Payment) error {
	if m.KnownTxHashes == nil {
		return nil
	}
	if !m.KnownTxHashes[payment.TxHash] {
		return fmt.Errorf("%w: tx_hash=%s", ErrPaymentNotFound, payment.TxHash)
	}
	return nil
}

// MockL1Payment creates a mock L1 payment with a randomly generated tx hash,
// used for the fallback payment when the miner declared nothing for a height.
// `amount` must not be nil.
func MockL1Payment(amount *big.Int, minerPubkey string) *L1Payment {
	txHash := make([]byte, 32)
	// best-effort random; ignore error for mock usage
	_, _ = rand.Read(txHash)
	return NewL1Payment(hex.EncodeToString(txHash), amount, minerPubkey)
}
