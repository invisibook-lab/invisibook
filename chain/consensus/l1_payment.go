package consensus

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
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

// ErrPaymentNotFound reports that L1 holds no allocation for the height a
// miner claims to have paid for. Callers wrap it with the offending details.
var ErrPaymentNotFound = errors.New("no matching payment record on L1")

// ErrCommitmentMismatch reports that a declared plaintext amount does not open
// the commitment the miner recorded on L1 for that height.
var ErrCommitmentMismatch = errors.New("declared amount does not match the commitment on L1")

// MinerPubkeyHex renders a miner's compressed secp256k1 public key as hex.
// The raw 33-byte encoding is used rather than yu's type-tagged form because
// it is exactly the byte string CKB hashes into a lock's args, and the same
// string an owner key is stored as.
func MinerPubkeyHex(pubkey keypair.PubKey) string {
	return hex.EncodeToString(pubkey.Bytes())
}

// PaymentDeclaration is a miner's statement that, out of the prepayment made
// in L1 transaction `TxHash`, it allocated `Amount` of L1 token to the L2 block
// at `BlockHeight`. One declaration binds exactly one height.
//
// On L1 that allocation is stored as a Poseidon commitment, so competitors
// cannot read how much a miner bid for an upcoming height. The declaration
// submitted here is the plaintext opening of that commitment: `Amount` and
// `Random` together must hash to the commitment sitting on L1.
type PaymentDeclaration struct {
	// BlockHeight is the L2 block height this payment competes for.
	BlockHeight common.BlockNum `json:"block_height"`
	// Amount is the plaintext allocation as a decimal string, e.g. "5000".
	Amount string `json:"amount"`
	// Random is the 64-char hex blinding factor of the on-L1 commitment.
	Random string `json:"random"`
	// TxHash is the L1 prepayment transaction this allocation is drawn from.
	TxHash string `json:"tx_hash"`
	// BudgetProof proves this allocation and the ones before it stay within
	// the prepaid total. Empty until the circuit exists — see
	// VerifyAllocationBudget.
	BudgetProof AllocationBudgetProof `json:"budget_proof,omitempty"`
}

// L1PaymentInput is a declaration that passed validation and was confirmed
// against L1, held by the PaymentBook until the consensus loop reaches its
// height.
type L1PaymentInput struct {
	// BlockHeight is the L2 block height this payment competes for.
	BlockHeight common.BlockNum
	// Amount is the parsed plaintext allocation.
	Amount *big.Int
	// Random is the hex blinding factor opening the on-L1 commitment.
	Random string
	// TxHash is the L1 prepayment transaction this allocation is drawn from.
	TxHash string
	// BudgetProof proves the allocations stay within the prepaid total.
	BudgetProof AllocationBudgetProof
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

// ValidateDeclarations checks every declaration's fields and rejects a batch
// that names the same height twice. It consults neither the book nor L1, so a
// malformed declaration is always reported as malformed — a later L1 lookup
// can never mask it with a "not found".
//
// Returns the parsed declarations when the whole batch is well formed, or nil
// plus one rejection per offending height.
func ValidateDeclarations(decls []PaymentDeclaration) ([]*L1PaymentInput, []RejectedDeclaration) {
	var rejected []RejectedDeclaration
	inputs := make([]*L1PaymentInput, 0, len(decls))
	// seen catches a batch that declares the same height twice, which would
	// otherwise silently keep whichever entry happened to be stored last.
	seen := make(map[common.BlockNum]bool, len(decls))

	for _, d := range decls {
		if seen[d.BlockHeight] {
			rejected = append(rejected, RejectedDeclaration{
				BlockHeight: d.BlockHeight,
				Error:       fmt.Sprintf("height %d declared twice in the same batch", d.BlockHeight),
			})
			continue
		}
		input, err := validateShape(d)
		if err != nil {
			rejected = append(rejected, RejectedDeclaration{BlockHeight: d.BlockHeight, Error: err.Error()})
			continue
		}
		seen[d.BlockHeight] = true
		inputs = append(inputs, input)
	}

	if len(rejected) > 0 {
		return nil, rejected
	}
	return inputs, nil
}

// validateShape parses and checks one declaration's fields in isolation.
func validateShape(d PaymentDeclaration) (*L1PaymentInput, error) {
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
	if len(d.Random) != RandomHexLen {
		return nil, fmt.Errorf("random must be %d hex chars, got %d", RandomHexLen, len(d.Random))
	}
	return &L1PaymentInput{
		BlockHeight: d.BlockHeight,
		Amount:      amount,
		Random:      d.Random,
		TxHash:      d.TxHash,
		BudgetProof: d.BudgetProof,
	}, nil
}

// Store records declarations that are already validated and confirmed on L1,
// keeping the batch atomic: if any height has been overtaken by the chain,
// nothing is stored. Returns nil when the whole batch was stored. Re-declaring
// a height that has not been consumed yet replaces the previous entry.
func (b *PaymentBook) Store(inputs []*L1PaymentInput) []RejectedDeclaration {
	b.mu.Lock()
	defer b.mu.Unlock()

	var rejected []RejectedDeclaration
	for _, input := range inputs {
		if input.BlockHeight <= b.consumed {
			rejected = append(rejected, RejectedDeclaration{
				BlockHeight: input.BlockHeight,
				Error: fmt.Sprintf("height %d is not in the future (already at %d)",
					input.BlockHeight, b.consumed),
			})
		}
	}
	if len(rejected) > 0 {
		return rejected
	}

	for _, input := range inputs {
		b.byHeight[input.BlockHeight] = input
	}
	return nil
}

// Take removes and returns the declaration for `height`, or nil when the miner
// declared nothing for it.
//
// Taking does not mark the height as gone: a round can end without settling on
// any block, and the kernel then retries the same height. Until a block
// actually lands the miner is still free to declare for it, so only Settle
// closes a height off.
func (b *PaymentBook) Take(height common.BlockNum) *L1PaymentInput {
	b.mu.Lock()
	defer b.mu.Unlock()

	input := b.byHeight[height]
	delete(b.byHeight, height)
	return input
}

// Settle records that the chain has accepted a block at `height`, closing that
// height and every one below it: their declarations can never be used again,
// and declaring for them is refused from here on.
func (b *PaymentBook) Settle(height common.BlockNum) {
	b.mu.Lock()
	defer b.mu.Unlock()

	for h := range b.byHeight {
		if h <= height {
			delete(b.byHeight, h)
		}
	}
	if height > b.consumed {
		b.consumed = height
	}
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

	// Shape first, so a malformed field is reported as such rather than as a
	// lookup failure.
	inputs, rejected := ValidateDeclarations(req.Payments)
	if rejected != nil {
		logrus.Warnf("PaymentServer: rejected malformed batch of %d declaration(s)", len(req.Payments))
		c.JSON(http.StatusBadRequest, PayL1TokenResponse{Rejected: rejected})
		return
	}

	// Then confirm every allocation against L1 before the book is touched, so
	// a batch containing one unconfirmable payment never takes partial effect.
	if rejected := ps.confirmOnL1(c.Request.Context(), inputs); rejected != nil {
		logrus.Warnf("PaymentServer: rejected batch of %d declaration(s): %d failed L1 confirmation",
			len(req.Payments), len(rejected))
		c.JSON(http.StatusBadRequest, PayL1TokenResponse{Rejected: rejected})
		return
	}

	if rejected := ps.book.Store(inputs); rejected != nil {
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

// confirmOnL1 confirms every already-validated declaration against L1,
// returning one rejection per payment that L1 does not back. Returns nil when
// all of them check out. `inputs` must have come from ValidateDeclarations.
func (ps *PaymentServer) confirmOnL1(ctx context.Context, inputs []*L1PaymentInput) []RejectedDeclaration {
	var rejected []RejectedDeclaration
	for _, input := range inputs {
		payment := NewL1Payment(input.TxHash, input.Amount, input.Random, ps.minerPubkey, input.BudgetProof)
		if _, err := ConfirmPayment(ctx, ps.verifier, payment, ps.minerPubkey, input.BlockHeight); err != nil {
			rejected = append(rejected, RejectedDeclaration{
				BlockHeight: input.BlockHeight,
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

// L1Payment is the opening of an on-L1 allocation commitment, carried inside
// the block so every node can score the block and re-check the commitment.
//
// The allocation is hidden on L1 and revealed here: scoring needs the
// plaintext `Amount`, and `Random` lets any node recompute the commitment and
// confirm the miner is revealing the value it actually committed to.
type L1Payment struct {
	// TxHash is the L1 prepayment transaction this allocation is drawn from.
	TxHash string `json:"tx_hash"`
	// Amount is the plaintext allocation in the smallest unit.
	Amount *big.Int `json:"amount"`
	// Random is the hex blinding factor opening the on-L1 commitment.
	Random string `json:"random"`
	// BudgetProof proves this allocation and the ones before it stay within
	// the miner's prepaid total.
	BudgetProof AllocationBudgetProof `json:"budget_proof,omitempty"`
	// Payer is the miner's L1 address.
	Payer string `json:"payer"`
	// MinerPubkey identifies which miner made this payment.
	MinerPubkey string `json:"miner_pubkey"`
}

// NewL1Payment builds an L1Payment from a validated declaration.
// `amount` must not be nil; `txHash` and `random` come from the miner's
// declaration.
func NewL1Payment(txHash string, amount *big.Int, random, minerPubkey string, budgetProof AllocationBudgetProof) *L1Payment {
	return &L1Payment{
		TxHash:      txHash,
		Amount:      new(big.Int).Set(amount),
		Random:      random,
		BudgetProof: budgetProof,
		Payer:       mockPayerAddr,
		MinerPubkey: minerPubkey,
	}
}

// Allocation is one entry of a miner's budget table as recorded on L1.
//
// It is a struct rather than a pair of return values because the checks that
// read it are still being added: V4 needs the L1 block number today, and
// growing the tuple would churn every implementation and call site each time
// another field is needed.
type Allocation struct {
	// Commitment is the Poseidon commitment to (amount, random) the miner
	// posted for this height, as a 64-char hex string.
	Commitment string
	// L1BlockNumber is the L1 block the entry was written in.
	//
	// V4 compares it: an allocation must be at least 24 L1 blocks older than
	// the L1 block holding the commitment of the L2 block that spends it.
	// Without that gap a miner could post the allocation on an L1 fork that
	// has not converged yet, and L1's uncertainty would spread to L2. R3.1 on
	// chain only makes the table immutable once written — that it was written
	// early enough can only be checked here.
	L1BlockNumber uint64
}

// L1PaymentVerifier resolves allocations recorded on L1.
// Implement this interface for each supported L1 (e.g. CKB).
type L1PaymentVerifier interface {
	// FetchAllocation returns the allocation the miner posted on L1 drawing
	// part of prepayment `txHash` for L2 block `height`. It returns an error
	// wrapping ErrPaymentNotFound when no such allocation exists.
	FetchAllocation(ctx context.Context, txHash, minerPubkey string, height common.BlockNum) (*Allocation, error)

	// FetchPrepayment returns the plaintext total the miner paid to the mining
	// addr in `txHash`, the ceiling every allocation drawn from it must
	// respect. It returns an error wrapping ErrPaymentNotFound when the
	// transaction holds no prepayment by this miner.
	//
	// Plaintext, not a commitment: a capacity transfer is public on CKB, so
	// the total cannot be hidden and there is no reason to try. Only the
	// per-height amounts are committed (ckb_layout.md §3).
	FetchPrepayment(ctx context.Context, txHash, minerPubkey string) (*big.Int, error)
}

// ConfirmPayment checks a claimed L1 payment against L1: that the claim is
// well formed, that it is bound to `minerPubkey` — the identity that must have
// paid for it — that L1 holds an allocation for `height`, that the plaintext
// amount really opens the commitment recorded there, and that the allocation
// stays inside the prepayment it is drawn from.
//
// The last check is what makes the plaintext trustworthy. The allocation is
// committed on L1 before the miner knows anyone else's bid, so revealing it
// later cannot be a lie: a miner that tries to claim a larger amount than it
// committed to produces a different Poseidon hash and is rejected here.
//
// Every path that accepts a payment claim goes through here, so the checks a
// miner's own declaration passes when it is submitted are exactly the checks
// another node applies to that miner's block when it arrives over P2P:
//
//   - POST /pay_l1_token, before a declaration enters the payment book
//   - StartBlock, for each candidate block received from another miner
//
// It returns the allocation as recorded on L1. Callers that go on to check V4
// need its L1 block number, and handing it back here spares them a second
// round-trip to fetch what this call already read.
//
// `verifier` must not be nil; `minerPubkey` is the hex-encoded compressed
// public key of the block producer the payment has to belong to; `height` is
// the L2 height the payment is meant to buy.
func ConfirmPayment(ctx context.Context, verifier L1PaymentVerifier, payment *L1Payment, minerPubkey string, height common.BlockNum) (*Allocation, error) {
	if payment == nil {
		return nil, errors.New("payment is missing")
	}
	if payment.Amount == nil {
		return nil, errors.New("payment amount is missing")
	}
	// A payment made by some other identity proves nothing about this block
	// producer, so a miner cannot claim someone else's transaction.
	if payment.MinerPubkey != minerPubkey {
		return nil, fmt.Errorf("payment is bound to %s, not to the block producer %s",
			payment.MinerPubkey, minerPubkey)
	}

	alloc, err := verifier.FetchAllocation(ctx, payment.TxHash, minerPubkey, height)
	if err != nil {
		return nil, err
	}

	opening, err := PoseidonCommit(payment.Amount, payment.Random)
	if err != nil {
		return nil, fmt.Errorf("recomputing the allocation commitment: %w", err)
	}
	if opening != alloc.Commitment {
		return nil, fmt.Errorf("%w: height %d commits to %s, but the declared amount opens to %s",
			ErrCommitmentMismatch, height, alloc.Commitment, opening)
	}

	// An allocation that opens correctly can still be money the miner does not
	// have: nothing so far ties it to the size of the prepayment it is drawn
	// from. That is what the budget proof is for.
	prepaid, err := verifier.FetchPrepayment(ctx, payment.TxHash, minerPubkey)
	if err != nil {
		return nil, err
	}
	if err := VerifyAllocationBudget(prepaid, payment.BudgetProof, payment); err != nil {
		return nil, fmt.Errorf("allocation budget: %w", err)
	}
	return alloc, nil
}

// MockL1PaymentVerifier stands in for a real L1 client in Phase 1 / testing.
// It holds the commitments a miner would have posted on L1, keyed the same way
// a real client would look them up.
type MockL1PaymentVerifier struct {
	mu sync.Mutex
	// allocations maps (tx hash, miner, height) to the entry recorded on L1.
	allocations map[string]*Allocation
	// prepayments maps (tx hash, miner) to the plaintext prepaid total.
	prepayments map[string]*big.Int
}

// mockDefaultPrepaid is what FetchPrepayment reports for a miner that has
// allocations but no prepayment seeded: a total large enough that any
// allocation a test sets up fits inside it, which is what such a test means
// by leaving the prepayment unspecified.
var mockDefaultPrepaid = new(big.Int).SetUint64(1 << 62)

// allocationKey builds the lookup key for one on-L1 allocation.
func allocationKey(txHash, minerPubkey string, height common.BlockNum) string {
	return fmt.Sprintf("%s/%s/%d", txHash, minerPubkey, height)
}

// Allocate records the commitment for a plaintext (amount, random) pair,
// standing in for the miner having posted that allocation on L1 in block
// `l1Block`. `randomHex` must be 64 hex chars.
func (m *MockL1PaymentVerifier) Allocate(txHash, minerPubkey string, height common.BlockNum, amount *big.Int, randomHex string, l1Block uint64) error {
	commitment, err := PoseidonCommit(amount, randomHex)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.allocations == nil {
		m.allocations = make(map[string]*Allocation)
	}
	m.allocations[allocationKey(txHash, minerPubkey, height)] = &Allocation{
		Commitment:    commitment,
		L1BlockNumber: l1Block,
	}
	return nil
}

// Prepay records a miner's prepaid total, standing in for the miner having
// transferred that much to the mining addr on L1. `total` must not be nil.
func (m *MockL1PaymentVerifier) Prepay(txHash, minerPubkey string, total *big.Int) error {
	if total == nil {
		return errors.New("prepaid total is missing")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.prepayments == nil {
		m.prepayments = make(map[string]*big.Int)
	}
	m.prepayments[txHash+"/"+minerPubkey] = new(big.Int).Set(total)
	return nil
}

// FetchPrepayment returns the recorded prepaid total.
//
// A miner with allocations but no recorded prepayment falls back to
// mockDefaultPrepaid, so a test that only cares about allocations need not
// seed both. The fallback is deliberately large: it stands for "some total
// this allocation fits inside", which is exactly what such a test assumes.
func (m *MockL1PaymentVerifier) FetchPrepayment(_ context.Context, txHash, minerPubkey string) (*big.Int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if total, ok := m.prepayments[txHash+"/"+minerPubkey]; ok {
		return new(big.Int).Set(total), nil
	}
	for key := range m.allocations {
		if strings.HasPrefix(key, txHash+"/"+minerPubkey+"/") {
			return new(big.Int).Set(mockDefaultPrepaid), nil
		}
	}
	return nil, fmt.Errorf("%w: no prepayment in tx_hash=%s", ErrPaymentNotFound, txHash)
}

// FetchAllocation returns the recorded allocation, or ErrPaymentNotFound.
func (m *MockL1PaymentVerifier) FetchAllocation(_ context.Context, txHash, minerPubkey string, height common.BlockNum) (*Allocation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	alloc, ok := m.allocations[allocationKey(txHash, minerPubkey, height)]
	if !ok {
		return nil, fmt.Errorf("%w: tx_hash=%s height=%d", ErrPaymentNotFound, txHash, height)
	}
	// Copied, so a caller cannot reach back into the mock's own table.
	copied := *alloc
	return &copied, nil
}

// MockL1Payment creates a placeholder payment with a randomly generated tx
// hash and blinding factor, used when the miner declared nothing for a height.
//
// No allocation backs it on L1, so peers will reject a block carrying one —
// which is the point: a miner that did not pay cannot win the height.
// `amount` must not be nil.
func MockL1Payment(amount *big.Int, minerPubkey string) *L1Payment {
	buf := make([]byte, 64)
	// best-effort random; ignore error for mock usage
	_, _ = rand.Read(buf)
	return NewL1Payment(hex.EncodeToString(buf[:32]), amount, hex.EncodeToString(buf[32:]), minerPubkey, "")
}
