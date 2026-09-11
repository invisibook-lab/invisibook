package consensus

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yu-org/yu/common"
)

// Blinding factors used throughout these tests. Any 64-char hex string works.
var (
	randA = strings.Repeat("a1", 32)
	randB = strings.Repeat("b2", 32)
)

// declareAll runs the validate-then-store path the HTTP handler uses, minus
// the L1 confirmation step, and returns any rejections.
func declareAll(t *testing.T, book *PaymentBook, decls ...PaymentDeclaration) []RejectedDeclaration {
	t.Helper()
	inputs, rejected := ValidateDeclarations(decls)
	if rejected != nil {
		return rejected
	}
	return book.Store(inputs)
}

// decl is a shorthand for building a declaration in tests.
func decl(height common.BlockNum, amount, random, txHash string) PaymentDeclaration {
	return PaymentDeclaration{BlockHeight: height, Amount: amount, Random: random, TxHash: txHash}
}

// ───────────────────────────── PaymentBook ─────────────────────────────

func TestPaymentBookAcceptsBatchAndKeysByHeight(t *testing.T) {
	book := NewPaymentBook()

	if rejected := declareAll(t, book,
		decl(10, "500", randA, "0xaa"),
		decl(11, "700", randB, "0xbb"),
		decl(12, "900", randA, "0xcc"),
	); rejected != nil {
		t.Fatalf("expected batch to be accepted, got %+v", rejected)
	}
	if got := book.Pending(); got != 3 {
		t.Fatalf("Pending() = %d, want 3", got)
	}

	// Heights are independent: taking 11 must not disturb 10 or 12.
	got := book.Take(11)
	if got == nil {
		t.Fatal("Take(11) returned nil")
	}
	if got.TxHash != "0xbb" || got.Amount.Cmp(big.NewInt(700)) != 0 || got.Random != randB {
		t.Fatalf("Take(11) = %+v, want tx 0xbb amount 700 random %s", got, randB)
	}
	if got := book.Pending(); got != 2 {
		t.Fatalf("Pending() after Take(11) = %d, want 2", got)
	}
	if book.Take(12) == nil {
		t.Fatal("Take(12) returned nil, declaration should have survived")
	}
}

func TestPaymentBookTakeReturnsNilForUndeclaredHeight(t *testing.T) {
	book := NewPaymentBook()
	if got := book.Take(5); got != nil {
		t.Fatalf("Take(5) = %+v, want nil", got)
	}
}

func TestPaymentBookRejectsBatchAtomically(t *testing.T) {
	book := NewPaymentBook()

	// One bad amount must sink the whole batch, including the valid entries.
	rejected := declareAll(t, book,
		decl(10, "500", randA, "0xaa"),
		decl(11, "not-a-number", randB, "0xbb"),
	)
	if len(rejected) != 1 {
		t.Fatalf("expected 1 rejection, got %+v", rejected)
	}
	if rejected[0].BlockHeight != 11 {
		t.Fatalf("rejection is for height %d, want 11", rejected[0].BlockHeight)
	}
	if got := book.Pending(); got != 0 {
		t.Fatalf("Pending() = %d, want 0 — a rejected batch must not take partial effect", got)
	}
}

func TestPaymentBookValidation(t *testing.T) {
	cases := []struct {
		name  string
		decls []PaymentDeclaration
	}{
		{"missing tx hash", []PaymentDeclaration{decl(10, "500", randA, "")}},
		{"zero amount", []PaymentDeclaration{decl(10, "0", randA, "0xaa")}},
		{"negative amount", []PaymentDeclaration{decl(10, "-5", randA, "0xaa")}},
		{"missing random", []PaymentDeclaration{decl(10, "500", "", "0xaa")}},
		{"short random", []PaymentDeclaration{decl(10, "500", "a1b2", "0xaa")}},
		{"duplicate height", []PaymentDeclaration{decl(10, "500", randA, "0xaa"), decl(10, "600", randB, "0xbb")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			book := NewPaymentBook()
			if rejected := declareAll(t, book, tc.decls...); rejected == nil {
				t.Fatal("expected the batch to be rejected")
			}
		})
	}
}

func TestPaymentBookRejectsSettledHeight(t *testing.T) {
	book := NewPaymentBook()
	book.Settle(20) // the chain accepted a block at height 20

	if rejected := declareAll(t, book, decl(20, "500", randA, "0xaa")); rejected == nil {
		t.Fatal("declaring an already-consumed height must be rejected")
	}
	if rejected := declareAll(t, book, decl(21, "500", randA, "0xaa")); rejected != nil {
		t.Fatalf("declaring a future height must be accepted, got %+v", rejected)
	}
}

func TestPaymentBookRedeclarationReplaces(t *testing.T) {
	book := NewPaymentBook()
	declareAll(t, book, decl(10, "500", randA, "0xaa"))
	declareAll(t, book, decl(10, "900", randB, "0xbb"))

	got := book.Take(10)
	if got == nil || got.TxHash != "0xbb" || got.Amount.Cmp(big.NewInt(900)) != 0 {
		t.Fatalf("Take(10) = %+v, want the re-declared tx 0xbb amount 900", got)
	}
}

// ───────────────────────────── Commitment ──────────────────────────────

// TestPoseidonCommitMatchesCircomParameterization pins the Go commitment to the
// same constant the chain and the Rust wallet already agree on, so a drift in
// Poseidon parameters cannot go unnoticed.
func TestPoseidonCommitMatchesCircomParameterization(t *testing.T) {
	const zeroCommitmentHex = "2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864"

	got, err := PoseidonCommit(big.NewInt(0), strings.Repeat("00", 32))
	if err != nil {
		t.Fatalf("PoseidonCommit: %v", err)
	}
	if got != zeroCommitmentHex {
		t.Fatalf("Poseidon(0, 0) = %s, want %s", got, zeroCommitmentHex)
	}
}

func TestPoseidonCommitIsDeterministicAndBinding(t *testing.T) {
	first, err := PoseidonCommit(big.NewInt(5000), randA)
	if err != nil {
		t.Fatalf("PoseidonCommit: %v", err)
	}
	again, _ := PoseidonCommit(big.NewInt(5000), randA)
	if first != again {
		t.Fatal("the same (amount, random) must commit to the same value")
	}
	if len(first) != CommitmentHexLen {
		t.Fatalf("commitment length = %d, want %d", len(first), CommitmentHexLen)
	}

	// Changing either input must change the commitment.
	otherAmount, _ := PoseidonCommit(big.NewInt(5001), randA)
	if otherAmount == first {
		t.Fatal("a different amount must produce a different commitment")
	}
	otherRandom, _ := PoseidonCommit(big.NewInt(5000), randB)
	if otherRandom == first {
		t.Fatal("a different random must produce a different commitment")
	}
}

func TestPoseidonCommitRejectsBadInput(t *testing.T) {
	if _, err := PoseidonCommit(nil, randA); err == nil {
		t.Fatal("a nil amount must be rejected")
	}
	if _, err := PoseidonCommit(big.NewInt(-1), randA); err == nil {
		t.Fatal("a negative amount must be rejected")
	}
	if _, err := PoseidonCommit(big.NewInt(1), "zz"); err == nil {
		t.Fatal("a malformed random must be rejected")
	}
	if _, err := PoseidonCommit(big.NewInt(1), strings.Repeat("zz", 32)); err == nil {
		t.Fatal("a non-hex random must be rejected")
	}
}

// ─────────────────────────── ConfirmPayment ────────────────────────────

func TestConfirmPayment(t *testing.T) {
	const height common.BlockNum = 42
	verifier := &MockL1PaymentVerifier{}
	if err := verifier.Allocate("0xprepay", "minerA", height, big.NewInt(500), randA); err != nil {
		t.Fatalf("seeding the mock allocation: %v", err)
	}
	ctx := context.Background()

	t.Run("accepts an opening that matches the commitment", func(t *testing.T) {
		payment := NewL1Payment("0xprepay", big.NewInt(500), randA, "minerA")
		if err := ConfirmPayment(ctx, verifier, payment, "minerA", height); err != nil {
			t.Fatalf("expected the payment to be confirmed, got %v", err)
		}
	})

	t.Run("rejects an inflated amount", func(t *testing.T) {
		// The miner committed to 500 on L1 but now claims 50000 to win the height.
		payment := NewL1Payment("0xprepay", big.NewInt(50000), randA, "minerA")
		err := ConfirmPayment(ctx, verifier, payment, "minerA", height)
		if !errors.Is(err, ErrCommitmentMismatch) {
			t.Fatalf("expected ErrCommitmentMismatch, got %v", err)
		}
	})

	t.Run("rejects a substituted random", func(t *testing.T) {
		payment := NewL1Payment("0xprepay", big.NewInt(500), randB, "minerA")
		if err := ConfirmPayment(ctx, verifier, payment, "minerA", height); !errors.Is(err, ErrCommitmentMismatch) {
			t.Fatalf("expected ErrCommitmentMismatch, got %v", err)
		}
	})

	t.Run("rejects a payment claimed by another miner", func(t *testing.T) {
		// minerB replays minerA's allocation inside its own block.
		payment := NewL1Payment("0xprepay", big.NewInt(500), randA, "minerA")
		err := ConfirmPayment(ctx, verifier, payment, "minerB", height)
		if err == nil {
			t.Fatal("a payment bound to another miner must be rejected")
		}
		if !strings.Contains(err.Error(), "minerB") {
			t.Fatalf("error %q should name the block producer", err)
		}
	})

	t.Run("rejects a height with no allocation on L1", func(t *testing.T) {
		payment := NewL1Payment("0xprepay", big.NewInt(500), randA, "minerA")
		if err := ConfirmPayment(ctx, verifier, payment, "minerA", height+1); !errors.Is(err, ErrPaymentNotFound) {
			t.Fatalf("expected ErrPaymentNotFound, got %v", err)
		}
	})

	t.Run("rejects a block carrying no payment at all", func(t *testing.T) {
		if err := ConfirmPayment(ctx, verifier, nil, "minerA", height); err == nil {
			t.Fatal("a nil payment must be rejected")
		}
	})

	t.Run("rejects a payment with no amount", func(t *testing.T) {
		payment := &L1Payment{TxHash: "0xprepay", Random: randA, MinerPubkey: "minerA"}
		if err := ConfirmPayment(ctx, verifier, payment, "minerA", height); err == nil {
			t.Fatal("a payment without an amount must be rejected")
		}
	})
}

// ───────────────────────── POST /pay_l1_token ──────────────────────────

// postDeclarations drives the HTTP handler directly and returns the status
// code plus the decoded response body.
func postDeclarations(t *testing.T, ps *PaymentServer, body string) (int, PayL1TokenResponse) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/pay_l1_token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	ps.Router().ServeHTTP(w, req)

	var resp PayL1TokenResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding response %q: %v", w.Body.String(), err)
	}
	return w.Code, resp
}

// declJSON renders one declaration as a JSON object for request bodies.
func declJSON(height common.BlockNum, amount, random, txHash string) string {
	return fmt.Sprintf(`{"block_height":%d,"amount":%q,"random":%q,"tx_hash":%q}`,
		height, amount, random, txHash)
}

func TestPayL1TokenStoresConfirmedPayments(t *testing.T) {
	book := NewPaymentBook()
	verifier := &MockL1PaymentVerifier{}
	verifier.Allocate("0xprepay", "minerpub", 10, big.NewInt(500), randA)
	verifier.Allocate("0xprepay", "minerpub", 11, big.NewInt(600), randB)
	ps := NewPaymentServer(book, verifier, "minerpub")

	code, resp := postDeclarations(t, ps, `{"payments":[`+
		declJSON(10, "500", randA, "0xprepay")+`,`+
		declJSON(11, "600", randB, "0xprepay")+`]}`)

	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %+v)", code, resp)
	}
	if len(resp.Accepted) != 2 {
		t.Fatalf("accepted = %v, want both heights", resp.Accepted)
	}
	if got := book.Take(10); got == nil || got.Random != randA {
		t.Fatalf("Take(10) = %+v, want the confirmed declaration", got)
	}
}

func TestPayL1TokenRejectsPaymentMissingOnL1(t *testing.T) {
	book := NewPaymentBook()
	verifier := &MockL1PaymentVerifier{}
	verifier.Allocate("0xprepay", "minerpub", 10, big.NewInt(500), randA)
	ps := NewPaymentServer(book, verifier, "minerpub")

	// Height 11 was never allocated on L1.
	code, resp := postDeclarations(t, ps, `{"payments":[`+
		declJSON(10, "500", randA, "0xprepay")+`,`+
		declJSON(11, "600", randB, "0xprepay")+`]}`)

	if code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", code)
	}
	if len(resp.Rejected) != 1 || resp.Rejected[0].BlockHeight != 11 {
		t.Fatalf("rejected = %+v, want a single rejection for height 11", resp.Rejected)
	}
	if !strings.Contains(resp.Rejected[0].Error, ErrPaymentNotFound.Error()) {
		t.Fatalf("rejection reason %q should report the payment is missing on L1", resp.Rejected[0].Error)
	}
	// The valid sibling must not have been stored either.
	if got := book.Pending(); got != 0 {
		t.Fatalf("Pending() = %d, want 0 — a batch with an unfindable payment must not take partial effect", got)
	}
}

func TestPayL1TokenRejectsAmountNotMatchingCommitment(t *testing.T) {
	book := NewPaymentBook()
	verifier := &MockL1PaymentVerifier{}
	verifier.Allocate("0xprepay", "minerpub", 10, big.NewInt(500), randA)
	ps := NewPaymentServer(book, verifier, "minerpub")

	// The miner committed to 500 on L1 but declares 50000 locally.
	code, resp := postDeclarations(t, ps, `{"payments":[`+declJSON(10, "50000", randA, "0xprepay")+`]}`)

	if code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", code)
	}
	if len(resp.Rejected) != 1 || !strings.Contains(resp.Rejected[0].Error, ErrCommitmentMismatch.Error()) {
		t.Fatalf("rejected = %+v, want the commitment-mismatch reason", resp.Rejected)
	}
	if got := book.Pending(); got != 0 {
		t.Fatalf("Pending() = %d, want 0", got)
	}
}

func TestPayL1TokenReportsShapeErrorsWithoutHittingL1(t *testing.T) {
	book := NewPaymentBook()
	// Nothing is allocated on this verifier: a malformed amount must be caught
	// by the shape check and reported as such, not as a missing L1 record.
	ps := NewPaymentServer(book, &MockL1PaymentVerifier{}, "minerpub")

	code, resp := postDeclarations(t, ps, `{"payments":[`+declJSON(10, "abc", randA, "0xaa")+`]}`)

	if code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", code)
	}
	if len(resp.Rejected) != 1 || !strings.Contains(resp.Rejected[0].Error, "decimal integer") {
		t.Fatalf("rejected = %+v, want the malformed-amount reason", resp.Rejected)
	}
}

func TestPayL1TokenRejectsEmptyBatch(t *testing.T) {
	ps := NewPaymentServer(NewPaymentBook(), &MockL1PaymentVerifier{}, "minerpub")
	code, _ := postDeclarations(t, ps, `{"payments":[]}`)
	if code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", code)
	}
}

// TestPaymentBookTakeDoesNotCloseTheHeight covers the retry path: a round that
// ends without settling leaves the height open, so the miner can still declare
// for it before the chain moves on.
func TestPaymentBookTakeDoesNotCloseTheHeight(t *testing.T) {
	book := NewPaymentBook()

	// The consensus loop asks for height 18 and finds nothing, then stands
	// down without settling.
	if got := book.Take(18); got != nil {
		t.Fatalf("Take(18) = %+v, want nil", got)
	}

	// A late declaration for the same height must still be accepted, because
	// no block has landed there yet.
	if rejected := declareAll(t, book, decl(18, "500", randA, "0xaa")); rejected != nil {
		t.Fatalf("declaring for an unsettled height must be accepted, got %+v", rejected)
	}
	if got := book.Take(18); got == nil || got.TxHash != "0xaa" {
		t.Fatalf("Take(18) = %+v, want the late declaration", got)
	}
}

// TestPaymentBookSettlePrunesLowerHeights checks that settling a height drops
// every declaration the chain has moved past, including ones never taken.
func TestPaymentBookSettlePrunesLowerHeights(t *testing.T) {
	book := NewPaymentBook()
	declareAll(t, book,
		decl(10, "100", randA, "0xaa"),
		decl(11, "200", randA, "0xbb"),
		decl(12, "300", randA, "0xcc"),
	)

	book.Settle(11)

	if got := book.Pending(); got != 1 {
		t.Fatalf("Pending() = %d, want 1 — heights 10 and 11 should be gone", got)
	}
	if book.Take(12) == nil {
		t.Fatal("height 12 is still ahead of the chain and must survive")
	}
}
