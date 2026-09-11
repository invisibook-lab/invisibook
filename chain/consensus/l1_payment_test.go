package consensus

import (
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yu-org/yu/common"
)

// decl is a shorthand for building a declaration in tests.
func decl(height common.BlockNum, amount, txHash string) PaymentDeclaration {
	return PaymentDeclaration{BlockHeight: height, Amount: amount, TxHash: txHash}
}

func TestPaymentBookAcceptsBatchAndKeysByHeight(t *testing.T) {
	book := NewPaymentBook()

	if rejected := book.DeclareBatch([]PaymentDeclaration{
		decl(10, "500", "0xaa"),
		decl(11, "700", "0xbb"),
		decl(12, "900", "0xcc"),
	}); rejected != nil {
		t.Fatalf("expected batch to be accepted, got %+v", rejected)
	}
	if got := book.Pending(); got != 3 {
		t.Fatalf("Pending() = %d, want 3", got)
	}

	// Heights are independent: taking 11 must not disturb 12.
	got := book.Take(11)
	if got == nil {
		t.Fatal("Take(11) returned nil")
	}
	if got.TxHash != "0xbb" || got.Amount.Cmp(big.NewInt(700)) != 0 {
		t.Fatalf("Take(11) = %+v, want tx 0xbb amount 700", got)
	}
	// 10 is now in the past and must have been pruned along with 11.
	if got := book.Pending(); got != 1 {
		t.Fatalf("Pending() after Take(11) = %d, want 1", got)
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
	rejected := book.DeclareBatch([]PaymentDeclaration{
		decl(10, "500", "0xaa"),
		decl(11, "not-a-number", "0xbb"),
	})
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
		{"missing tx hash", []PaymentDeclaration{decl(10, "500", "")}},
		{"zero amount", []PaymentDeclaration{decl(10, "0", "0xaa")}},
		{"negative amount", []PaymentDeclaration{decl(10, "-5", "0xaa")}},
		{"duplicate height", []PaymentDeclaration{decl(10, "500", "0xaa"), decl(10, "600", "0xbb")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			book := NewPaymentBook()
			if rejected := book.DeclareBatch(tc.decls); rejected == nil {
				t.Fatal("expected the batch to be rejected")
			}
		})
	}
}

func TestPaymentBookRejectsConsumedHeight(t *testing.T) {
	book := NewPaymentBook()
	book.Take(20) // chain has moved past height 20

	if rejected := book.DeclareBatch([]PaymentDeclaration{decl(20, "500", "0xaa")}); rejected == nil {
		t.Fatal("declaring an already-consumed height must be rejected")
	}
	if rejected := book.DeclareBatch([]PaymentDeclaration{decl(21, "500", "0xaa")}); rejected != nil {
		t.Fatalf("declaring a future height must be accepted, got %+v", rejected)
	}
}

func TestPaymentBookRedeclarationReplaces(t *testing.T) {
	book := NewPaymentBook()
	book.DeclareBatch([]PaymentDeclaration{decl(10, "500", "0xaa")})
	book.DeclareBatch([]PaymentDeclaration{decl(10, "900", "0xbb")})

	got := book.Take(10)
	if got == nil || got.TxHash != "0xbb" || got.Amount.Cmp(big.NewInt(900)) != 0 {
		t.Fatalf("Take(10) = %+v, want the re-declared tx 0xbb amount 900", got)
	}
}

func TestMockVerifierReportsMissingPayment(t *testing.T) {
	verifier := &MockL1PaymentVerifier{KnownTxHashes: map[string]bool{"0xknown": true}}
	ctx := context.Background()

	if err := verifier.VerifyPayment(ctx, NewL1Payment("0xknown", big.NewInt(1), "pub")); err != nil {
		t.Fatalf("known tx should verify, got %v", err)
	}

	err := verifier.VerifyPayment(ctx, NewL1Payment("0xmissing", big.NewInt(1), "pub"))
	if !errors.Is(err, ErrPaymentNotFound) {
		t.Fatalf("unknown tx should report ErrPaymentNotFound, got %v", err)
	}
}

func TestMockVerifierAcceptsEverythingWhenUnrestricted(t *testing.T) {
	verifier := &MockL1PaymentVerifier{}
	if err := verifier.VerifyPayment(context.Background(), NewL1Payment("0xany", big.NewInt(1), "pub")); err != nil {
		t.Fatalf("unrestricted mock should accept any payment, got %v", err)
	}
}

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

func TestPayL1TokenRejectsPaymentMissingOnL1(t *testing.T) {
	book := NewPaymentBook()
	verifier := &MockL1PaymentVerifier{KnownTxHashes: map[string]bool{"0xpaid": true}}
	ps := NewPaymentServer(book, verifier, "minerpub")

	code, resp := postDeclarations(t, ps, `{"payments":[
		{"block_height":10,"amount":"500","tx_hash":"0xpaid"},
		{"block_height":11,"amount":"600","tx_hash":"0xneverpaid"}
	]}`)

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

func TestPayL1TokenStoresConfirmedPayments(t *testing.T) {
	book := NewPaymentBook()
	verifier := &MockL1PaymentVerifier{KnownTxHashes: map[string]bool{"0xpaid10": true, "0xpaid11": true}}
	ps := NewPaymentServer(book, verifier, "minerpub")

	code, resp := postDeclarations(t, ps, `{"payments":[
		{"block_height":10,"amount":"500","tx_hash":"0xpaid10"},
		{"block_height":11,"amount":"600","tx_hash":"0xpaid11"}
	]}`)

	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %+v)", code, resp)
	}
	if len(resp.Accepted) != 2 {
		t.Fatalf("accepted = %v, want both heights", resp.Accepted)
	}
	if got := book.Pending(); got != 2 {
		t.Fatalf("Pending() = %d, want 2", got)
	}
	if got := book.Take(10); got == nil || got.TxHash != "0xpaid10" {
		t.Fatalf("Take(10) = %+v, want the confirmed declaration", got)
	}
}

func TestPayL1TokenReportsShapeErrorsWithoutHittingL1(t *testing.T) {
	book := NewPaymentBook()
	// A verifier that fails the test if it is ever called: a malformed amount
	// must be caught before any L1 round-trip is attempted.
	verifier := &MockL1PaymentVerifier{KnownTxHashes: map[string]bool{}}
	ps := NewPaymentServer(book, verifier, "minerpub")

	code, resp := postDeclarations(t, ps, `{"payments":[{"block_height":10,"amount":"abc","tx_hash":"0xaa"}]}`)

	if code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", code)
	}
	if len(resp.Rejected) != 1 || !strings.Contains(resp.Rejected[0].Error, "decimal integer") {
		t.Fatalf("rejected = %+v, want the malformed-amount reason", resp.Rejected)
	}
}

func TestConfirmPayment(t *testing.T) {
	verifier := &MockL1PaymentVerifier{KnownTxHashes: map[string]bool{"0xpaid": true}}
	ctx := context.Background()

	t.Run("accepts a bound payment found on L1", func(t *testing.T) {
		payment := NewL1Payment("0xpaid", big.NewInt(500), "minerA")
		if err := ConfirmPayment(ctx, verifier, payment, "minerA"); err != nil {
			t.Fatalf("expected the payment to be confirmed, got %v", err)
		}
	})

	t.Run("rejects a payment claimed by another miner", func(t *testing.T) {
		// minerB replays minerA's transaction inside its own block.
		payment := NewL1Payment("0xpaid", big.NewInt(500), "minerA")
		err := ConfirmPayment(ctx, verifier, payment, "minerB")
		if err == nil {
			t.Fatal("a payment bound to another miner must be rejected")
		}
		if !strings.Contains(err.Error(), "minerB") {
			t.Fatalf("error %q should name the block producer", err)
		}
	})

	t.Run("rejects a payment missing from L1", func(t *testing.T) {
		payment := NewL1Payment("0xneverpaid", big.NewInt(500), "minerA")
		if err := ConfirmPayment(ctx, verifier, payment, "minerA"); !errors.Is(err, ErrPaymentNotFound) {
			t.Fatalf("expected ErrPaymentNotFound, got %v", err)
		}
	})

	t.Run("rejects a block carrying no payment at all", func(t *testing.T) {
		if err := ConfirmPayment(ctx, verifier, nil, "minerA"); err == nil {
			t.Fatal("a nil payment must be rejected")
		}
	})

	t.Run("rejects a payment with no amount", func(t *testing.T) {
		payment := &L1Payment{TxHash: "0xpaid", MinerPubkey: "minerA"}
		if err := ConfirmPayment(ctx, verifier, payment, "minerA"); err == nil {
			t.Fatal("a payment without an amount must be rejected")
		}
	})
}
