package miner

import (
	"context"
	"crypto/rand"
	"math/big"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/invisibook-lab/invisibook/consensus"
)

// nodeUnderTest serves a real payment server over a mock L1, the way the node
// does, and returns a client pointed at it.
func nodeUnderTest(t *testing.T) (*NodeClient, *consensus.PaymentBook, *consensus.MockL1PaymentVerifier) {
	t.Helper()
	book := consensus.NewPaymentBook()
	verifier := &consensus.MockL1PaymentVerifier{}
	server := httptest.NewServer(consensus.NewPaymentServer(book, verifier, "02ab").Router())
	t.Cleanup(server.Close)
	return NewNodeClient(server.URL + "/"), book, verifier
}

func TestNodeClientReadsTheBook(t *testing.T) {
	client, book, _ := nodeUnderTest(t)
	book.Settle(41)
	if got := client.Consumed(); got != 41 {
		t.Fatalf("consumed = %d, want 41", got)
	}
	if got := client.Pending(); got != 0 {
		t.Fatalf("pending = %d, want 0", got)
	}
}

func TestNodeClientDeclares(t *testing.T) {
	client, book, verifier := nodeUnderTest(t)
	random, err := consensus.NewPaymentRandomHex(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.Allocate("0xprepay", "02ab", 7, big.NewInt(500), random, 1); err != nil {
		t.Fatal(err)
	}

	ok := client.Declare(context.Background(), []consensus.PaymentDeclaration{
		{BlockHeight: 7, Amount: "500", Random: random, TxHash: "0xprepay"},
	})
	if len(ok.Accepted) != 1 || len(ok.Rejected) != 0 {
		t.Fatalf("an allocation L1 holds was not accepted: %+v", ok)
	}
	if book.Pending() != 1 {
		t.Fatalf("the node's book holds %d declarations, want 1", book.Pending())
	}

	// A refusal arrives as a 400 with the reasons: those must come through
	// as they are, not as a transport error.
	bad := client.Declare(context.Background(), []consensus.PaymentDeclaration{
		{BlockHeight: 8, Amount: "500", Random: random, TxHash: "0xprepay"},
	})
	if len(bad.Rejected) != 1 || bad.Rejected[0].BlockHeight != 8 {
		t.Fatalf("an allocation L1 lacks came back as %+v", bad)
	}
}

// A node that is down leaves the last known state in place and rejects every
// declaration with the reason, rather than inventing a height of zero.
func TestNodeClientSurvivesAnUnreachableNode(t *testing.T) {
	client, book, _ := nodeUnderTest(t)
	book.Settle(9)
	if client.Consumed() != 9 {
		t.Fatal("did not read the live node")
	}
	client.baseURL = "http://127.0.0.1:1"

	if got := client.Consumed(); got != 9 {
		t.Fatalf("consumed fell back to %d, want the last known 9", got)
	}
	resp := client.Declare(context.Background(), []consensus.PaymentDeclaration{
		{BlockHeight: 10, Amount: "1", Random: strings.Repeat("00", 32), TxHash: "0x"},
	})
	if len(resp.Rejected) != 1 || !strings.Contains(resp.Rejected[0].Error, "reaching the node") {
		t.Fatalf("got %+v", resp)
	}
}
