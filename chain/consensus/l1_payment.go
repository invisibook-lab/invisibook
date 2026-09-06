package consensus

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

// PendingPaymentCh holds the latest L1 payment input submitted by external
// clients via the gin HTTP endpoint, ready for the consensus loop.
var PendingPaymentCh = make(chan *L1PaymentInput, 1)

// L1PaymentInput carries a payment submitted by an external client.
type L1PaymentInput struct {
	// PaymentHash is the L1 payment transaction hash.
	PaymentHash string `json:"payment_hash"`
	// Amount is the payment amount as decimal string.
	Amount string `json:"amount"`
	// BlockHeight is the target block height this payment is intended for.
	BlockHeight uint64 `json:"block_height"`
}

// PayL1TokenRequest is the request body for the POST /pay_l1_token endpoint.
type PayL1TokenRequest struct {
	// PaymentHash is the L1 payment transaction hash.
	PaymentHash string `json:"payment_hash"`
	// Amount is the payment amount as decimal string, e.g. "100".
	Amount string `json:"amount"`
}

// PaymentServer wraps the gin HTTP server for L1 payment requests.
type PaymentServer struct{}

// PayL1Token handles POST /pay_l1_token requests.
// It accepts the L1 payment hash and amount directly, then pushes it
// to PendingPaymentCh for the consensus loop to consume.
func (ps *PaymentServer) PayL1Token(c *gin.Context) {
	var req PayL1TokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.PaymentHash == "" || req.Amount == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "payment_hash and amount are required"})
		return
	}

	input := &L1PaymentInput{
		PaymentHash: req.PaymentHash,
		Amount:      req.Amount,
		BlockHeight: 0,
	}

	// Drain stale value if present, then push the new one.
	select {
	case <-PendingPaymentCh:
	default:
	}
	PendingPaymentCh <- input

	c.JSON(http.StatusOK, gin.H{"payment_hash": req.PaymentHash})
}

// StartPaymentServer starts a gin HTTP server that exposes the /pay_l1_token endpoint.
// `listenAddr` is the address to listen on (e.g. ":8081").
func StartPaymentServer(listenAddr string) {
	ps := &PaymentServer{}

	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())
	r.POST("/pay_l1_token", ps.PayL1Token)

	go func() {
		logrus.Infof("PaymentServer: listening on %s", listenAddr)
		if err := r.Run(listenAddr); err != nil {
			logrus.Errorf("PaymentServer: failed to start: %v", err)
		}
	}()
}

// L1Payment represents a payment proof from L1.
// In Phase 1 this is fully mocked.
type L1Payment struct {
	// TxHash is the L1 transaction hash (mock: randomly generated).
	TxHash string `json:"tx_hash"`
	// Amount is the payment amount in the smallest unit.
	Amount *big.Int `json:"amount"`
	// Payer is the miner's L1 address.
	Payer string `json:"payer"`
	// MinerPubkey identifies which miner made this payment.
	MinerPubkey string `json:"miner_pubkey"`
}

// L1PaymentVerifier abstracts L1 payment verification.
// Implement this interface for each supported L1 (e.g. CKB).
type L1PaymentVerifier interface {
	// VerifyPayment checks whether the given payment exists on L1.
	VerifyPayment(ctx context.Context, payment *L1Payment) bool
}

// MockL1PaymentVerifier is a mock verifier used in Phase 1 / testing.
// VerifyPayment always returns true.
type MockL1PaymentVerifier struct{}

// VerifyPayment always returns true for mock usage.
func (m *MockL1PaymentVerifier) VerifyPayment(_ context.Context, _ *L1Payment) bool {
	return true
}

// MockL1Payment creates a mock L1 payment with the given amount and miner pubkey.
// `amount` must not be nil.
func MockL1Payment(amount *big.Int, minerPubkey string) *L1Payment {
	txHash := make([]byte, 32)
	// best-effort random; ignore error for mock usage
	_, _ = rand.Read(txHash)
	return &L1Payment{
		TxHash:      hex.EncodeToString(txHash),
		Amount:      new(big.Int).Set(amount),
		Payer:       "0xMOCK_PAYER",
		MinerPubkey: minerPubkey,
	}
}
