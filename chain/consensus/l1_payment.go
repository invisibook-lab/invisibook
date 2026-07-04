package consensus

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

// PendingPaymentCh holds the latest L1 payment input submitted by external
// clients via the gin HTTP endpoint, ready for the consensus loop.
var PendingPaymentCh = make(chan *L1PaymentInput, 1)

// L1PaymentInput carries a payment hash submitted by an external client.
type L1PaymentInput struct {
	// PaymentHash is the L1 payment hash (e.g. from Fiber send_payment).
	PaymentHash string `json:"payment_hash"`
	// BlockHeight is the target block height this payment is intended for.
	BlockHeight uint64 `json:"block_height"`
}

// PayL1TokenRequest is the request body for the POST /pay_l1_token endpoint.
type PayL1TokenRequest struct {
	// Amount is the payment amount as hex u128, e.g. "0x64".
	Amount string `json:"amount"`
	// TargetPubkey is the Fiber target node pubkey in hex.
	TargetPubkey string `json:"target_pubkey"`
}

// FiberClient is a JSON-RPC client for the Fiber node.
type FiberClient struct {
	RPCUrl string
}

// fiberRPCRequest is a JSON-RPC 2.0 request payload.
type fiberRPCRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      int         `json:"id"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params"`
}

// fiberSendPaymentParams holds the params for send_payment RPC.
type fiberSendPaymentParams struct {
	TargetPubkey string `json:"target_pubkey"`
	Amount       string `json:"amount"`
}

// fiberRPCResponse is a JSON-RPC 2.0 response payload.
type fiberRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int             `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   json.RawMessage `json:"error"`
}

// fiberSendPaymentResult holds the result of send_payment RPC.
type fiberSendPaymentResult struct {
	PaymentHash string `json:"payment_hash"`
}

// SendPayment calls Fiber's send_payment JSON-RPC method.
// `amount` is the hex u128 amount, `targetPubkey` is the destination node pubkey.
func (fc *FiberClient) SendPayment(amount, targetPubkey string) (string, error) {
	reqBody := fiberRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "send_payment",
		Params: []fiberSendPaymentParams{
			{TargetPubkey: targetPubkey, Amount: amount},
		},
	}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("marshal rpc request: %w", err)
	}

	resp, err := http.Post(fc.RPCUrl, "application/json", bytes.NewReader(bodyBytes))
	if err != nil {
		return "", fmt.Errorf("fiber rpc call: %w", err)
	}
	defer resp.Body.Close()

	var rpcResp fiberRPCResponse
	if err = json.NewDecoder(resp.Body).Decode(&rpcResp); err != nil {
		return "", fmt.Errorf("decode rpc response: %w", err)
	}
	if rpcResp.Error != nil && string(rpcResp.Error) != "null" {
		return "", fmt.Errorf("fiber rpc error: %s", string(rpcResp.Error))
	}

	var result fiberSendPaymentResult
	if err = json.Unmarshal(rpcResp.Result, &result); err != nil {
		return "", fmt.Errorf("unmarshal rpc result: %w", err)
	}
	return result.PaymentHash, nil
}

// PaymentServer wraps the gin HTTP server for L1 payment requests.
type PaymentServer struct {
	fiberClient *FiberClient
}

// PayL1Token handles POST /pay_l1_token requests.
// It calls Fiber send_payment and pushes the result to PendingPaymentCh.
func (ps *PaymentServer) PayL1Token(c *gin.Context) {
	var req PayL1TokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Amount == "" || req.TargetPubkey == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "amount and target_pubkey are required"})
		return
	}

	paymentHash, err := ps.fiberClient.SendPayment(req.Amount, req.TargetPubkey)
	if err != nil {
		logrus.Errorf("PayL1Token: fiber send_payment failed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	input := &L1PaymentInput{
		PaymentHash: paymentHash,
		BlockHeight: 0,
	}

	// Drain stale value if present, then push the new one.
	select {
	case <-PendingPaymentCh:
	default:
	}
	PendingPaymentCh <- input

	c.JSON(http.StatusOK, gin.H{"payment_hash": paymentHash})
}

// StartPaymentServer starts a gin HTTP server that exposes the /pay_l1_token endpoint.
// `listenAddr` is the address to listen on (e.g. ":8081").
// `fiberRPCUrl` is the Fiber node JSON-RPC URL (e.g. "http://127.0.0.1:8227").
func StartPaymentServer(listenAddr, fiberRPCUrl string) {
	ps := &PaymentServer{fiberClient: &FiberClient{RPCUrl: fiberRPCUrl}}

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
