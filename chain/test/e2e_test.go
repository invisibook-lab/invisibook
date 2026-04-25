package test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/invisibook-lab/invisibook/core"
)

const (
	httpURL = "http://localhost:7999"
)

// Pre-derived ed25519 seeds from BIP-39 mnemonics via SLIP-0010 at m/44'/60'/0'/0'/0'.
// alice mnemonic: "test test test test test test test test test test test junk"
// bob   mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
const (
	aliceDerivedSeedHex = "0728a1a2b488fdfe677ebe6de2558f251d7263f311bc0a57cd02b32f69878c5a"
	bobDerivedSeedHex   = "4e578ced277a96ec9507366a159f9ce5b70789bbe8f934d2bc8ef43c9c2bca77"
)

// deriveKeypair returns (privKey, pubkeyHex) from a 64-char hex seed string.
func deriveKeypair(t *testing.T, seedHex string) (ed25519.PrivateKey, string) {
	t.Helper()
	seed, err := hex.DecodeString(seedHex)
	if err != nil || len(seed) != 32 {
		t.Fatalf("invalid seed hex: %s", seedHex)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pubHex := hex.EncodeToString(priv.Public().(ed25519.PublicKey))
	return priv, pubHex
}

// signOrderID signs the order ID string with the given private key and returns a hex signature.
func signOrderID(priv ed25519.PrivateKey, orderID string) string {
	sig := ed25519.Sign(priv, []byte(orderID))
	return hex.EncodeToString(sig)
}

// ────────────────────── yu HTTP helpers ──────────────────────

// rdCall sends a reading request to the chain and returns the response body.
func rdCall(tripod, funcName string, params any) ([]byte, error) {
	paramsJSON, _ := json.Marshal(params)
	body := map[string]string{
		"tripod_name": tripod,
		"func_name":   funcName,
		"params":      string(paramsJSON),
	}
	bodyJSON, _ := json.Marshal(body)
	resp, err := http.Post(httpURL+"/api/reading", "application/json", bytes.NewReader(bodyJSON))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

// wrCall sends a writing request to the chain. Since PoA CheckTxn is a no-op, no signature is needed.
func wrCall(tripod, funcName string, params any) error {
	paramsJSON, _ := json.Marshal(params)
	body := map[string]any{
		"pubkey":    "",
		"address":   "",
		"signature": "",
		"call": map[string]any{
			"tripod_name": tripod,
			"func_name":   funcName,
			"params":      string(paramsJSON),
			"lei_price":   100,
			"tips":        0,
			"chain_id":    1926,
		},
	}
	bodyJSON, _ := json.Marshal(body)
	fmt.Printf("[wrCall] %s.%s params=%s\n", tripod, funcName, string(paramsJSON))
	resp, err := http.Post(httpURL+"/api/writing", "application/json", bytes.NewReader(bodyJSON))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	fmt.Printf("[wrCall] response (%d): %s\n", resp.StatusCode, string(b))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("writing failed (%d): %s", resp.StatusCode, string(b))
	}
	return nil
}

// waitBlock waits for a block to be produced so the writing takes effect.
func waitBlock() {
	time.Sleep(6 * time.Second)
}

// ────────────────────── Test ──────────────────────

func TestFullOrderLifecycle(t *testing.T) {
	// Derive keypairs from pre-computed BIP-39/SLIP-0010 seeds
	alicePriv, alicePubkey := deriveKeypair(t, aliceDerivedSeedHex)
	bobPriv, bobPubkey := deriveKeypair(t, bobDerivedSeedHex)
	t.Logf("alice pubkey: %s", alicePubkey)
	t.Logf("bob   pubkey: %s", bobPubkey)

	// --- Kill any old chain process on our ports ---
	exec.Command("bash", "-c", "lsof -ti:7999 -ti:8999 -ti:8887 | xargs kill -9 2>/dev/null").Run()
	time.Sleep(1 * time.Second)

	// --- Start chain process from chain/ directory ---
	chainDir := ".."
	os.RemoveAll(chainDir + "/data")

	cmd := exec.Command("./invisibook")
	cmd.Dir = chainDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start chain: %v", err)
	}
	defer func() {
		cmd.Process.Kill()
		cmd.Wait()
	}()

	// Wait for chain to start and produce first block
	time.Sleep(6 * time.Second)

	// ═══════════════════ Step 1: Query genesis accounts ═══════════════════
	t.Log("=== Step 1: Query genesis accounts ===")

	aliceETH := getAccount(t, alicePubkey, "ETH")
	t.Logf("Alice ETH cash: %d items", len(aliceETH))
	if len(aliceETH) != 1 {
		t.Fatalf("expected 1 ETH cash for alice, got %d", len(aliceETH))
	}
	aliceETHCashID := aliceETH[0].ID
	t.Logf("  cash_id=%s amount=%s", aliceETHCashID, aliceETH[0].Amount)

	bobUSDT := getAccount(t, bobPubkey, "USDT")
	t.Logf("Bob USDT cash: %d items", len(bobUSDT))
	if len(bobUSDT) != 1 {
		t.Fatalf("expected 1 USDT cash for bob, got %d", len(bobUSDT))
	}
	bobUSDTCashID := bobUSDT[0].ID
	t.Logf("  cash_id=%s amount=%s", bobUSDTCashID, bobUSDT[0].Amount)

	// ═══════════════════ Step 2: Alice sells 1 ETH at price 3500 ═══════════════════
	t.Log("=== Step 2: Alice sells ETH/USDT at price 3500 ===")

	sellOrderID := core.ComputeOrderID([]string{aliceETHCashID})
	t.Logf("  sell order ID: %s", sellOrderID)
	sellSig := signOrderID(alicePriv, string(sellOrderID))

	err := wrCall("orderbook", "SendOrder", map[string]any{
		"id":             sellOrderID,
		"type":           1, // Sell
		"subject":        map[string]string{"token1": "ETH", "token2": "USDT"},
		"price":          3500,
		"amount":         "1000",
		"pubkey":         alicePubkey,
		"signature":      sellSig,
		"input_cash_ids": []string{aliceETHCashID},
		"handling_fee":   []string{"0"},
	})
	if err != nil {
		t.Fatalf("SendOrder (sell) failed: %v", err)
	}
	waitBlock()

	// Verify alice's ETH cash is now Locked
	aliceETHAfterSell := getAccount(t, alicePubkey, "ETH")
	t.Logf("Alice ETH after sell order: %d active cash", len(aliceETHAfterSell))
	if len(aliceETHAfterSell) != 0 {
		t.Fatalf("expected 0 active ETH cash for alice (should be locked), got %d", len(aliceETHAfterSell))
	}

	// Verify sell order is Pending (no counter yet)
	orders := queryOrders(t, sellOrderID)
	t.Logf("  sell order status: %d", orders[0].Status)
	if orders[0].Status != 0 { // Pending
		t.Fatalf("expected sell order status Pending(0), got %d", orders[0].Status)
	}

	// ═══════════════════ Step 3: Bob buys ETH/USDT at price 3500 → match! ═══════════════════
	t.Log("=== Step 3: Bob buys ETH/USDT at price 3500 (should match) ===")

	buyOrderID := core.ComputeOrderID([]string{bobUSDTCashID})
	t.Logf("  buy order ID: %s", buyOrderID)
	buySig := signOrderID(bobPriv, string(buyOrderID))

	err = wrCall("orderbook", "SendOrder", map[string]any{
		"id":             buyOrderID,
		"type":           0, // Buy
		"subject":        map[string]string{"token1": "ETH", "token2": "USDT"},
		"price":          3500,
		"amount":         "500000",
		"pubkey":         bobPubkey,
		"signature":      buySig,
		"input_cash_ids": []string{bobUSDTCashID},
		"handling_fee":   []string{"0"},
	})
	if err != nil {
		t.Fatalf("SendOrder (buy) failed: %v", err)
	}
	waitBlock()

	// Verify both orders are now Matched
	sellOrders := queryOrders(t, sellOrderID)
	buyOrders := queryOrders(t, buyOrderID)
	if len(sellOrders) == 0 {
		t.Fatalf("sell order not found after buy order")
	}
	if len(buyOrders) == 0 {
		t.Fatalf("buy order not found after submission (may need longer waitBlock)")
	}
	t.Logf("  sell order status: %d, match_order: %s", sellOrders[0].Status, sellOrders[0].MatchOrder)
	t.Logf("  buy  order status: %d, match_order: %s", buyOrders[0].Status, buyOrders[0].MatchOrder)

	if sellOrders[0].Status != 1 { // Matched
		t.Fatalf("expected sell order status Matched(1), got %d", sellOrders[0].Status)
	}
	if buyOrders[0].Status != 1 { // Matched
		t.Fatalf("expected buy order status Matched(1), got %d", buyOrders[0].Status)
	}

	// ═══════════════════ Step 4: Settle the matched pair ═══════════════════
	t.Log("=== Step 4: Settle matched orders ===")

	err = wrCall("orderbook", "SettleOrder", map[string]any{
		"order_ids": []string{string(sellOrderID), string(buyOrderID)},
		"outputs": []map[string]string{
			{"pubkey": bobPubkey, "token": "ETH", "amount": "1000"},      // bob gets ETH
			{"pubkey": alicePubkey, "token": "USDT", "amount": "500000"}, // alice gets USDT
		},
		"zk_proof": "test-proof-skip",
	})
	if err != nil {
		t.Fatalf("SettleOrder failed: %v", err)
	}
	waitBlock()

	// Verify orders are Done
	sellFinal := queryOrders(t, sellOrderID)
	buyFinal := queryOrders(t, buyOrderID)
	t.Logf("  sell order final status: %d", sellFinal[0].Status)
	t.Logf("  buy  order final status: %d", buyFinal[0].Status)

	if sellFinal[0].Status != 2 { // Done
		t.Fatalf("expected sell order status Done(2), got %d", sellFinal[0].Status)
	}
	if buyFinal[0].Status != 2 { // Done
		t.Fatalf("expected buy order status Done(2), got %d", buyFinal[0].Status)
	}

	// ═══════════════════ Step 5: Verify final balances ═══════════════════
	t.Log("=== Step 5: Verify final balances ===")

	// Bob should now have ETH: genesis(1000) + settlement(1000) = 2 cash items
	bobETHFinal := getAccount(t, bobPubkey, "ETH")
	t.Logf("Bob ETH: %d cash items", len(bobETHFinal))
	if len(bobETHFinal) != 2 {
		t.Fatalf("expected bob to have 2 ETH cash (genesis + settlement), got %d", len(bobETHFinal))
	}
	for _, c := range bobETHFinal {
		t.Logf("  bob ETH cash: id=%s amount=%s", c.ID, c.Amount)
	}

	// Alice should now have USDT: genesis(500000) + settlement(500000) = 2 cash items
	aliceUSDTFinal := getAccount(t, alicePubkey, "USDT")
	t.Logf("Alice USDT: %d cash items", len(aliceUSDTFinal))
	if len(aliceUSDTFinal) != 2 {
		t.Fatalf("expected alice to have 2 USDT cash (genesis + settlement), got %d", len(aliceUSDTFinal))
	}
	for _, c := range aliceUSDTFinal {
		t.Logf("  alice USDT cash: id=%s amount=%s", c.ID, c.Amount)
	}

	// Alice's ETH should be gone (locked by sell order, then spent in settlement)
	aliceETHFinal := getAccount(t, alicePubkey, "ETH")
	t.Logf("Alice ETH: %d active cash items (should be 0, spent in settlement)", len(aliceETHFinal))
	if len(aliceETHFinal) != 0 {
		t.Fatalf("expected alice ETH to be 0 (spent), got %d", len(aliceETHFinal))
	}

	// Bob's USDT should be gone (locked by buy order, then spent in settlement)
	bobUSDTFinal := getAccount(t, bobPubkey, "USDT")
	t.Logf("Bob USDT: %d active cash items (should be 0, spent in settlement)", len(bobUSDTFinal))
	if len(bobUSDTFinal) != 0 {
		t.Fatalf("expected bob USDT to be 0 (spent), got %d", len(bobUSDTFinal))
	}

	t.Log("=== All tests passed! Full order lifecycle verified. ===")
}

// ────────────────────── Helpers ──────────────────────

type CashItem struct {
	ID      string `json:"id"`
	Pubkey  string `json:"pubkey"`
	Token   string `json:"token"`
	Amount  string `json:"amount"`
	ZkProof string `json:"zk_proof"`
	Status  int    `json:"status"`
	By      string `json:"by"`
}

type AccountResp struct {
	Pubkey string     `json:"pubkey"`
	Token  string     `json:"token"`
	Cash   []CashItem `json:"cash"`
}

func getAccount(t *testing.T, pubkey, token string) []CashItem {
	t.Helper()
	data, err := rdCall("account", "GetAccount", map[string]string{
		"pubkey": pubkey,
		"token":  token,
	})
	if err != nil {
		t.Fatalf("GetAccount failed: %v", err)
	}
	var resp AccountResp
	if err := json.Unmarshal(data, &resp); err != nil {
		t.Fatalf("parse GetAccount response failed: %v\nraw: %s", err, string(data))
	}
	return resp.Cash
}

type OrderItem struct {
	ID           string   `json:"id"`
	Status       int      `json:"status"`
	MatchOrder   string   `json:"match_order"`
	Pubkey       string   `json:"pubkey"`
	InputCashIDs []string `json:"input_cash_ids"`
}

type QueryOrdersResp struct {
	Orders []OrderItem `json:"orders"`
}

func queryOrders(t *testing.T, id core.OrderID) []OrderItem {
	t.Helper()
	params := map[string]any{}
	params["id"] = core.OrderID(id)

	data, err := rdCall("orderbook", "QueryOrders", params)
	if err != nil {
		t.Fatalf("QueryOrders failed: %v", err)
	}
	var resp QueryOrdersResp
	if err := json.Unmarshal(data, &resp); err != nil {
		t.Fatalf("parse QueryOrders response failed: %v\nraw: %s", err, string(data))
	}
	return resp.Orders
}
