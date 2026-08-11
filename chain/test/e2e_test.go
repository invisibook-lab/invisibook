package test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/gorilla/websocket"
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

	cmd := exec.Command("./invisibook", "--core-config", "cfg/tests/core_test.toml")
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

	// ═══════════════════ WS Event Subscriber ═══════════════════
	t.Log("=== Starting WS event subscriber ===")
	wsURL := "ws://localhost:8999/subscribe/results"
	wsConn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Logf("[ws] WARNING: failed to connect: %v (continuing without WS)", err)
	} else {
		t.Log("[ws] connected to", wsURL)
		defer wsConn.Close()
		go func() {
			for {
				_, msg, err := wsConn.ReadMessage()
				if err != nil {
					fmt.Printf("[ws] read error (connection closed): %v\n", err)
					return
				}
				// Pretty-print: try to parse as JSON
				var raw map[string]any
				if json.Unmarshal(msg, &raw) == nil {
					tripod, _ := raw["tripod_name"].(string)
					writing, _ := raw["writing_name"].(string)
					errStr, _ := raw["error"].(string)
					events, _ := raw["events"].([]any)
					fmt.Printf("\n[ws] ════════════ RECEIPT ════════════\n")
					fmt.Printf("[ws]   tripod:  %s\n", tripod)
					fmt.Printf("[ws]   writing: %s\n", writing)
					if errStr != "" {
						fmt.Printf("[ws]   error:   %s\n", errStr)
					}
					fmt.Printf("[ws]   events:  %d\n", len(events))
					for i, ev := range events {
						evMap, ok := ev.(map[string]any)
						if !ok {
							fmt.Printf("[ws]   event[%d]: %v\n", i, ev)
							continue
						}
						// Go json.Marshal([]byte) → base64 string
						valueB64, _ := evMap["value"].(string)
						valueBytes, decErr := base64.StdEncoding.DecodeString(valueB64)
						if decErr != nil {
							fmt.Printf("[ws]   event[%d] raw: %s\n", i, valueB64)
							continue
						}
						// Pretty-print the decoded JSON
						var eventData map[string]any
						if json.Unmarshal(valueBytes, &eventData) == nil {
							pretty, _ := json.MarshalIndent(eventData, "[ws]     ", "  ")
							fmt.Printf("[ws]   event[%d]: %s\n", i, string(pretty))
						} else {
							fmt.Printf("[ws]   event[%d]: %s\n", i, string(valueBytes))
						}
					}
					fmt.Printf("[ws] ════════════════════════════════\n\n")
				} else {
					fmt.Printf("[ws] raw: %s\n", string(msg))
				}
			}
		}()
	}

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

	err = wrCall("orderbook", "SendOrder", map[string]any{
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

	// Verify alice's ETH cash is now Locked (GetAccount returns Active+Locked, not Spent)
	aliceETHAfterSell := getAccount(t, alicePubkey, "ETH")
	t.Logf("Alice ETH after sell order: %d non-spent cash", len(aliceETHAfterSell))
	activeCount := 0
	for _, c := range aliceETHAfterSell {
		t.Logf("  cash id=%s status=%d", c.ID, c.Status)
		if c.Status == 0 { // Active
			activeCount++
		}
	}
	if activeCount != 0 {
		t.Fatalf("expected 0 active ETH cash for alice (should be locked), got %d active", activeCount)
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

	// ═══════════════════ Step 3.5: Settle address exchange ═══════════════════
	t.Log("=== Step 3.5a: Alice registers settle addr ===")
	err = wrCall("orderbook", "RegisterSettleAddr", map[string]any{
		"order_id":       string(sellOrderID),
		"match_order_id": string(buyOrderID),
		"addr":           "127.0.0.1:9001",
	})
	if err != nil {
		t.Fatalf("RegisterSettleAddr (alice) failed: %v", err)
	}
	waitBlock()

	// Query from bob's side — should see alice's addr
	aliceAddr := querySettleAddr(t, string(buyOrderID), string(sellOrderID))
	t.Logf("  alice settle addr (seen by bob): %q", aliceAddr)
	if aliceAddr != "127.0.0.1:9001" {
		t.Fatalf("expected alice addr '127.0.0.1:9001', got %q", aliceAddr)
	}

	// Query bob's addr from alice's side — should be empty (not yet registered)
	bobAddr := querySettleAddr(t, string(sellOrderID), string(buyOrderID))
	t.Logf("  bob settle addr (seen by alice): %q", bobAddr)
	if bobAddr != "" {
		t.Fatalf("expected bob addr empty, got %q", bobAddr)
	}

	t.Log("=== Step 3.5b: Bob registers settle addr ===")
	err = wrCall("orderbook", "RegisterSettleAddr", map[string]any{
		"order_id":       string(buyOrderID),
		"match_order_id": string(sellOrderID),
		"addr":           "127.0.0.1:9002",
	})
	if err != nil {
		t.Fatalf("RegisterSettleAddr (bob) failed: %v", err)
	}
	waitBlock()

	// Now alice can see bob's addr
	bobAddr = querySettleAddr(t, string(sellOrderID), string(buyOrderID))
	t.Logf("  bob settle addr (seen by alice): %q", bobAddr)
	if bobAddr != "127.0.0.1:9002" {
		t.Fatalf("expected bob addr '127.0.0.1:9002', got %q", bobAddr)
	}

	// ═══════════════════ Step 4: CompareOrders (MPC phase) ═══════════════════
	t.Log("=== Step 4a: Alice submits CompareOrders (first party) ===")

	// Build test MPC shares where cmp=1 (buy >= sell, sell is smaller).
	aliceMpcShare, bobMpcShare := buildTestMpcShares(t)

	// Alice's compare submission (sell side)
	err = wrCall("orderbook", "CompareOrders", map[string]any{
		"order_id":       string(sellOrderID),
		"match_order_id": string(buyOrderID),
		"mpc_share":      aliceMpcShare,
	})
	if err != nil {
		t.Fatalf("CompareOrders (alice) failed: %v", err)
	}
	waitBlock()

	// Verify orders are still Matched after first submission
	sellAfterFirst := queryOrders(t, sellOrderID)
	buyAfterFirst := queryOrders(t, buyOrderID)
	t.Logf("  sell order status after first compare: %d", sellAfterFirst[0].Status)
	t.Logf("  buy  order status after first compare: %d", buyAfterFirst[0].Status)
	if sellAfterFirst[0].Status != 1 { // still Matched
		t.Fatalf("expected sell order still Matched(1) after first compare, got %d", sellAfterFirst[0].Status)
	}
	if buyAfterFirst[0].Status != 1 { // still Matched
		t.Fatalf("expected buy order still Matched(1) after first compare, got %d", buyAfterFirst[0].Status)
	}

	t.Log("=== Step 4b: Bob submits CompareOrders (second party → triggers comparison) ===")

	// Bob's compare submission (buy side)
	err = wrCall("orderbook", "CompareOrders", map[string]any{
		"order_id":       string(buyOrderID),
		"match_order_id": string(sellOrderID),
		"mpc_share":      bobMpcShare,
	})
	if err != nil {
		t.Fatalf("CompareOrders (bob) failed: %v", err)
	}
	waitBlock()

	// Verify both orders are now Settling (status=5)
	sellAfterCompare := queryOrders(t, sellOrderID)
	buyAfterCompare := queryOrders(t, buyOrderID)
	t.Logf("  sell order status after compare: %d, is_smaller: %v",
		sellAfterCompare[0].Status, sellAfterCompare[0].IsSmaller)
	t.Logf("  buy  order status after compare: %d, is_smaller: %v",
		buyAfterCompare[0].Status, buyAfterCompare[0].IsSmaller)

	if sellAfterCompare[0].Status != 5 { // Settling
		t.Fatalf("expected sell order status Settling(5), got %d", sellAfterCompare[0].Status)
	}
	if buyAfterCompare[0].Status != 5 { // Settling
		t.Fatalf("expected buy order status Settling(5), got %d", buyAfterCompare[0].Status)
	}
	// cmp=1 means buy>=sell, so sell side is smaller
	if !sellAfterCompare[0].IsSmaller {
		t.Fatalf("expected sell order IsSmaller=true (cmp=1 means sell is smaller)")
	}
	if buyAfterCompare[0].IsSmaller {
		t.Fatalf("expected buy order IsSmaller=false (cmp=1 means buy is larger)")
	}

	// Everything above — deposit, split, SendOrder, matching, CompareOrders —
	// is still live and has been asserted. The remaining steps drive the
	// legacy `SettleOrders` writing, which is no longer registered because it
	// mints from an unconstrained commitment (see the DO NOT RE-REGISTER note
	// on the handler). Settlement coverage lives in cozk_e2e_test.go and
	// cozk2p_real_proof_test.go.
	t.Skip("legacy SettleOrders path is unregistered; see cozk2p_real_proof_test.go for settlement")

	// ═══════════════════ Step 5: SettleOrders (ZK phase) ═══════════════════
	t.Log("=== Step 5a: Alice submits SettleOrders (sell=smaller, no leg) ===")

	// Alice's settle submission (sell side = smaller, no ZK proof required)
	err = wrCall("orderbook", "SettleOrders", map[string]any{
		"order_id":       string(sellOrderID),
		"match_order_id": string(buyOrderID),
	})
	if err != nil {
		t.Fatalf("SettleOrders (alice) failed: %v", err)
	}
	waitBlock()

	// Verify orders are still Settling after first settle submission
	sellAfterSettle1 := queryOrders(t, sellOrderID)
	buyAfterSettle1 := queryOrders(t, buyOrderID)
	t.Logf("  sell order status after first settle: %d", sellAfterSettle1[0].Status)
	t.Logf("  buy  order status after first settle: %d", buyAfterSettle1[0].Status)
	if sellAfterSettle1[0].Status != 5 { // still Settling
		t.Fatalf("expected sell order still Settling(5) after first settle, got %d", sellAfterSettle1[0].Status)
	}
	if buyAfterSettle1[0].Status != 5 { // still Settling
		t.Fatalf("expected buy order still Settling(5) after first settle, got %d", buyAfterSettle1[0].Status)
	}

	t.Log("=== Step 5b: Bob submits SettleOrders (buy=larger, triggers settlement) ===")

	// Bob's settle submission (buy side = larger).
	// recv_commitment/recv_pubkey = what the smaller party (Alice) receives in USDT.
	// other_match_commitment = what the larger party (Bob) receives from smaller's
	// token (ETH), minted by the chain using this commitment.
	err = wrCall("orderbook", "SettleOrders", map[string]any{
		"order_id":       string(buyOrderID),
		"match_order_id": string(sellOrderID),
		"leg": map[string]any{
			"side":                   "larger",
			"token":                  "USDT",
			"my_match_commitment":    "0000000000000000000000000000000000000000000000000000000000001234",
			"other_match_commitment": "0000000000000000000000000000000000000000000000000000000000005678",
			"price":                  3500,
			"is_token2_sender":       true,
			"change_commitment":      "2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864",
			"recv_commitment":        "0000000000000000000000000000000000000000000000000000000000009abc",
			"recv_pubkey":            alicePubkey,
			"zk_proof":               "test-proof-skip",
		},
	})
	if err != nil {
		t.Fatalf("SettleOrders (bob) failed: %v", err)
	}
	waitBlock()

	// Verify orders are Done after second settle submission
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

	// ═══════════════════ Step 6: Verify final balances ═══════════════════
	t.Log("=== Step 6: Verify final balances ===")

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

	// ═══════════════════ Step 7: Verify settle addrs cleaned up ═══════════════════
	t.Log("=== Step 7: Verify settle addrs cleaned up after settlement ===")
	aliceAddrAfter := querySettleAddr(t, string(buyOrderID), string(sellOrderID))
	bobAddrAfter := querySettleAddr(t, string(sellOrderID), string(buyOrderID))
	if aliceAddrAfter != "" {
		t.Fatalf("expected alice settle addr cleaned up, got %q", aliceAddrAfter)
	}
	if bobAddrAfter != "" {
		t.Fatalf("expected bob settle addr cleaned up, got %q", bobAddrAfter)
	}
	t.Log("  settle addrs cleaned up correctly")

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
	Amount       string   `json:"amount"`
	MatchOrder   string   `json:"match_order"`
	Pubkey       string   `json:"pubkey"`
	InputCashIDs []string `json:"input_cash_ids"`
	IsSmaller    bool     `json:"is_smaller"`
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

// querySettleAddr queries the counterparty's registered settle address.
// Returns empty string if not yet registered.
func querySettleAddr(t *testing.T, orderID, matchOrderID string) string {
	t.Helper()
	data, err := rdCall("orderbook", "QuerySettleAddr", map[string]string{
		"order_id":       orderID,
		"match_order_id": matchOrderID,
	})
	if err != nil {
		t.Fatalf("QuerySettleAddr failed: %v", err)
	}
	var resp struct {
		Addr string `json:"addr"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		t.Fatalf("parse QuerySettleAddr response failed: %v\nraw: %s", err, string(data))
	}
	return resp.Addr
}

// buildTestMpcShares constructs two MPC share maps that satisfy the SPDZ MAC
// equation: (mac_A + mac_B) == (delta_A + delta_B) * (share_A + share_B).
// Uses small known values where cmp=1 (buy >= sell, sell is smaller).
func buildTestMpcShares(t *testing.T) (map[string]string, map[string]string) {
	t.Helper()

	// delta_A = 7, delta_B = 11 → delta = 18
	//
	// cmp: share_A = 0, share_B = 1 → cmp = 1 (buy >= sell, sell is smaller)
	// cmp_mac_A + cmp_mac_B = delta * cmp = 18 * 1 = 18
	// Let cmp_mac_A = 8, cmp_mac_B = 10
	//
	// r_smaller: share_A = 42, share_B = 0 → r_smaller = 42
	// r_smaller_mac_A + r_smaller_mac_B = delta * r_smaller = 18 * 42 = 756
	// Let r_smaller_mac_A = 356, r_smaller_mac_B = 400
	alice := map[string]string{
		"cmp_share":        "0",
		"cmp_mac":          "8",
		"r_smaller_share":  "42",
		"r_smaller_mac":    "356",
		"mac_key_share":    "7",
	}
	bob := map[string]string{
		"cmp_share":        "1",
		"cmp_mac":          "10",
		"r_smaller_share":  "0",
		"r_smaller_mac":    "400",
		"mac_key_share":    "11",
	}
	return alice, bob
}
