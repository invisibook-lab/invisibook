package test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
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

// signedSendOrder builds a SendOrderRequest whose ID derives from
// `inputCashIDs`, then signs the canonical signing message (which covers
// every field, see core.SendOrderSigningMessage) with `priv`. The returned
// request serializes to the exact JSON payload SendOrder expects.
// `price` must be non-zero (all tests trade at an explicit price).
// canonicalHex renders a 32-byte seed as a canonical field-element hex
// (leading zero byte keeps it below the modulus) for test placeholders.
func canonicalHex(seed string) string {
	h := sha256.Sum256([]byte(seed))
	h[0] = 0
	return hex.EncodeToString(h[:])
}

// signedSendOrder builds a v4 SendOrder request for test mode (proof
// verification skipped). `seed` distinguishes the two nullifiers and the
// anchor is the always-valid empty-tree root. Locked-only model: the order
// carries ONE commitment. When `locked` is already a 64-char hex it becomes
// the row's LockedCommitment verbatim (real-proof e2e tests seed the exact
// commitments a fixture proved against); any other string only salts a
// canonical placeholder.
func signedSendOrder(priv ed25519.PrivateKey, tradeType core.TradeType, token1, token2 string,
	price uint64, locked, pubkey string, seed []string) *core.SendOrderRequest {
	tag := pubkey
	if len(seed) > 0 {
		tag = seed[0]
	}
	collNfs := []string{canonicalHex("coll-nf0:" + tag), canonicalHex("coll-nf1:" + tag)}
	feeNfs := []string{canonicalHex("fee-nf0:" + tag), canonicalHex("fee-nf1:" + tag)}
	nfs := append(append([]string{}, collNfs...), feeNfs...)
	lockedCommitment := locked
	if len(lockedCommitment) != 64 {
		lockedCommitment = canonicalHex("locked:" + tag + ":" + locked)
	}
	req := &core.SendOrderRequest{
		ID:                         core.ComputeOrderID(nfs),
		Kind:                       core.Limit,
		Type:                       tradeType,
		Subject:                    core.TradePair{Token1: core.TokenID(token1), Token2: core.TokenID(token2)},
		Price:                      new(big.Int).SetUint64(price),
		Pubkey:                     pubkey,
		Anchor:                     core.FrToHex(core.EmptyRoot(core.TreeDepth)),
		CollateralNullifiers:       collNfs,
		FeeNullifiers:              feeNfs,
		LockedCommitment:           lockedCommitment,
		Fee:                        0,
		CollateralChangeCommitment: canonicalHex("coll-change:" + tag),
		FeeChangeCommitment:        canonicalHex("fee-change:" + tag),
		ZkProof:                    "test-proof-skip",
	}
	req.Signature = hex.EncodeToString(ed25519.Sign(priv, core.SendOrderSigningMessage(req)))
	return req
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

	// ═══════════════════ Step 1: Note-model funding ═══════════════════
	// v2 orders spend pool notes by nullifier; in test mode (proof checks
	// skipped) the nullifiers are derived from per-trader tag strings.
	t.Log("=== Step 1: Note-model funding (nullifier tags) ===")
	aliceTag := "alice-eth-note"
	bobTag := "bob-usdt-note"

	// ═══════════════════ Step 2: Alice sells 1 ETH at price 3500 ═══════════════════
	t.Log("=== Step 2: Alice sells ETH/USDT at price 3500 ===")

	sellReq := signedSendOrder(alicePriv, core.Sell, "ETH", "USDT",
		3500, "1000", alicePubkey, []string{aliceTag})
	sellOrderID := sellReq.ID
	t.Logf("  sell order ID: %s", sellOrderID)

	err = wrCall("orderbook", "SendOrder", sellReq)
	if err != nil {
		t.Fatalf("SendOrder (sell) failed: %v", err)
	}
	waitBlock()

	// In v2 an order spends pool notes and carries its collateral as a
	// commitment on the order row — the genesis cash is untouched. Verify the
	// order landed with its collateral commitment.
	sellStored := queryOrders(t, sellOrderID)[0]
	if sellStored.LockedCommitment == "" {
		t.Fatalf("sell order must carry a locked collateral commitment")
	}

	// Verify sell order is Pending (no counter yet)
	orders := queryOrders(t, sellOrderID)
	t.Logf("  sell order status: %d", orders[0].Status)
	if orders[0].Status != 0 { // Pending
		t.Fatalf("expected sell order status Pending(0), got %d", orders[0].Status)
	}

	// ═══════════════════ Step 3: Bob buys ETH/USDT at price 3500 → match! ═══════════════════
	t.Log("=== Step 3: Bob buys ETH/USDT at price 3500 (should match) ===")

	buyReq := signedSendOrder(bobPriv, core.Buy, "ETH", "USDT",
		3500, "500000", bobPubkey, []string{bobTag})
	buyOrderID := buyReq.ID
	t.Logf("  buy order ID: %s", buyOrderID)

	err = wrCall("orderbook", "SendOrder", buyReq)
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
	aliceAddrReq := &core.RegisterSettleAddrRequest{
		OrderID: sellOrderID, MatchOrderID: buyOrderID, MatchRound: sellOrders[0].MatchRound,
		Addr: "127.0.0.1:9001", EncryptionPubkey: canonicalHex("alice-x25519"),
	}
	aliceAddrReq.Signature = hex.EncodeToString(ed25519.Sign(alicePriv, core.SettleAddrSigningMessage(aliceAddrReq)))
	err = wrCall("orderbook", "RegisterSettleAddr", aliceAddrReq)
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
	bobAddrReq := &core.RegisterSettleAddrRequest{
		OrderID: buyOrderID, MatchOrderID: sellOrderID, MatchRound: buyOrders[0].MatchRound,
		Addr: "127.0.0.1:9002", EncryptionPubkey: canonicalHex("bob-x25519"),
	}
	bobAddrReq.Signature = hex.EncodeToString(ed25519.Sign(bobPriv, core.SettleAddrSigningMessage(bobAddrReq)))
	err = wrCall("orderbook", "RegisterSettleAddr", bobAddrReq)
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

	t.Log("=== All steps passed: SendOrder (note model), matching, rendezvous. ===")
	t.Log("Settlement coverage lives in cozk_e2e_test.go and cozk2p_real_proof_test.go.")
}

// ────────────────────── Helpers ──────────────────────

type OrderItem struct {
	ID               string `json:"id"`
	Status           int    `json:"status"`
	MatchOrder       string `json:"match_order"`
	Pubkey           string `json:"pubkey"`
	LockedCommitment string `json:"locked_commitment"`
	MatchRound       uint64 `json:"match_round"`
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
