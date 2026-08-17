package test

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"
)

// TestShieldedPoolLifecycle drives the pool writings end-to-end against a
// real chain process with REAL proof verification:
//
//	genesis notes → NoteDeposit (+ replay rejection) →
//	NoteWithdraw (+ double-spend rejection) → chain restart →
//	pool state unchanged (genesis idempotency + frontier restore).
//
// Requires /tmp/pool_fixture.json from
// `cargo run -p invisibook-lib --example dump_pool_fixture` (whose --copy-vk
// artifacts must match chain/vk/*.json).
func TestShieldedPoolLifecycle(t *testing.T) {
	fx := loadPoolE2EFixture(t)

	// --- Config: real VKs, fixture genesis notes, no legacy genesis cash ---
	cfgPath := writePoolTestConfig(t, fx)

	// --- Boot the chain ---
	exec.Command("bash", "-c", "lsof -ti:7999 -ti:8999 -ti:8887 | xargs kill -9 2>/dev/null").Run()
	time.Sleep(1 * time.Second)
	chainDir := ".."
	os.RemoveAll(chainDir + "/data")
	startChain := func() *exec.Cmd {
		cmd := exec.Command("./invisibook", "--core-config", cfgPath)
		cmd.Dir = chainDir
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			t.Fatalf("failed to start chain: %v", err)
		}
		time.Sleep(6 * time.Second)
		return cmd
	}
	cmd := startChain()
	stopped := false
	defer func() {
		if !stopped {
			cmd.Process.Kill()
			cmd.Wait()
		}
	}()

	// --- Genesis pool seeded: 3 leaves, root = fixture anchor ---
	info := getPoolInfo(t)
	if info.LeafCount != 3 || info.LatestRoot != fx.Anchor {
		t.Fatalf("genesis pool wrong: %d leaves root %s (want 3 / %s)",
			info.LeafCount, info.LatestRoot, fx.Anchor)
	}

	// --- NoteDeposit with the fixture proof ---
	depositParams := map[string]any{
		"token":             fx.Deposit.Token,
		"bridge_commitment": fx.Deposit.BridgeCommitment,
		"output_commitment": fx.Deposit.OutputCommitment,
		"zk_proof":          string(fx.Deposit.ProofJSON),
	}
	if err := wrCall("account", "NoteDeposit", depositParams); err != nil {
		t.Fatalf("NoteDeposit failed: %v", err)
	}
	waitBlock()
	if got := getPoolInfo(t); got.LeafCount != 4 {
		t.Fatalf("deposit must append leaf 3, pool has %d leaves", got.LeafCount)
	}

	// Replay of the same bridge commitment must be rejected — either by
	// yu's txpool (identical txn → 400) or by the bridge_seen dedup in the
	// handler. Either way the pool must not grow.
	if err := wrCall("account", "NoteDeposit", depositParams); err != nil {
		t.Logf("deposit replay rejected at submission: %v", err)
	}
	waitBlock()
	if got := getPoolInfo(t); got.LeafCount != 4 {
		t.Fatalf("deposit replay must not mint again, pool has %d leaves", got.LeafCount)
	}

	// --- NoteWithdraw with the fixture proof (anchor = genesis root, which
	// stays valid after the deposit because anchors accumulate) ---
	withdrawParams := map[string]any{
		"token":                 fx.Withdraw.Token,
		"anchor":                fx.Withdraw.Anchor,
		"nullifiers":            fx.Withdraw.Nullifiers,
		"bridge_out_commitment": fx.Withdraw.BridgeOutCommitment,
		"change_commitment":     fx.Withdraw.ChangeCommitment,
		"zk_proof":              string(fx.Withdraw.ProofJSON),
	}
	if err := wrCall("account", "NoteWithdraw", withdrawParams); err != nil {
		t.Fatalf("NoteWithdraw failed: %v", err)
	}
	waitBlock()
	if got := getPoolInfo(t); got.LeafCount != 5 {
		t.Fatalf("withdraw must append the change leaf, pool has %d leaves", got.LeafCount)
	}
	spent := getNullifiers(t, fx.Withdraw.Nullifiers)
	if !spent[0] || !spent[1] {
		t.Fatalf("both nullifiers must be spent, got %v", spent)
	}

	// Double spend: replaying the withdraw must be rejected — by the
	// txpool (identical txn) or by the nullifier set. The pool must not
	// grow either way.
	if err := wrCall("account", "NoteWithdraw", withdrawParams); err != nil {
		t.Logf("withdraw replay rejected at submission: %v", err)
	}
	waitBlock()
	if got := getPoolInfo(t); got.LeafCount != 5 {
		t.Fatalf("double spend must not mint again, pool has %d leaves", got.LeafCount)
	}

	rootBefore := getPoolInfo(t).LatestRoot

	// --- Restart: genesis re-seeding must be a no-op, frontier restored ---
	cmd.Process.Kill()
	cmd.Wait()
	stopped = true
	time.Sleep(1 * time.Second)
	cmd2 := startChain()
	defer func() {
		cmd2.Process.Kill()
		cmd2.Wait()
	}()

	after := getPoolInfo(t)
	if after.LeafCount != 5 || after.LatestRoot != rootBefore {
		t.Fatalf("restart changed the pool: %d leaves root %s (want 5 / %s)",
			after.LeafCount, after.LatestRoot, rootBefore)
	}

	// The change commitment is findable (client recovery predicate).
	leafIdx := getNoteByCm(t, fx.Withdraw.ChangeCommitment)
	if leafIdx != 4 {
		t.Fatalf("change note must sit at leaf 4, got %d", leafIdx)
	}

	t.Log("=== Shielded pool lifecycle verified: deposit, replay rejection, withdraw, double-spend rejection, restart. ===")
}

// ────────────────────── Fixture + config plumbing ──────────────────────

type poolE2EFixture struct {
	ChainID      uint64             `json:"chain_id"`
	GenesisNotes []string           `json:"genesis_notes"`
	Anchor       string             `json:"anchor"`
	Deposit      poolE2EDepositFix  `json:"deposit"`
	Withdraw     poolE2EWithdrawFix `json:"withdraw"`
}

type poolE2EDepositFix struct {
	Token            string          `json:"token"`
	BridgeCommitment string          `json:"bridge_commitment"`
	OutputCommitment string          `json:"output_commitment"`
	ProofJSON        json.RawMessage `json:"proof_json"`
}

type poolE2EWithdrawFix struct {
	Token               string          `json:"token"`
	Anchor              string          `json:"anchor"`
	Nullifiers          []string        `json:"nullifiers"`
	BridgeOutCommitment string          `json:"bridge_out_commitment"`
	ChangeCommitment    string          `json:"change_commitment"`
	ProofJSON           json.RawMessage `json:"proof_json"`
}

func loadPoolE2EFixture(t *testing.T) poolE2EFixture {
	t.Helper()
	raw, err := os.ReadFile("/tmp/pool_fixture.json")
	if err != nil {
		t.Skip("fixture not found — run `cargo run -p invisibook-lib --example dump_pool_fixture -- /tmp/pool_fixture.json --copy-vk`")
	}
	var fx poolE2EFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("decoding fixture: %v", err)
	}
	return fx
}

// writePoolTestConfig renders a core config with REAL pool VKs and the
// fixture's genesis notes (no genesis cash, no legacy VKs).
func writePoolTestConfig(t *testing.T, fx poolE2EFixture) string {
	t.Helper()
	cfg := fmt.Sprintf("chain_id = %d\n\n[orderbook]\ndb_path = \"data/orders.db\"\nrequire_proofs = false\n\n[account]\ndb_path = \"data/accounts.db\"\nnote_deposit_vk_path   = \"vk/note_deposit_vk.json\"\nspend_withdraw_vk_path = \"vk/spend_withdraw_vk.json\"\n", fx.ChainID)
	for i, cm := range fx.GenesisNotes {
		cfg += fmt.Sprintf("\n[[account.genesis_note]]\ncm = %q\nmemo = \"golden leaf %d\"\n", cm, i)
	}
	path := "cfg/tests/pool_e2e_test.toml"
	if err := os.WriteFile("../"+path, []byte(cfg), 0o644); err != nil {
		t.Fatalf("writing pool test config: %v", err)
	}
	return path
}

// ────────────────────── Reading helpers ──────────────────────

type poolInfoResp struct {
	LeafCount  uint64 `json:"leaf_count"`
	LatestRoot string `json:"latest_root"`
}

func getPoolInfo(t *testing.T) poolInfoResp {
	t.Helper()
	data, err := rdCall("account", "GetPoolInfo", map[string]any{})
	if err != nil {
		t.Fatalf("GetPoolInfo failed: %v", err)
	}
	var resp poolInfoResp
	if err := json.Unmarshal(data, &resp); err != nil {
		t.Fatalf("parse GetPoolInfo: %v\nraw: %s", err, data)
	}
	return resp
}

func getNullifiers(t *testing.T, nfs []string) []bool {
	t.Helper()
	data, err := rdCall("account", "GetNullifiers", map[string]any{"nullifiers": nfs})
	if err != nil {
		t.Fatalf("GetNullifiers failed: %v", err)
	}
	var resp struct {
		Spent []bool `json:"spent"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		t.Fatalf("parse GetNullifiers: %v\nraw: %s", err, data)
	}
	return resp.Spent
}

func getNoteByCm(t *testing.T, cm string) int64 {
	t.Helper()
	data, err := rdCall("account", "GetNoteByCm", map[string]any{"cm": cm})
	if err != nil {
		t.Fatalf("GetNoteByCm failed: %v", err)
	}
	var resp struct {
		LeafIndex int64 `json:"leaf_index"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		t.Fatalf("parse GetNoteByCm: %v\nraw: %s", err, data)
	}
	return resp.LeafIndex
}
