package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// P1-1 regression: a missing config file must be an error, never a silent
// fall-back to defaults (main.go treats this error as fatal).
func TestLoadConfigMissingFileErrors(t *testing.T) {
	_, err := LoadConfig(filepath.Join(t.TempDir(), "no-such-core.toml"))
	if err == nil {
		t.Fatal("LoadConfig must error on a missing config file")
	}
}

// P1-1 regression: a malformed config file must be an error, never a silent
// fall-back to defaults.
func TestLoadConfigMalformedFileErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "core.toml")
	if err := os.WriteFile(path, []byte("[orderbook\ndb_path = broken"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("LoadConfig must error on malformed TOML")
	}
}

// P1-1 regression: the DEFAULT posture is fail-closed. Proof verification is
// required unless a config explicitly opts out with `require_proofs = false`.
func TestDefaultConfigRequiresProofs(t *testing.T) {
	cfg := DefaultConfig()
	if !cfg.OrderBook.RequireProofs {
		t.Fatal("DefaultConfig().OrderBook.RequireProofs must be true")
	}
	if !cfg.Account.RequireProofs {
		t.Fatal("DefaultConfig().Account.RequireProofs must be true")
	}
}

// P1-1 regression: a config that does not mention require_proofs keeps the
// secure default; only an explicit `require_proofs = false` enters dev mode.
func TestRequireProofsNeedsExplicitOptOut(t *testing.T) {
	dir := t.TempDir()
	implicit := filepath.Join(dir, "implicit.toml")
	if err := os.WriteFile(implicit,
		[]byte("[orderbook]\ndb_path = \"o.db\"\n\n[account]\ndb_path = \"a.db\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(implicit)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.OrderBook.RequireProofs || !cfg.Account.RequireProofs {
		t.Fatal("omitting require_proofs must keep the secure default (true)")
	}

	explicit := filepath.Join(dir, "explicit.toml")
	if err := os.WriteFile(explicit,
		[]byte("[orderbook]\ndb_path = \"o.db\"\nrequire_proofs = false\n\n"+
			"[account]\ndb_path = \"a.db\"\nrequire_proofs = false\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err = LoadConfig(explicit)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OrderBook.RequireProofs || cfg.Account.RequireProofs {
		t.Fatal("explicit require_proofs = false must be honored")
	}
}

// mustPanic runs f and reports the recovered panic message; it fails the
// test when f returns normally.
func mustPanic(t *testing.T, what string, f func()) string {
	t.Helper()
	var msg string
	func() {
		defer func() {
			if r := recover(); r != nil {
				if s, ok := r.(string); ok {
					msg = s
				} else {
					msg = "non-string panic"
				}
			}
		}()
		f()
		t.Fatalf("%s must refuse to construct (panic), but it returned", what)
	}()
	return msg
}

// P1-1 regression: with proofs required (the default), missing VK paths must
// refuse to boot — never silently fail open.
func TestOrderBookRefusesMissingVKsWhenProofsRequired(t *testing.T) {
	dir := t.TempDir()
	msg := mustPanic(t, "NewOrderBook", func() {
		NewOrderBook(&OrderBookConfig{
			DBPath:        filepath.Join(dir, "orders.db"),
			RequireProofs: true,
		})
	})
	if !strings.Contains(msg, "require_proofs") {
		t.Fatalf("panic must name require_proofs, got: %s", msg)
	}
}

// P1-1 regression: same fail-closed behavior for the Account tripod.
func TestAccountRefusesMissingVKsWhenProofsRequired(t *testing.T) {
	dir := t.TempDir()
	msg := mustPanic(t, "NewAccount", func() {
		NewAccount(&AccountConfig{
			DBPath:        filepath.Join(dir, "accounts.db"),
			RequireProofs: true,
		})
	})
	if !strings.Contains(msg, "require_proofs") {
		t.Fatalf("panic must name require_proofs, got: %s", msg)
	}
}

// The explicit dev opt-out still boots without circuit artifacts (test
// environments) — the opt-out is deliberate, not an accident of a broken
// config file.
func TestExplicitDevModeConstructsWithoutVKs(t *testing.T) {
	dir := t.TempDir()
	ot := NewOrderBook(&OrderBookConfig{
		DBPath:        filepath.Join(dir, "orders.db"),
		RequireProofs: false,
	})
	if ot == nil {
		t.Fatal("dev-mode OrderBook must construct")
	}
	a := NewAccount(&AccountConfig{
		DBPath:        filepath.Join(dir, "accounts.db"),
		RequireProofs: false,
	})
	if a == nil {
		t.Fatal("dev-mode Account must construct")
	}
}
