//go:build !cozk2p

package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// P1-4 regression (stub build): a node configured for collaborative
// settlement must refuse to boot when the binary lacks the PLONK verifier —
// never start as a node that accepts orders it can never settle.
func TestStubBinaryRefusesPlonkConfiguredNode(t *testing.T) {
	if PlonkVerifierAvailable() {
		t.Skip("built with -tags cozk2p; the stub refusal does not apply")
	}
	dir := t.TempDir()
	vk := filepath.Join(dir, "settle_cozk2p_vk.bin")
	if err := os.WriteFile(vk, []byte{0x01, 0x02}, 0o644); err != nil {
		t.Fatal(err)
	}
	msg := mustPanic(t, "NewOrderBook", func() {
		NewOrderBook(&OrderBookConfig{
			DBPath:             filepath.Join(dir, "orders.db"),
			SettleCoZk2pVKPath: vk,
			RequireProofs:      false,
		})
	})
	if !strings.Contains(msg, "cozk2p") {
		t.Fatalf("panic must name the missing cozk2p verifier, got: %s", msg)
	}
}
