//go:build cozk2p

package core

import "testing"

// P1-4 smoke (tagged build): the default `make build-chain` binary must
// carry the real PLONK verifier, not the stub.
func TestPlonkVerifierLinked(t *testing.T) {
	if !PlonkVerifierAvailable() {
		t.Fatal("binary built with -tags cozk2p must report the PLONK verifier as available")
	}
}
