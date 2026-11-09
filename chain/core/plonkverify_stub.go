//go:build !cozk2p

package core

import "errors"

// plonkVerifySettle2p is the no-cgo stub. It is reachable only when a PLONK
// VK is configured but the chain binary was built without the cozk2p bridge;
// with no VK configured, VerifyPlonkSettle2p skips verification before
// getting here.
func plonkVerifySettle2p(_, _, _ []byte) error {
	return errors.New(
		"this chain binary was built without the cozk2p PLONK verifier; " +
			"rebuild with `make build-chain-cozk2p` (go build -tags cozk2p)")
}

// plonkVerifySettle2pShares is the no-cgo counterpart of the native
// proof-share verifier. A configured VK makes this error reachable; an empty
// VK path keeps the existing test-only verification skip behavior.
func plonkVerifySettle2pShares(_, _, _, _ []byte) error {
	return errors.New(
		"this chain binary was built without the cozk2p PLONK verifier; " +
			"rebuild with `make build-chain-cozk2p` (go build -tags cozk2p)")
}

// PlonkVerifierAvailable reports whether this binary carries the cozk2p
// PLONK verifier. The stub build does NOT: a node configured with a PLONK
// VK refuses to boot instead of accepting orders it can never settle.
func PlonkVerifierAvailable() bool { return false }
