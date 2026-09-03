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
