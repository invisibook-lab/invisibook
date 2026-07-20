package core

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"
)

// ────────────────────── PLONK Verifier Infrastructure ──────────────────────
//
// The 2-party collaborative settlement (cozk2p) produces a TurboPlonk/KZG
// proof that go-rapidsnark cannot verify. Verification is bridged over cgo to
// the `cozk2p` Rust staticlib (cozk2p/src/ffi.rs), compiled in only when the
// chain is built with `-tags cozk2p` — the default build stays pure Go and
// rejects PLONK settlements at runtime (see plonkverify_stub.go). This file
// is the only place that knows the bridge's wire formats.

// PlonkVK bundles the ark-compressed verifying-key bytes of a PLONK circuit
// with its name for error reporting, mirroring CircuitVK for Groth16.
type PlonkVK struct {
	Name    string
	VKBytes []byte
}

// LoadPlonkVK reads an ark-compressed PLONK verifying key from disk (the
// output of `dump_settle2p_fixture --vk-out`). When `path` is empty, returns
// nil — callers passing a nil VK to VerifyPlonkSettle2p skip verification
// (test environments without circuit artifacts), matching LoadVK's contract.
func LoadPlonkVK(name, path string) (*PlonkVK, error) {
	if path == "" {
		log.Printf("[zk] PLONK VK %q: path empty, verification will be skipped", name)
		return nil, nil
	}
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("loading PLONK VK %q from %s: %w", name, path, err)
	}
	if len(bytes) == 0 {
		return nil, fmt.Errorf("PLONK VK %q at %s is empty", name, path)
	}
	return &PlonkVK{Name: name, VKBytes: bytes}, nil
}

// VerifyPlonkSettle2p verifies `proofHex` (hex of the ark-compressed PLONK
// proof both traders revealed) against `vk` and `publicJSON`, the canonical
// `SettlePublic` statement JSON the chain rebuilt from on-chain state.
// Logs one line per call plus the verdict, like VerifyGroth16.
func VerifyPlonkSettle2p(vk *PlonkVK, proofHex string, publicJSON []byte) error {
	// When no VK is loaded (path was empty in config), skip verification.
	if vk == nil {
		log.Printf("[zk] no PLONK VK loaded, skipping proof verification")
		return nil
	}
	proofBytes, err := hex.DecodeString(strings.TrimSpace(proofHex))
	if err != nil {
		return fmt.Errorf("decoding %s proof hex: %w", vk.Name, err)
	}
	if len(proofBytes) == 0 || len(publicJSON) == 0 {
		return fmt.Errorf("%s proof or public statement is empty", vk.Name)
	}
	log.Printf("[zk] verifying %s: %d B proof (PLONK)", vk.Name, len(proofBytes))
	if err := plonkVerifySettle2p(vk.VKBytes, publicJSON, proofBytes); err != nil {
		log.Printf("[zk] %s REJECTED: %v", vk.Name, err)
		return fmt.Errorf("plonk verification failed for %s: %w", vk.Name, err)
	}
	log.Printf("[zk] %s ok", vk.Name)
	return nil
}
