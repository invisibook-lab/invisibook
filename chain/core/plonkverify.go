package core

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
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

// VerifyPlonkSettle2p verifies `proofHex` (hex of one complete
// ark-compressed PLONK proof) against `vk` and `publicJSON`, the canonical
// `SettlePublic` statement JSON the chain rebuilt from on-chain state.
// Logs one line per call plus the verdict, like VerifyGroth16.
func VerifyPlonkSettle2p(vk *PlonkVK, proofHex string, publicJSON []byte) error {
	return verifyPlonkWith(vk, proofHex, publicJSON, plonkVerifySettle2p)
}

// VerifyPlonkSettle2pShares verifies a collaborative comparison without ever
// reconstructing its proof in Go. shareAHex and shareBHex are opaque
// versioned canonical payloads emitted by PARTY0 and PARTY1 respectively;
// Rust checks their common public transcript, group-adds their two final KZG
// point shares, and verifies the resulting proof.
func VerifyPlonkSettle2pShares(
	vk *PlonkVK, shareAHex, shareBHex string, publicJSON []byte,
) error {
	return verifyPlonkSharesWith(vk, shareAHex, shareBHex, publicJSON, plonkVerifySettle2pShares)
}

// verifyPlonkWith is the shared decode/log/skip shell around one FFI
// verifier entry. A nil VK (empty path in config) skips verification.
func verifyPlonkWith(
	vk *PlonkVK, proofHex string, publicJSON []byte,
	verify func(vkBytes, publicJSON, proofBytes []byte) error,
) error {
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
	// Same timing contract as VerifyGroth16: the experiment harness reads
	// the on-chain verification cost from this log line.
	start := time.Now()
	if err := verify(vk.VKBytes, publicJSON, proofBytes); err != nil {
		log.Printf("[zk] %s REJECTED: %v", vk.Name, err)
		return fmt.Errorf("plonk verification failed for %s: %w", vk.Name, err)
	}
	log.Printf("[zk] %s ok in %.3f ms", vk.Name, float64(time.Since(start).Microseconds())/1e3)
	return nil
}

// verifyPlonkSharesWith is the decode/log/skip shell around the native
// two-share FFI entry. Keeping both payloads opaque here makes Rust the sole
// implementation of arkworks' canonical share layout.
func verifyPlonkSharesWith(
	vk *PlonkVK, shareAHex, shareBHex string, publicJSON []byte,
	verify func(vkBytes, publicJSON, shareA, shareB []byte) error,
) error {
	if vk == nil {
		log.Printf("[zk] no PLONK VK loaded, skipping proof-share verification")
		return nil
	}
	decode := func(owner, encoded string) ([]byte, error) {
		raw, err := hex.DecodeString(strings.TrimSpace(encoded))
		if err != nil {
			return nil, fmt.Errorf("decoding %s %s proof share hex: %w", vk.Name, owner, err)
		}
		if len(raw) == 0 {
			return nil, fmt.Errorf("%s %s proof share is empty", vk.Name, owner)
		}
		return raw, nil
	}
	shareA, err := decode("order A", shareAHex)
	if err != nil {
		return err
	}
	shareB, err := decode("order B", shareBHex)
	if err != nil {
		return err
	}
	if len(publicJSON) == 0 {
		return fmt.Errorf("%s public statement is empty", vk.Name)
	}
	log.Printf("[zk] verifying %s: %d B + %d B native proof shares (PLONK)",
		vk.Name, len(shareA), len(shareB))
	start := time.Now()
	if err := verify(vk.VKBytes, publicJSON, shareA, shareB); err != nil {
		log.Printf("[zk] %s REJECTED: %v", vk.Name, err)
		return fmt.Errorf("plonk proof-share verification failed for %s: %w", vk.Name, err)
	}
	log.Printf("[zk] %s ok in %.3f ms", vk.Name, float64(time.Since(start).Microseconds())/1e3)
	return nil
}
