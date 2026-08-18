package core

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"

	"github.com/iden3/go-rapidsnark/types"
	"github.com/iden3/go-rapidsnark/verifier"
)

// ────────────────────── Verifier Infrastructure ──────────────────────
//
// Wallet circuits are proved by rapidsnark (C++) and produce snarkjs-format
// `proof.json` plus a `public.json` array of decimal-string public signals.
// chain side calls go-rapidsnark to verify; this file is the only place that
// knows the snarkjs JSON wire format so business code stays clean.

// CircuitVK bundles a verifier's verification-key bytes (snarkjs JSON format)
// with the circuit's name for error reporting. Chain components hold one of
// these per circuit, loaded once at startup.
type CircuitVK struct {
	Name    string
	VKBytes []byte
}

// LoadVK reads a snarkjs `vk.json` file from disk into memory, ready to be
// passed to `VerifyGroth16`. `path` should point at the output of
// `snarkjs zkey export verificationkey`.
// When `path` is empty, returns nil — callers that pass a nil VK to
// VerifyGroth16 will skip proof verification (useful in test environments
// where circuit artifacts are not available).
func LoadVK(name, path string) (*CircuitVK, error) {
	if path == "" {
		log.Printf("[zk] VK %q: path empty, verification will be skipped", name)
		return nil, nil
	}
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("loading VK %q from %s: %w", name, path, err)
	}
	// Parse once at load time so a malformed VK fails fast at startup, not on
	// the first deposit. We discard the parsed value — the verifier reparses
	// internally from the raw bytes.
	var probe map[string]any
	if err := json.Unmarshal(bytes, &probe); err != nil {
		return nil, fmt.Errorf("VK %q is not valid JSON: %w", name, err)
	}
	if probe["protocol"] != "groth16" {
		return nil, fmt.Errorf("VK %q is not a groth16 key (protocol=%v)", name, probe["protocol"])
	}
	return &CircuitVK{Name: name, VKBytes: bytes}, nil
}

// VerifyGroth16 verifies `proofJSON` (a snarkjs proof.json string emitted by
// rapidsnark) against `vk` and the supplied public signals. Public signals
// must be decimal-string field elements in the order the circuit declares
// them — caller is responsible for assembling them from request fields.
//
// Emits two log lines per call so a chain operator can watch zk activity:
//
//	[zk] verifying <circuit>: <N> public signals
//	[zk] <circuit> ok      OR      [zk] <circuit> REJECTED: <reason>
func VerifyGroth16(vk *CircuitVK, proofJSON string, publicSignals []string) error {
	// When no VK is loaded (path was empty in config), skip verification.
	if vk == nil {
		log.Printf("[zk] no VK loaded, skipping proof verification")
		return nil
	}
	log.Printf("[zk] verifying %s: %d public signals", vk.Name, len(publicSignals))

	// Trim trailing NUL bytes — rapidsnark pads its output buffer to a fixed
	// block size, so a proof piped straight from disk often ends with `\0`s.
	proofTrimmed := trimTrailingNuls(proofJSON)

	var proof types.ProofData
	if err := json.Unmarshal([]byte(proofTrimmed), &proof); err != nil {
		log.Printf("[zk] %s REJECTED: parse error: %v", vk.Name, err)
		return fmt.Errorf("parsing proof for %s: %w", vk.Name, err)
	}

	zk := types.ZKProof{Proof: &proof, PubSignals: publicSignals}
	// The verification wall-clock goes into the log line: the experiment
	// harness (experiments/rq3_end_to_end.sh) reads the on-chain
	// verification cost from these lines.
	start := time.Now()
	if err := verifier.VerifyGroth16(zk, vk.VKBytes); err != nil {
		log.Printf("[zk] %s REJECTED: %v", vk.Name, err)
		return fmt.Errorf("groth16 verification failed for %s: %w", vk.Name, err)
	}
	log.Printf("[zk] %s ok in %.3f ms", vk.Name, float64(time.Since(start).Microseconds())/1e3)
	return nil
}

// HexToDecimal converts a 64-char lowercase big-endian hex string (the on-wire
// commitment format produced by `lib/zk::wallet::fr_to_hex`) into its decimal
// representation, suitable as a snarkjs public-signal entry. Empty or missing
// hex strings are reported as an error.
func HexToDecimal(s string) (string, error) {
	bytes, err := hex.DecodeString(s)
	if err != nil {
		return "", fmt.Errorf("decoding commitment hex %q: %w", s, err)
	}
	if len(bytes) == 0 || len(bytes) > 32 {
		return "", fmt.Errorf("commitment hex must decode to 1..=32 bytes, got %d", len(bytes))
	}
	return new(big.Int).SetBytes(bytes).String(), nil
}

// trimTrailingNuls strips NUL and whitespace characters from the end of `s`.
// rapidsnark and some snarkjs versions emit padded output that breaks strict
// JSON parsers if not trimmed first.
func trimTrailingNuls(s string) string {
	end := len(s)
	for end > 0 {
		c := s[end-1]
		if c != 0 && c != ' ' && c != '\n' && c != '\r' && c != '\t' {
			break
		}
		end--
	}
	return s[:end]
}
