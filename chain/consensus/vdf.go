package consensus

import (
	"bytes"
	"crypto/sha256"
)

// VDFResult holds the output of a VDF computation.
// In this simplified Phase 1 implementation, Proof equals Output.
type VDFResult struct {
	// Output is the final hash after iterating SHA256.
	Output []byte `json:"output"`
	// Proof is the verification proof (equals Output in the simplified version).
	Proof []byte `json:"proof"`
	// Iterations is the number of SHA256 iterations performed.
	Iterations uint64 `json:"iterations"`
}

// Compute runs an iterative SHA256 VDF on the given input for `difficulty` rounds.
// `input` is typically the previous block hash.
// `difficulty` must be > 0.
func Compute(input []byte, difficulty uint64) *VDFResult {
	hash := sha256.Sum256(input)
	current := hash[:]
	for i := uint64(1); i < difficulty; i++ {
		h := sha256.Sum256(current)
		current = h[:]
	}
	result := make([]byte, len(current))
	copy(result, current)
	return &VDFResult{
		Output:     result,
		Proof:      result, // simplified: proof = output
		Iterations: difficulty,
	}
}

// Verify checks a VDF result by recomputing and comparing.
// Returns true if the recomputed output matches the claimed result.
func Verify(input []byte, result *VDFResult, difficulty uint64) bool {
	if result == nil || result.Iterations != difficulty {
		return false
	}
	expected := Compute(input, difficulty)
	return bytes.Equal(expected.Output, result.Output)
}
