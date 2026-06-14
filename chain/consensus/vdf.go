package consensus

import (
	"crypto/sha256"

	"github.com/harmony-one/vdf/src/vdf_go"
)

const (
	// vdfBitSize is the security parameter for the Wesolowski VDF (class group discriminant size).
	vdfBitSize = 2048
	// vdfYSize is the byte length of the VDF output Y.
	vdfYSize = 258
	// vdfProofSize is the byte length of the VDF proof.
	vdfProofSize = 258
	// VDFProofBlobSize is the total byte length of Y + proof.
	VDFProofBlobSize = vdfYSize + vdfProofSize
)

// VDFResult holds the output of a Wesolowski VDF computation.
type VDFResult struct {
	// ProofBlob contains Y (258 bytes) concatenated with proof (258 bytes).
	ProofBlob []byte `json:"proof_blob"`
	// Iterations is the number of squarings performed.
	Iterations uint64 `json:"iterations"`
}

// Compute runs a Wesolowski VDF on the given input for `difficulty` iterations.
// `input` is typically the previous block hash.
// `difficulty` must be > 0.
func Compute(input []byte, difficulty uint64) *VDFResult {
	// Hash input to produce a fixed 32-byte seed.
	seed := sha256.Sum256(input)

	y, proof := vdf_go.GenerateVDF(seed[:], int(difficulty), vdfBitSize)

	proofBlob := make([]byte, 0, VDFProofBlobSize)
	proofBlob = append(proofBlob, y...)
	proofBlob = append(proofBlob, proof...)

	return &VDFResult{
		ProofBlob:  proofBlob,
		Iterations: difficulty,
	}
}

// Verify checks a VDF result using the Wesolowski fast verification (O(1)).
// Returns true if the proof is valid for the given input and difficulty.
func Verify(input []byte, result *VDFResult, difficulty uint64) bool {
	if result == nil || result.Iterations != difficulty {
		return false
	}
	if len(result.ProofBlob) != VDFProofBlobSize {
		return false
	}
	seed := sha256.Sum256(input)
	return vdf_go.VerifyVDF(seed[:], result.ProofBlob, int(difficulty), vdfBitSize)
}

// VDFOutput extracts the Y portion (first 258 bytes) from a VDFResult's ProofBlob.
// Used for score calculation.
func VDFOutput(result *VDFResult) []byte {
	return result.ProofBlob[:vdfYSize]
}
