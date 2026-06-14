package consensus

import (
	"testing"
)

const testDifficulty = 100

// TestComputeAndVerify checks that a computed VDF result passes verification.
func TestComputeAndVerify(t *testing.T) {
	input := []byte("test-block-hash")
	result := Compute(input, testDifficulty)

	if !Verify(input, result, testDifficulty) {
		t.Fatal("VDF verification failed for valid result")
	}
}

// TestVerifyRejectsTampered flips a byte in ProofBlob and expects verification to fail.
func TestVerifyRejectsTampered(t *testing.T) {
	input := []byte("test-block-hash")
	result := Compute(input, testDifficulty)

	// Tamper with the proof blob
	result.ProofBlob[100] ^= 0xFF

	if Verify(input, result, testDifficulty) {
		t.Fatal("VDF verification should fail for tampered proof")
	}
}

// TestVerifyRejectsWrongInput uses a different input for verification.
func TestVerifyRejectsWrongInput(t *testing.T) {
	input := []byte("test-block-hash")
	result := Compute(input, testDifficulty)

	wrongInput := []byte("different-block-hash")
	if Verify(wrongInput, result, testDifficulty) {
		t.Fatal("VDF verification should fail for wrong input")
	}
}

// TestVDFOutputLength checks that ProofBlob is 516 bytes and VDFOutput is 258 bytes.
func TestVDFOutputLength(t *testing.T) {
	input := []byte("test-block-hash")
	result := Compute(input, testDifficulty)

	if len(result.ProofBlob) != VDFProofBlobSize {
		t.Fatalf("ProofBlob length: got %d, want %d", len(result.ProofBlob), VDFProofBlobSize)
	}

	output := VDFOutput(result)
	if len(output) != 258 {
		t.Fatalf("VDFOutput length: got %d, want 258", len(output))
	}
}
