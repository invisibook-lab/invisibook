package consensus

import (
	"bytes"
	"testing"

	"github.com/yu-org/yu/core/keypair"
)

// testMinerKey derives a miner keypair from a secret the same way main.go
// does, and returns the ecdsa private key plus the compressed public key.
func testMinerKey(t *testing.T, secret string) (privKey, pubKey []byte) {
	t.Helper()
	pub, priv, err := keypair.GenKeyPairWithSecret(keypair.Secp256k1, []byte(secret))
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	return priv.Bytes(), pub.Bytes()
}

// mustProve derives the ecdsa key and evaluates the VRF, failing the test on error.
func mustProve(t *testing.T, rawPriv, input []byte) *VRFResult {
	t.Helper()
	privKey, err := SecpPrivKeyToECDSA(rawPriv)
	if err != nil {
		t.Fatalf("convert private key: %v", err)
	}
	result, err := VRFProve(privKey, input)
	if err != nil {
		t.Fatalf("VRF prove: %v", err)
	}
	return result
}

// TestVRFProveAndVerify checks that a VRF proof passes verification.
func TestVRFProveAndVerify(t *testing.T) {
	rawPriv, pubKey := testMinerKey(t, "test-secret")
	input := []byte("test-block-hash")

	result := mustProve(t, rawPriv, input)
	if !VRFVerify(pubKey, input, result) {
		t.Fatal("VRF verification failed for valid result")
	}
}

// TestVRFKeyIsTheMinerKey checks that the VRF verifies against the public key
// yu derives for block signing — the property that makes VRF key grinding
// impossible without also changing the block producer's identity.
func TestVRFKeyIsTheMinerKey(t *testing.T) {
	rawPriv, pubKey := testMinerKey(t, "test-secret")
	if len(pubKey) != CompressedPubkeySize {
		t.Fatalf("miner pubkey length: got %d, want %d", len(pubKey), CompressedPubkeySize)
	}

	privKey, err := SecpPrivKeyToECDSA(rawPriv)
	if err != nil {
		t.Fatalf("convert private key: %v", err)
	}
	if derived := CompressedPubkey(&privKey.PublicKey); !bytes.Equal(derived, pubKey) {
		t.Fatalf("VRF key does not match miner key:\n got %x\nwant %x", derived, pubKey)
	}
}

// TestVRFDeterministic checks that the same (key, input) always produces the same output.
func TestVRFDeterministic(t *testing.T) {
	rawPriv, _ := testMinerKey(t, "test-secret")
	input := []byte("test-block-hash")

	r1 := mustProve(t, rawPriv, input)
	r2 := mustProve(t, rawPriv, input)

	if !bytes.Equal(r1.Output, r2.Output) {
		t.Fatal("VRF output is not deterministic")
	}
	if !bytes.Equal(r1.Proof, r2.Proof) {
		t.Fatal("VRF proof is not deterministic")
	}
}

// TestVRFDifferentKeys checks that different keys produce different outputs.
func TestVRFDifferentKeys(t *testing.T) {
	priv1, _ := testMinerKey(t, "secret-1")
	priv2, _ := testMinerKey(t, "secret-2")
	input := []byte("test-block-hash")

	r1 := mustProve(t, priv1, input)
	r2 := mustProve(t, priv2, input)

	if bytes.Equal(r1.Output, r2.Output) {
		t.Fatal("different keys should produce different VRF outputs")
	}
}

// TestVRFRejectsTampered flips a byte in the proof and expects verification to fail.
func TestVRFRejectsTampered(t *testing.T) {
	rawPriv, pubKey := testMinerKey(t, "test-secret")
	input := []byte("test-block-hash")

	result := mustProve(t, rawPriv, input)
	result.Proof[10] ^= 0xFF

	if VRFVerify(pubKey, input, result) {
		t.Fatal("VRF verification should fail for tampered proof")
	}
}

// TestVRFRejectsDoctoredOutput keeps a valid proof but rewrites the claimed
// output, which must not be accepted.
func TestVRFRejectsDoctoredOutput(t *testing.T) {
	rawPriv, pubKey := testMinerKey(t, "test-secret")
	input := []byte("test-block-hash")

	result := mustProve(t, rawPriv, input)
	result.Output[0] ^= 0xFF

	if VRFVerify(pubKey, input, result) {
		t.Fatal("VRF verification should fail for a doctored output")
	}
}

// TestVRFRejectsWrongInput uses a different input for verification.
func TestVRFRejectsWrongInput(t *testing.T) {
	rawPriv, pubKey := testMinerKey(t, "test-secret")
	input := []byte("test-block-hash")

	result := mustProve(t, rawPriv, input)

	if VRFVerify(pubKey, []byte("different-block-hash"), result) {
		t.Fatal("VRF verification should fail for wrong input")
	}
}

// TestVRFRejectsWrongPubkey verifies a valid proof against another miner's
// key, which must fail — this is what stops a miner from replaying someone
// else's VRF output under its own block.
func TestVRFRejectsWrongPubkey(t *testing.T) {
	priv1, _ := testMinerKey(t, "secret-1")
	_, pub2 := testMinerKey(t, "secret-2")
	input := []byte("test-block-hash")

	result := mustProve(t, priv1, input)
	if VRFVerify(pub2, input, result) {
		t.Fatal("VRF verification should fail against a different miner's key")
	}
}

// TestVRFRejectsMalformedPubkey feeds verification a key of the wrong length.
func TestVRFRejectsMalformedPubkey(t *testing.T) {
	rawPriv, pubKey := testMinerKey(t, "test-secret")
	input := []byte("test-block-hash")

	result := mustProve(t, rawPriv, input)
	if VRFVerify(pubKey[:CompressedPubkeySize-1], input, result) {
		t.Fatal("VRF verification should fail for a truncated pubkey")
	}
}

// TestVRFOutputLength checks that Output is 32 bytes.
func TestVRFOutputLength(t *testing.T) {
	rawPriv, _ := testMinerKey(t, "test-secret")

	result := mustProve(t, rawPriv, []byte("test-block-hash"))
	if len(result.Output) != VRFOutputSize {
		t.Fatalf("VRF output length: got %d, want %d", len(result.Output), VRFOutputSize)
	}
}
