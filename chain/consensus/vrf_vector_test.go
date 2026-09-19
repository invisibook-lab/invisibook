package consensus

import (
	"encoding/hex"
	"testing"
)

// TestPrintVRFVector emits a known-good ECVRF tuple for the CKB contract's
// Rust implementation to check itself against. Run with -v to read it.
func TestPrintVRFVector(t *testing.T) {
	priv := make([]byte, 32)
	for i := range priv {
		priv[i] = byte(i + 1)
	}
	ecdsaKey, err := SecpPrivKeyToECDSA(priv)
	if err != nil {
		t.Fatalf("deriving key: %v", err)
	}

	input := []byte("parent-block-hash-stand-in------")
	result, err := VRFProve(ecdsaKey, input)
	if err != nil {
		t.Fatalf("VRFProve: %v", err)
	}

	pubkey := CompressedPubkey(&ecdsaKey.PublicKey)
	t.Logf("privkey     %s", hex.EncodeToString(priv))
	t.Logf("pubkey      %s", hex.EncodeToString(pubkey))
	t.Logf("input       %s", hex.EncodeToString(input))
	t.Logf("alpha       %s", hex.EncodeToString(vrfAlpha(input)))
	t.Logf("pi          %s", hex.EncodeToString(result.Proof))
	t.Logf("beta        %s", hex.EncodeToString(result.Output))

	if !VRFVerify(pubkey, input, result) {
		t.Fatal("the vector must verify against our own verifier")
	}
}
