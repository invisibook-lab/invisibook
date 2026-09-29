package core

import (
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/yu-org/yu/core/keypair"
)

const testMessage = "order-id-under-signature"

// TestVerifyOwnerSignature covers the property the whole ownership model rests
// on: a miner signs with the same key it produces blocks with, and that key
// owns the cash credited to it.
func TestVerifyOwnerSignature(t *testing.T) {
	pub, priv := keypair.GenSecpKeyWithSecret([]byte("owner-under-test"))
	sig, err := priv.SignData([]byte(testMessage))
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	ownerHex := hex.EncodeToString(pub.Bytes())

	if got := len(ownerHex); got != OwnerPubkeySize*2 {
		t.Fatalf("owner key renders to %d hex chars, want %d", got, OwnerPubkeySize*2)
	}
	if err := VerifyOwnerSignature(ownerHex, testMessage, hex.EncodeToString(sig)); err != nil {
		t.Fatalf("a valid signature must verify, got %v", err)
	}
	if err := VerifyOwnerSignature(ownerHex, "another message", hex.EncodeToString(sig)); err == nil {
		t.Fatal("a signature over a different message must be rejected")
	}

	// Someone else's key must not validate this signature.
	other, _ := keypair.GenSecpKeyWithSecret([]byte("someone-else"))
	if err := VerifyOwnerSignature(hex.EncodeToString(other.Bytes()), testMessage, hex.EncodeToString(sig)); err == nil {
		t.Fatal("a signature must not verify under another owner's key")
	}
}

// TestVerifyOwnerSignatureRejectsEd25519 pins the migration: keys from the old
// ed25519 scheme are 32 bytes and must be refused outright rather than being
// silently reinterpreted.
func TestVerifyOwnerSignatureRejectsEd25519(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	sig := ed25519.Sign(priv, []byte(testMessage))

	if err := VerifyOwnerSignature(hex.EncodeToString(pub), testMessage, hex.EncodeToString(sig)); err == nil {
		t.Fatal("a 32-byte ed25519 key must be rejected")
	}
}

func TestVerifyOwnerSignatureRejectsMalformedInput(t *testing.T) {
	valid := strings.Repeat("ab", OwnerPubkeySize)
	if err := VerifyOwnerSignature("zz", testMessage, strings.Repeat("cd", OwnerSignatureSize)); err == nil {
		t.Fatal("a non-hex pubkey must be rejected")
	}
	if err := VerifyOwnerSignature(valid, testMessage, "zz"); err == nil {
		t.Fatal("a non-hex signature must be rejected")
	}
	if err := VerifyOwnerSignature(valid, testMessage, strings.Repeat("cd", 10)); err == nil {
		t.Fatal("a short signature must be rejected")
	}
}

func TestValidOwnerPubkey(t *testing.T) {
	if err := ValidOwnerPubkey(strings.Repeat("ab", OwnerPubkeySize)); err != nil {
		t.Fatalf("a compressed secp256k1 key must be accepted, got %v", err)
	}
	if err := ValidOwnerPubkey(strings.Repeat("ab", 32)); err == nil {
		t.Fatal("a 32-byte key must be rejected")
	}
	if err := ValidOwnerPubkey("zz"); err == nil {
		t.Fatal("a non-hex key must be rejected")
	}
}
