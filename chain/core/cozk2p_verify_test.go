//go:build cozk2p

package core

import (
	"encoding/json"
	"testing"
)

// marshalPublic marshals a settle2pPublic for the verifier bridge.
func marshalPublic(t *testing.T, p settle2pPublic) []byte {
	t.Helper()
	raw, err := json.Marshal(&p)
	if err != nil {
		t.Fatalf("marshaling public statement: %v", err)
	}
	return raw
}

func loadCoZk2pVK(t *testing.T, fx cozk2pFixture) *PlonkVK {
	t.Helper()
	vk, err := LoadPlonkVK("settle_cozk2p", fx.VKPath)
	if err != nil {
		t.Fatalf("loading PLONK VK: %v", err)
	}
	return vk
}

func TestVerifyPlonkAcceptsCollaborativeSettle2pProof(t *testing.T) {
	fx := loadCoZk2pFixture(t)
	vk := loadCoZk2pVK(t, fx)
	public := marshalPublic(t, rebuildCoZk2pPublic(fx))
	if err := VerifyPlonkSettle2p(vk, fx.ProofHex, public); err != nil {
		t.Fatalf("verify on a valid collaborative settle2p proof must succeed, got: %v", err)
	}
}

func TestVerifyPlonkRejectsTamperedSettle2pCmp(t *testing.T) {
	fx := loadCoZk2pFixture(t)
	vk := loadCoZk2pVK(t, fx)
	tampered := rebuildCoZk2pPublic(fx)
	// Flipping the public comparison result must break verification — a
	// submitter cannot lie about which order fully filled.
	tampered.Cmp = -tampered.Cmp
	if err := VerifyPlonkSettle2p(vk, fx.ProofHex, marshalPublic(t, tampered)); err == nil {
		t.Fatal("verify must reject when the cmp public signal is altered")
	}
}

func TestVerifyPlonkRejectsTamperedSettle2pRemainder(t *testing.T) {
	fx := loadCoZk2pFixture(t)
	vk := loadCoZk2pVK(t, fx)
	tampered := rebuildCoZk2pPublic(fx)
	// new_order_a is the surviving order's remainder commitment.
	tampered.NewOrderA = bumpLastDigit(tampered.NewOrderA)
	if err := VerifyPlonkSettle2p(vk, fx.ProofHex, marshalPublic(t, tampered)); err == nil {
		t.Fatal("verify must reject when the remainder commitment is altered")
	}
}

func TestVerifyPlonkRejectsTruncatedSettle2pProof(t *testing.T) {
	fx := loadCoZk2pFixture(t)
	vk := loadCoZk2pVK(t, fx)
	public := marshalPublic(t, rebuildCoZk2pPublic(fx))
	if err := VerifyPlonkSettle2p(vk, fx.ProofHex[:len(fx.ProofHex)/2], public); err == nil {
		t.Fatal("verify must reject a truncated proof")
	}
}
