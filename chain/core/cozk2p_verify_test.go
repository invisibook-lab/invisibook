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

// rebuildComparePublic assembles the comparison statement from the fixture
// the same way SubmitCompareCoZk2p does from a request + order rows.
func rebuildComparePublic(fx cozk2pFixture) settle2pPublic {
	return settle2pPublic{
		Cmp:    fx.Cmp,
		OrderA: fx.OrderACommitmentHex,
		OrderB: fx.OrderBCommitmentHex,
	}
}

func TestVerifyPlonkAcceptsCollaborativeCompareProof(t *testing.T) {
	fx := loadCoZk2pFixture(t)
	vk := loadCoZk2pVK(t, fx)
	public := marshalPublic(t, rebuildComparePublic(fx))
	if err := VerifyPlonkSettle2p(vk, fx.ProofHex, public); err != nil {
		t.Fatalf("verify on a valid collaborative compare proof must succeed, got: %v", err)
	}
}

func TestVerifyPlonkRejectsTamperedCompareCmp(t *testing.T) {
	fx := loadCoZk2pFixture(t)
	vk := loadCoZk2pVK(t, fx)
	tampered := rebuildComparePublic(fx)
	// Flipping the public comparison result must break verification — a
	// submitter cannot lie about which order is smaller.
	tampered.Cmp = -tampered.Cmp
	if err := VerifyPlonkSettle2p(vk, fx.ProofHex, marshalPublic(t, tampered)); err == nil {
		t.Fatal("verify must reject when the cmp public signal is altered")
	}
}

func TestVerifyPlonkRejectsTamperedCompareCommitment(t *testing.T) {
	fx := loadCoZk2pFixture(t)
	vk := loadCoZk2pVK(t, fx)
	tampered := rebuildComparePublic(fx)
	tampered.OrderA = bumpLastDigit(tampered.OrderA)
	if err := VerifyPlonkSettle2p(vk, fx.ProofHex, marshalPublic(t, tampered)); err == nil {
		t.Fatal("verify must reject when an order commitment is altered")
	}
}

func TestVerifyPlonkRejectsTruncatedCompareProof(t *testing.T) {
	fx := loadCoZk2pFixture(t)
	vk := loadCoZk2pVK(t, fx)
	public := marshalPublic(t, rebuildComparePublic(fx))
	if err := VerifyPlonkSettle2p(vk, fx.ProofHex[:len(fx.ProofHex)/2], public); err == nil {
		t.Fatal("verify must reject a truncated proof")
	}
}
