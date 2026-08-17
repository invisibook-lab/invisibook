//go:build cozk2p

package core

import (
	"encoding/json"
	"testing"
)

// The real FFI round-trip for the MERGED statement: the collaborative
// fixture proof must verify against the chain-rebuilt statement, and any
// tampered signal must be rejected.
func TestSettlePair2pVerifyFixture(t *testing.T) {
	fx := loadSettlePair2pFixture(t)
	if fx.VKPath == "" {
		t.Skip("fixture carries no vk_path — dump with --vk-out")
	}
	vk, err := LoadPlonkVK("settle_pair_cozk2p", fx.VKPath)
	if err != nil {
		t.Fatalf("loading VK: %v", err)
	}

	public := rebuiltPair2pPublic(t, fx)
	marshal := func(p settlePair2pPublic) []byte {
		raw, err := json.Marshal(&p)
		if err != nil {
			t.Fatalf("marshaling public: %v", err)
		}
		return raw
	}

	if err := VerifyPlonkSettlePair(vk, fx.ProofHex, marshal(public)); err != nil {
		t.Fatalf("genuine merged proof rejected: %v", err)
	}

	// Flipped cmp must be rejected.
	bad := public
	bad.Cmp = -bad.Cmp
	if err := VerifyPlonkSettlePair(vk, fx.ProofHex, marshal(bad)); err == nil {
		t.Fatal("flipped cmp must not verify")
	}

	// A substituted payout note must be rejected.
	bad = public
	bad.CmNoteOutA, bad.CmNoteOutB = bad.CmNoteOutB, bad.CmNoteOutA
	if err := VerifyPlonkSettlePair(vk, fx.ProofHex, marshal(bad)); err == nil {
		t.Fatal("swapped payout notes must not verify")
	}

	// A truncated proof is a parse error, not a crash.
	if err := VerifyPlonkSettlePair(vk, fx.ProofHex[:len(fx.ProofHex)/2], marshal(public)); err == nil {
		t.Fatal("truncated proof must error")
	}
}
