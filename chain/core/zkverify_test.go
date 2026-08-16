package core

import (
	"encoding/json"
	"os"
	"testing"
)

// fixture mirrors `lib/zk/examples/dump_deposit_fixture.rs` output: a real
// rapidsnark-generated deposit proof + the VK that verifies it.
type depositFixture struct {
	BridgeCommitmentHex string          `json:"bridge_commitment_hex"`
	OutputCommitmentHex string          `json:"output_commitment_hex"`
	ProofJSON           json.RawMessage `json:"proof_json"`
	PublicJSON          []string        `json:"public_json"`
	VKPath              string          `json:"vk_path"`
}

// loadDepositFixture reads /tmp/deposit_fixture.json. The fixture is generated
// out-of-band by `cargo run -p zk --example dump_deposit_fixture -- /tmp/deposit_fixture.json`;
// the test is skipped if it hasn't been produced yet so contributors who haven't
// installed snarkjs/rapidsnark can still run unrelated tests.
func loadDepositFixture(t *testing.T) depositFixture {
	t.Helper()
	const path = "/tmp/deposit_fixture.json"
	bytes, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("fixture not found at %s — run `cargo run -p zk --example dump_deposit_fixture -- %s`", path, path)
	}
	var f depositFixture
	if err := json.Unmarshal(bytes, &f); err != nil {
		t.Fatalf("decoding fixture: %v", err)
	}
	return f
}

func TestVerifyGroth16AcceptsValidDepositProof(t *testing.T) {
	fx := loadDepositFixture(t)
	vk, err := LoadVK("deposit", fx.VKPath)
	if err != nil {
		t.Fatalf("loading VK: %v", err)
	}
	if err := VerifyGroth16(vk, string(fx.ProofJSON), fx.PublicJSON); err != nil {
		t.Fatalf("verify on a valid proof must succeed, got: %v", err)
	}
}

func TestVerifyGroth16RejectsTamperedPublicSignal(t *testing.T) {
	fx := loadDepositFixture(t)
	vk, err := LoadVK("deposit", fx.VKPath)
	if err != nil {
		t.Fatalf("loading VK: %v", err)
	}
	tampered := make([]string, len(fx.PublicJSON))
	copy(tampered, fx.PublicJSON)
	// Flip the bridge commitment to a different (valid-looking) decimal — the
	// proof is bound to the original commitment, so verification must fail.
	tampered[0] = "1"
	if err := VerifyGroth16(vk, string(fx.ProofJSON), tampered); err == nil {
		t.Fatalf("verify must reject when public[0] is altered")
	}
}

func TestVerifyGroth16RejectsTamperedProof(t *testing.T) {
	fx := loadDepositFixture(t)
	vk, err := LoadVK("deposit", fx.VKPath)
	if err != nil {
		t.Fatalf("loading VK: %v", err)
	}
	// Re-marshal then mutate pi_a[0]'s last digit — produces a different
	// (random) curve point that won't satisfy the pairing check.
	var bag map[string]json.RawMessage
	if err := json.Unmarshal(fx.ProofJSON, &bag); err != nil {
		t.Fatalf("decoding proof: %v", err)
	}
	var piA []string
	if err := json.Unmarshal(bag["pi_a"], &piA); err != nil {
		t.Fatalf("decoding pi_a: %v", err)
	}
	piA[0] = bumpLastDigit(piA[0])
	bag["pi_a"], _ = json.Marshal(piA)
	tampered, _ := json.Marshal(bag)
	if err := VerifyGroth16(vk, string(tampered), fx.PublicJSON); err == nil {
		t.Fatalf("verify must reject a tampered proof")
	}
}

// bumpLastDigit replaces the trailing decimal digit of `s` with a different
// one so the resulting field element no longer matches the original.
func bumpLastDigit(s string) string {
	if s == "" {
		return "1"
	}
	last := s[len(s)-1]
	next := byte('0')
	if last == '0' {
		next = '1'
	}
	return s[:len(s)-1] + string(next)
}

func TestHexToDecimalRejectsInvalidInput(t *testing.T) {
	cases := []struct {
		name, hex string
	}{
		{"empty", ""},
		{"odd length", "abc"},
		{"non-hex", "zz"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := HexToDecimal(c.hex); err == nil {
				t.Fatalf("HexToDecimal(%q) must error", c.hex)
			}
		})
	}
}

func TestHexToDecimalRoundTripsKnownCommitment(t *testing.T) {
	got, err := HexToDecimal(PoseidonZeroCommitmentHex)
	if err != nil {
		t.Fatalf("HexToDecimal: %v", err)
	}
	if got != PoseidonZeroCommitment {
		t.Fatalf("hex→decimal mismatch:\nwant %s\ngot  %s", PoseidonZeroCommitment, got)
	}
}

// withdrawFixture mirrors `lib/zk/examples/dump_withdraw_fixture.rs` output.
// Distinct from depositFixture because the field shapes differ (multiple input
// commitments + a change commitment instead of a single output commitment).
type withdrawFixture struct {
	BridgeOutCommitmentHex string          `json:"bridge_out_commitment_hex"`
	InputCommitmentsHex    []string        `json:"input_commitments_hex"`
	ChangeCommitmentHex    string          `json:"change_commitment_hex"`
	ProofJSON              json.RawMessage `json:"proof_json"`
	PublicJSON             []string        `json:"public_json"`
	VKPath                 string          `json:"vk_path"`
}

func loadWithdrawFixture(t *testing.T) withdrawFixture {
	t.Helper()
	const path = "/tmp/withdraw_fixture.json"
	bytes, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("fixture not found at %s — run `cargo run -p zk --example dump_withdraw_fixture -- %s`", path, path)
	}
	var f withdrawFixture
	if err := json.Unmarshal(bytes, &f); err != nil {
		t.Fatalf("decoding fixture: %v", err)
	}
	return f
}

func TestVerifyGroth16AcceptsValidWithdrawProof(t *testing.T) {
	fx := loadWithdrawFixture(t)
	vk, err := LoadVK("withdraw", fx.VKPath)
	if err != nil {
		t.Fatalf("loading VK: %v", err)
	}
	if err := VerifyGroth16(vk, string(fx.ProofJSON), fx.PublicJSON); err != nil {
		t.Fatalf("verify on a valid withdraw proof must succeed, got: %v", err)
	}
}

func TestVerifyGroth16RejectsTamperedWithdrawChangeSlot(t *testing.T) {
	fx := loadWithdrawFixture(t)
	vk, err := LoadVK("withdraw", fx.VKPath)
	if err != nil {
		t.Fatalf("loading VK: %v", err)
	}
	tampered := make([]string, len(fx.PublicJSON))
	copy(tampered, fx.PublicJSON)
	// public[3] is output_hashes[0] = change commitment; mutating it must
	// break verification because the proof is bound to the original.
	tampered[3] = bumpLastDigit(tampered[3])
	if err := VerifyGroth16(vk, string(fx.ProofJSON), tampered); err == nil {
		t.Fatalf("verify must reject when change-commitment public input is altered")
	}
}

// splitFixture mirrors `lib/zk/examples/dump_split_fixture.rs` output.
type splitFixture struct {
	InputCommitmentsHex []string        `json:"input_commitments_hex"`
	LockedCommitmentHex string          `json:"locked_commitment_hex"`
	ChangeCommitmentHex string          `json:"change_commitment_hex"`
	ProofJSON           json.RawMessage `json:"proof_json"`
	PublicJSON          []string        `json:"public_json"`
	VKPath              string          `json:"vk_path"`
}

func loadSplitFixture(t *testing.T) splitFixture {
	t.Helper()
	const path = "/tmp/split_fixture.json"
	bytes, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("fixture not found at %s — run `cargo run -p zk --example dump_split_fixture -- %s`", path, path)
	}
	var f splitFixture
	if err := json.Unmarshal(bytes, &f); err != nil {
		t.Fatalf("decoding fixture: %v", err)
	}
	return f
}

func TestVerifyGroth16AcceptsValidSplitProof(t *testing.T) {
	fx := loadSplitFixture(t)
	vk, err := LoadVK("split", fx.VKPath)
	if err != nil {
		t.Fatalf("loading VK: %v", err)
	}
	if err := VerifyGroth16(vk, string(fx.ProofJSON), fx.PublicJSON); err != nil {
		t.Fatalf("verify on a valid split proof must succeed, got: %v", err)
	}
}

func TestVerifyGroth16RejectsTamperedSplitLockedSlot(t *testing.T) {
	fx := loadSplitFixture(t)
	vk, err := LoadVK("split", fx.VKPath)
	if err != nil {
		t.Fatalf("loading VK: %v", err)
	}
	tampered := make([]string, len(fx.PublicJSON))
	copy(tampered, fx.PublicJSON)
	// public is [in[0], in[1], out[0]=locked, out[1]=change]; mutating the
	// locked slot must break the conservation proof.
	tampered[2] = bumpLastDigit(tampered[2])
	if err := VerifyGroth16(vk, string(fx.ProofJSON), tampered); err == nil {
		t.Fatalf("verify must reject when locked-commitment public input is altered")
	}
}
