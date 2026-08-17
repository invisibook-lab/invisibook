package core

import (
	"testing"
)

// Groth16 accept/reject behavior over REAL fixture proofs is covered by
// pool_verify_test.go (note_deposit / spend_withdraw fixtures from
// `dump_pool_fixture`); this file keeps the pure helpers honest.

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

// bumpLastDigit replaces the trailing decimal digit of `s` with a different
// one so the resulting field element no longer matches the original.
// Shared by the fixture-based verifier tests in this package.
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
