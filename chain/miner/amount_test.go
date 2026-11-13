package miner

import (
	"math/big"
	"testing"
)

// TestParseCKB covers the forms a person types and the ones that must not
// reach L1.
func TestParseCKB(t *testing.T) {
	good := map[string]string{
		"1":          "100000000",
		"0.5":        "50000000",
		".5":         "50000000",
		"1500":       "150000000000",
		"0.00000001": "1",
		" 2.25 ":     "225000000",
	}
	for in, want := range good {
		got, err := ParseCKB(in)
		if err != nil || got.String() != want {
			t.Errorf("ParseCKB(%q) = %v, %v; want %s", in, got, err, want)
		}
	}

	for _, in := range []string{"", ".", "0", "0.0", "-1", "+1", "1e3", "1.000000001", "abc", "1,000", "0x10"} {
		if got, err := ParseCKB(in); err == nil {
			t.Errorf("ParseCKB(%q) = %v, want an error", in, got)
		}
	}
}

// TestFormatCKBRoundTrips checks FormatCKB inverts ParseCKB and trims zeros.
func TestFormatCKBRoundTrips(t *testing.T) {
	for _, in := range []string{"1", "0.5", "1500.25", "0.00000001", "123456789"} {
		shannon, err := ParseCKB(in)
		if err != nil {
			t.Fatal(err)
		}
		if got := FormatCKB(shannon); got != in {
			t.Errorf("FormatCKB(ParseCKB(%q)) = %q", in, got)
		}
	}
	if got := FormatCKB(big.NewInt(0)); got != "0" {
		t.Errorf("FormatCKB(0) = %q", got)
	}
}
