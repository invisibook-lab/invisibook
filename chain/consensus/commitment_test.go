package consensus

import (
	"strings"
	"testing"

	"github.com/yu-org/yu/common"
)

// bidFixture is one well-formed set of arguments to CommitBlockHash, which
// each test perturbs in exactly one place.
func bidFixture() (common.Hash, string) {
	return common.BytesToHash([]byte("a-block-hash-of-exactly-32-bytes")), strings.Repeat("ab", 32)
}

func TestCommitBlockHashIsDeterministic(t *testing.T) {
	hash, random := bidFixture()

	first, err := CommitBlockHash(hash, random)
	if err != nil {
		t.Fatalf("CommitBlockHash: %v", err)
	}
	second, err := CommitBlockHash(hash, random)
	if err != nil {
		t.Fatalf("CommitBlockHash: %v", err)
	}

	if first != second {
		t.Fatalf("same inputs gave %s then %s", first, second)
	}
	if len(first) != CommitmentHexLen {
		t.Fatalf("commitment is %d chars, want %d", len(first), CommitmentHexLen)
	}
}

// TestCommitBlockHashBindsEveryInput is the property the whole scheme rests on:
// a miner must not be able to open its commitment to any block other than the
// one it produced. Changing either input has to change the commitment.
func TestCommitBlockHashBindsEveryInput(t *testing.T) {
	hash, random := bidFixture()
	base, err := CommitBlockHash(hash, random)
	if err != nil {
		t.Fatalf("CommitBlockHash: %v", err)
	}

	// A hash differing only in its last byte catches an implementation that
	// drops part of the preimage, which would let two different blocks share
	// a commitment.
	tailChanged := hash
	tailChanged[31] ^= 0x01
	headChanged := hash
	headChanged[0] ^= 0x01

	cases := []struct {
		name   string
		hash   common.Hash
		random string
	}{
		{"hash, first byte", headChanged, random},
		{"hash, last byte", tailChanged, random},
		{"random", hash, strings.Repeat("cd", 32)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CommitBlockHash(tc.hash, tc.random)
			if err != nil {
				t.Fatalf("CommitBlockHash: %v", err)
			}
			if got == base {
				t.Fatalf("changing %s left the commitment unchanged at %s", tc.name, got)
			}
		})
	}
}

func TestCommitBlockHashRejectsMalformedRandom(t *testing.T) {
	hash, _ := bidFixture()

	cases := []struct {
		name   string
		random string
	}{
		{"short random", "abcd"},
		{"non-hex random", strings.Repeat("zz", 32)},
		{"empty random", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := CommitBlockHash(hash, tc.random); err == nil {
				t.Fatal("expected an error, got none")
			}
		})
	}
}

func TestNewRandomHexIsFreshAndWellFormed(t *testing.T) {
	first, err := NewRandomHex()
	if err != nil {
		t.Fatalf("NewRandomHex: %v", err)
	}
	second, err := NewRandomHex()
	if err != nil {
		t.Fatalf("NewRandomHex: %v", err)
	}

	if len(first) != RandomHexLen {
		t.Fatalf("random is %d chars, want %d", len(first), RandomHexLen)
	}
	if first == second {
		t.Fatal("two draws returned the same blinding factor")
	}
	// It has to be usable as a blinding factor, not merely look like one.
	if _, err := decodeRandom(first); err != nil {
		t.Fatalf("decodeRandom on a fresh value: %v", err)
	}
}
