package consensus

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
)

// Vectors from `cargo run -p budget-stark --example dump_vectors` (lib/).
// If these drift, commitments this node opens no longer match the ones the
// balance proof on L1 was made over.

func TestPoseidon2PermutationMatchesPlonky3(t *testing.T) {
	var state [p2Width]uint32
	for i := range state {
		state[i] = uint32(i)
	}
	poseidon2Permute(&state)
	want := [p2Width]uint32{
		0x4b134812, 0x278ba7f8, 0x76944b51, 0x1c672bb2, 0x31dfa6bb, 0x6b7e9d79, 0x4945e876, 0x78a321a8,
		0x7a73bc0a, 0x5cc8abbc, 0x56beb8c0, 0x57b4c9a2, 0x193b9df3, 0x15194d64, 0x47ba9576, 0x5eeccb64,
	}
	if state != want {
		t.Fatalf("permutation([0..16]) = %#x, want %#x", state, want)
	}
}

func TestPaymentCommitMatchesPlonky3(t *testing.T) {
	cases := []struct {
		amount     uint64
		random     string
		commitment string
	}{
		{0, "0000000000000000000000000000000000000000000000000000000000000000", "44917757aa9a1104a1ad4b7cbe60fe659316d4334d2ca2295e2525771877632b"},
		{10000000000, "0100000002000000030000000400000005000000060000000700000008000000", "3ca18f0c4f02511001002f605456ef2bf2fb6133330a1f654c6b6f503d45c535"},
		{18446744073709551615, "0000007f0000007f0000007f0000007f0000007f0000007f0000007f0000007f", "20daee46fb445d4cc541533137e9f638104ebe757b73c03b701703395d86bb12"},
		{81985529216486895, "68039d36e059d14858b0055bd0063a6d475d6e00bfb3a212370ad724af600b37", "01c25505598321760573af31b7135c6361995f7defbfb6725c1f3002c7633232"},
	}
	for _, c := range cases {
		got, err := PaymentCommit(new(big.Int).SetUint64(c.amount), c.random)
		if err != nil {
			t.Fatalf("PaymentCommit(%d): %v", c.amount, err)
		}
		if got != c.commitment {
			t.Errorf("PaymentCommit(%d) = %s, want %s", c.amount, got, c.commitment)
		}
	}
}

func TestPaymentCommitRejectsBadInput(t *testing.T) {
	zero := strings.Repeat("00", 32)
	if _, err := PaymentCommit(nil, zero); err == nil {
		t.Error("nil amount accepted")
	}
	if _, err := PaymentCommit(big.NewInt(-1), zero); err == nil {
		t.Error("negative amount accepted")
	}
	tooBig := new(big.Int).Lsh(big.NewInt(1), 64)
	if _, err := PaymentCommit(tooBig, zero); err == nil {
		t.Error("amount above u64 accepted")
	}
	if _, err := PaymentCommit(big.NewInt(1), "zz"); err == nil {
		t.Error("short random accepted")
	}
	// The field order itself is one past the largest canonical word.
	nonCanonical := "0100007f" + strings.Repeat("00", 28)
	if _, err := PaymentCommit(big.NewInt(1), nonCanonical); err == nil {
		t.Error("non-canonical random word accepted")
	}
}

func TestNewPaymentRandomHexIsCanonicalAndFresh(t *testing.T) {
	first, err := NewPaymentRandomHex(rand.Reader)
	if err != nil {
		t.Fatalf("NewPaymentRandomHex: %v", err)
	}
	second, _ := NewPaymentRandomHex(rand.Reader)
	if first == second {
		t.Fatal("two blinding factors came out equal")
	}
	if _, err := decodePaymentRandom(first); err != nil {
		t.Fatalf("fresh blinding factor does not decode: %v", err)
	}
}

// Words at or above the field order are drawn again, not reduced.
func TestNewPaymentRandomHexRejectsOutOfRangeWords(t *testing.T) {
	var src bytes.Buffer
	word := make([]byte, 4)
	binary.LittleEndian.PutUint32(word, koalaBearP) // rejected
	src.Write(word)
	for i := 0; i < randomLen; i++ {
		binary.LittleEndian.PutUint32(word, uint32(i+1))
		src.Write(word)
	}
	got, err := NewPaymentRandomHex(&src)
	if err != nil {
		t.Fatalf("NewPaymentRandomHex: %v", err)
	}
	if want := "0100000002000000030000000400000005000000060000000700000008000000"; got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
	if _, err := hex.DecodeString(got); err != nil {
		t.Fatal(err)
	}
}
