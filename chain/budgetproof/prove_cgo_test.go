//go:build budgetstark

package budgetproof

import (
	"crypto/rand"
	"math/big"
	"strings"
	"testing"

	"github.com/invisibook-lab/invisibook/consensus"
)

// The prover's commitments must be exactly what the node recomputes when a
// miner opens them: the table on L1 holds the one, V3 checks the other.
func TestProveMatchesGoCommitments(t *testing.T) {
	amounts := []uint64{10_000_000_000, 3, 0, 1 << 40}
	randoms := make([]string, len(amounts))
	for i := range randoms {
		r, err := consensus.NewPaymentRandomHex(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		randoms[i] = r
	}

	proof, err := Prove(amounts, randoms)
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}
	var total uint64
	for i, a := range amounts {
		total += a
		want, err := consensus.PaymentCommit(new(big.Int).SetUint64(a), randoms[i])
		if err != nil {
			t.Fatal(err)
		}
		if proof.Commitments[i] != want {
			t.Errorf("entry %d: prover committed %s, Go computes %s", i, proof.Commitments[i], want)
		}
	}
	if proof.Prepaid != total {
		t.Errorf("prepaid = %d, want %d", proof.Prepaid, total)
	}
	if len(proof.Bytes) == 0 {
		t.Error("empty proof")
	}
}

func TestProveRejectsBadInput(t *testing.T) {
	if _, err := Prove(nil, nil); err == nil {
		t.Error("empty table accepted")
	}
	if _, err := Prove([]uint64{1}, []string{"zz"}); err == nil {
		t.Error("malformed random accepted")
	}
	// A word equal to the field order is not canonical.
	bad := "0100007f00000000000000000000000000000000000000000000000000000000"
	if _, err := Prove([]uint64{1}, []string{bad}); err == nil {
		t.Error("non-canonical random accepted")
	}
	zero := strings.Repeat("00", 32)
	if _, err := Prove([]uint64{^uint64(0), 1}, []string{zero, zero}); err == nil {
		t.Error("overflowing total accepted")
	}
}
