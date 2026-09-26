package ckb

import (
	"encoding/binary"
	"strings"
	"testing"
)

// entry builds a table row whose commitment is `fill` repeated, so that a
// test can tell rows apart at a glance.
func entry(height uint32, fill string) BudgetEntry {
	return BudgetEntry{Height: height, Commitment: strings.Repeat(fill, commitmentLen*2)}
}

func TestBudgetDataRoundTrip(t *testing.T) {
	want := &BudgetData{
		Prepaid: 1_234_500_000_000,
		Allocations: []BudgetEntry{
			entry(1, "a"),
			entry(7, "b"),
			entry(4096, "c"),
		},
	}

	encoded, err := want.Encode()
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}
	// The layout the on-chain script and any other reader depend on: the
	// total in front as a bare u64, then the molecule fixvec.
	if size := prepaidLen + fixvecHeaderLen + 3*allocationLen; len(encoded) != size {
		t.Fatalf("encoded to %d bytes, want %d", len(encoded), size)
	}
	if got := binary.LittleEndian.Uint64(encoded[:prepaidLen]); got != want.Prepaid {
		t.Fatalf("prepaid reads back as %d, want %d", got, want.Prepaid)
	}
	if got := binary.LittleEndian.Uint32(encoded[prepaidLen : prepaidLen+fixvecHeaderLen]); got != 3 {
		t.Fatalf("fixvec declares %d items, want 3", got)
	}

	got, err := DecodeBudgetData(encoded)
	if err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if got.Prepaid != want.Prepaid || len(got.Allocations) != len(want.Allocations) {
		t.Fatalf("round trip gave %+v, want %+v", got, want)
	}
	for i, allocation := range got.Allocations {
		if allocation != want.Allocations[i] {
			t.Fatalf("allocation %d round tripped to %+v, want %+v", i, allocation, want.Allocations[i])
		}
	}
}

// The on-chain script reads the total out of the first 8 bytes and nothing
// else, so a cell carrying only a total is well formed.
func TestBudgetDataEmptyTable(t *testing.T) {
	encoded, err := (&BudgetData{Prepaid: 42}).Encode()
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}
	got, err := DecodeBudgetData(encoded)
	if err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if got.Prepaid != 42 || len(got.Allocations) != 0 {
		t.Fatalf("decoded %+v, want prepaid 42 and no allocations", got)
	}

	// A cell holding the bare total, with no fixvec header at all, reads the
	// same way: pob-budget accepts it, so this side has to as well.
	bare := make([]byte, prepaidLen)
	binary.LittleEndian.PutUint64(bare, 42)
	got, err = DecodeBudgetData(bare)
	if err != nil {
		t.Fatalf("decoding a table-less cell: %v", err)
	}
	if got.Prepaid != 42 || len(got.Allocations) != 0 {
		t.Fatalf("decoded %+v, want prepaid 42 and no allocations", got)
	}
}

// A table that is not ascending has two commitments claiming one height with
// no rule to choose between them, so it is refused on the way in rather than
// left for a reader to resolve.
func TestBudgetDataRejectsDisorder(t *testing.T) {
	cases := map[string][]BudgetEntry{
		"descending": {entry(9, "a"), entry(2, "b")},
		"duplicate":  {entry(3, "a"), entry(3, "b")},
	}
	for name, allocations := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := (&BudgetData{Prepaid: 1, Allocations: allocations}).Encode(); err == nil {
				t.Fatal("encoded a table that is not ascending by height")
			}
		})
	}
}

func TestBudgetDataRejectsShortCommitment(t *testing.T) {
	_, err := (&BudgetData{
		Prepaid:     1,
		Allocations: []BudgetEntry{{Height: 1, Commitment: "abcd"}},
	}).Encode()
	if err == nil {
		t.Fatal("encoded a commitment that is not 32 bytes")
	}
}

// A count read off the chain decides how much this side allocates, so it is
// checked against the bytes actually present before anything is reserved.
func TestDecodeBudgetDataRejectsBadCount(t *testing.T) {
	encoded, err := (&BudgetData{Prepaid: 1, Allocations: []BudgetEntry{entry(1, "a")}}).Encode()
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}

	overstated := append([]byte(nil), encoded...)
	binary.LittleEndian.PutUint32(overstated[prepaidLen:prepaidLen+fixvecHeaderLen], 1<<20)
	if _, err := DecodeBudgetData(overstated); err == nil {
		t.Fatal("accepted a fixvec claiming a million entries it does not carry")
	}

	if _, err := DecodeBudgetData(encoded[:len(encoded)-1]); err == nil {
		t.Fatal("accepted a table truncated mid-entry")
	}
	if _, err := DecodeBudgetData([]byte{1, 2, 3}); err == nil {
		t.Fatal("accepted data too short to hold the prepaid total")
	}
}

func TestBudgetDataLookup(t *testing.T) {
	data := &BudgetData{Allocations: []BudgetEntry{entry(2, "a"), entry(5, "b"), entry(9, "c")}}

	if got, ok := data.Lookup(5); !ok || got != entry(5, "b").Commitment {
		t.Fatalf("Lookup(5) = %q, %v", got, ok)
	}
	// A height the miner did not bid on is an ordinary answer, not an error:
	// a table covers what its owner chose and says nothing about the rest.
	for _, height := range []uint32{1, 6, 100} {
		if _, ok := data.Lookup(height); ok {
			t.Fatalf("Lookup(%d) found an allocation that was never written", height)
		}
	}
}
