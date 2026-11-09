package core

import (
	"encoding/binary"
	"encoding/json"
	"math/big"
	"os"
	"testing"
)

// golden loads spec/golden.json — the cross-language vectors that pin every
// shielded-pool derivation across Go, Rust, and circom.
func golden(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile("../../spec/golden.json")
	if err != nil {
		t.Fatalf("spec/golden.json must exist: %v", err)
	}
	var g map[string]any
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatalf("golden.json must parse: %v", err)
	}
	return g
}

func goldenHex(t *testing.T, g map[string]any, key string) string {
	t.Helper()
	s, ok := g[key].(string)
	if !ok {
		t.Fatalf("golden key %q missing or not a string", key)
	}
	return s
}

// rep32 returns 32 copies of b.
func rep32(b byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = b
	}
	return out
}

func TestGoldenKeysAndAssets(t *testing.T) {
	g := golden(t)
	sk1 := FrFromBE(rep32(0x42))
	nk := Poseidon2(big.NewInt(TagNK), sk1)
	npk := Poseidon2(big.NewInt(TagNPK), sk1)
	if FrToHex(nk) != goldenHex(t, g, "nk1") {
		t.Fatalf("nk mismatch: %s", FrToHex(nk))
	}
	if FrToHex(npk) != goldenHex(t, g, "npk1") {
		t.Fatalf("npk mismatch: %s", FrToHex(npk))
	}
	eth, err := AssetID("ETH")
	if err != nil {
		t.Fatal(err)
	}
	if FrToHex(eth) != goldenHex(t, g, "asset_eth") {
		t.Fatalf("assetID(ETH) mismatch: %s", FrToHex(eth))
	}
	if _, err := AssetID(""); err == nil {
		t.Fatal("empty token symbol must be rejected")
	}
	if _, err := AssetID(TokenID(rep32('X'))); err == nil {
		t.Fatal("32-byte token symbol must be rejected")
	}
}

func TestGoldenCommitmentsAndNullifiers(t *testing.T) {
	g := golden(t)
	sk2 := FrFromBE(rep32(0x43))
	npk2 := Poseidon2(big.NewInt(TagNPK), sk2)
	usdt, _ := AssetID("USDT")
	l1 := NoteCommit(npk2, usdt, 1_000_000, FrFromBE(rep32(0x34)))
	if FrToHex(l1) != goldenHex(t, g, "leaf1") {
		t.Fatalf("leaf1 mismatch: %s", FrToHex(l1))
	}

	rho := NoteRho(l1, 1)
	if FrToHex(rho) != goldenHex(t, g, "rho_leaf1") {
		t.Fatalf("rho mismatch: %s", FrToHex(rho))
	}
	nk2 := Poseidon2(big.NewInt(TagNK), sk2)
	if FrToHex(NoteNullifier(nk2, rho)) != goldenHex(t, g, "nf_leaf1") {
		t.Fatalf("nf mismatch")
	}

	// Dummy slot: same formula over fresh random secrets.
	nkd := Poseidon2(big.NewInt(TagNK), FrFromBE(rep32(0x66)))
	if FrToHex(NoteNullifier(nkd, FrFromBE(rep32(0x77)))) != goldenHex(t, g, "nf_dummy") {
		t.Fatalf("dummy nf mismatch")
	}
}

func TestGoldenFrontierRootAndEmptyRoots(t *testing.T) {
	g := golden(t)
	if FrToHex(EmptyLeaf()) != goldenHex(t, g, "empty_leaf") {
		t.Fatalf("empty leaf mismatch")
	}
	if FrToHex(EmptyRoot(TreeDepth)) != goldenHex(t, g, "empty_root_20") {
		t.Fatalf("empty root mismatch")
	}

	sk1, sk2 := FrFromBE(rep32(0x42)), FrFromBE(rep32(0x43))
	npk1 := Poseidon2(big.NewInt(TagNPK), sk1)
	npk2 := Poseidon2(big.NewInt(TagNPK), sk2)
	eth, _ := AssetID("ETH")
	usdt, _ := AssetID("USDT")
	leaves := []*big.Int{
		NoteCommit(npk1, eth, 7, FrFromBE(rep32(0x33))),
		NoteCommit(npk2, usdt, 1_000_000, FrFromBE(rep32(0x34))),
		NoteCommit(npk1, eth, 5, FrFromBE(rep32(0x35))),
	}

	f := NewFrontier()
	if FrToHex(f.Root()) != goldenHex(t, g, "empty_root_20") {
		t.Fatalf("fresh frontier root must be the empty root")
	}
	for i, l := range leaves {
		idx, err := f.Append(l)
		if err != nil {
			t.Fatal(err)
		}
		if idx != uint64(i) {
			t.Fatalf("leaf index %d, want %d", idx, i)
		}
	}
	if FrToHex(f.Root()) != goldenHex(t, g, "root_after_3") {
		t.Fatalf("root mismatch: %s", FrToHex(f.Root()))
	}

	// Round-trip through the serialized state and keep appending — the
	// restored frontier must behave identically.
	restored, err := FrontierFromState(f.State())
	if err != nil {
		t.Fatal(err)
	}
	extra := NoteCommit(npk1, eth, 9, FrFromBE(rep32(0x36)))
	i1, _ := f.Append(extra)
	i2, _ := restored.Append(extra)
	if i1 != i2 || FrToHex(f.Root()) != FrToHex(restored.Root()) {
		t.Fatalf("restored frontier diverged after append")
	}
}

func TestGoldenBindHash(t *testing.T) {
	g := golden(t)
	var chainID [8]byte
	binary.BigEndian.PutUint64(chainID[:], 1926)
	var version [4]byte
	binary.BigEndian.PutUint32(version[:], 1)
	bind := BindHash(
		[]byte("invisibook.bind.v1"),
		chainID[:],
		[]byte("spend_withdraw"),
		version[:],
		[]byte("abc"),
		[]byte("hello"),
	)
	if FrToHex(bind) != goldenHex(t, g, "bind") {
		t.Fatalf("bind mismatch: %s", FrToHex(bind))
	}
}
