package core

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/iden3/go-iden3-crypto/poseidon"
)

// This file is the Go half of the frozen shielded-pool spec (plan rev. 3,
// "Protocol equations"). The Rust twin lives in `lib/chain/src/note.rs`,
// the circom twin in `lib/zk/templates/note.circom`. All three are pinned
// byte-for-byte by `spec/golden.json`; change nothing here without
// regenerating the golden vectors in all three languages.
//
// Derivations (`P2` = 2-input circomlib Poseidon over BN254 Fr):
//
//	nk  = P2(TAG_NK,  sk)          npk = P2(TAG_NPK, sk)
//	cm  = P2( P2( P2( P2(TAG_CM, npk), assetID ), v ), r )
//	rho = P2( P2(TAG_RHO, cm), leafIndex )
//	nf  = P2( P2(TAG_NF,  nk), rho )

// Domain tags namespacing every Poseidon use (spec constants — never reuse).
const (
	TagNK  = 1
	TagNPK = 2
	TagCM  = 3
	TagRHO = 4
	TagNF  = 5
)

// TreeDepth is the note commitment tree depth (2^20 ≈ 1M notes).
const TreeDepth = 20

// MaxTokenSymbolBytes bounds token symbols so AssetID never reduces mod r
// (a reduced symbol could alias another one).
const MaxTokenSymbolBytes = 31

// frModulus is the BN254 scalar field modulus r.
var frModulus, _ = new(big.Int).SetString(
	"21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)

// emptyRoots[d] is the root of an empty subtree of depth d:
// E_0 = Fr("invisibook.empty"), E_{d+1} = P2(E_d, E_d).
var emptyRoots = computeEmptyRoots()

// Poseidon2 is the bare 2-input circomlib Poseidon over BN254 — the P2 every
// shielded-pool derivation is built from. Panics only on library failure,
// which cannot happen for two in-range field elements.
func Poseidon2(a, b *big.Int) *big.Int {
	h, err := poseidon.Hash([]*big.Int{a, b})
	if err != nil {
		panic(fmt.Sprintf("poseidon hash failed: %v", err))
	}
	return h
}

// FrFromBE interprets bytes as a big-endian integer reduced into Fr — the
// convention every secret and hash output enters the field by.
func FrFromBE(bytes []byte) *big.Int {
	return new(big.Int).Mod(new(big.Int).SetBytes(bytes), frModulus)
}

// FrToHex renders a field element as the 64-char lowercase big-endian hex
// string used on the wire and in storage.
func FrToHex(x *big.Int) string {
	return fmt.Sprintf("%064x", x)
}

// EmptyLeaf returns the empty tree leaf: Fr of ASCII "invisibook.empty".
// A raw constant, not a Poseidon image — no note commitment can collide.
func EmptyLeaf() *big.Int {
	return FrFromBE([]byte("invisibook.empty"))
}

func computeEmptyRoots() [TreeDepth + 1]*big.Int {
	var roots [TreeDepth + 1]*big.Int
	roots[0] = EmptyLeaf()
	for d := 1; d <= TreeDepth; d++ {
		roots[d] = Poseidon2(roots[d-1], roots[d-1])
	}
	return roots
}

// EmptyRoot returns the root of an empty subtree of the given depth.
// `depth` must be in [0, TreeDepth].
func EmptyRoot(depth int) *big.Int {
	return new(big.Int).Set(emptyRoots[depth])
}

// AssetID maps a token symbol to its field element: the UTF-8 bytes read as
// a big-endian integer. The symbol must be 1..=31 bytes so no reduction
// happens and distinct symbols stay distinct.
func AssetID(token TokenID) (*big.Int, error) {
	b := []byte(token)
	if len(b) == 0 || len(b) > MaxTokenSymbolBytes {
		return nil, fmt.Errorf("token symbol must be 1..=%d bytes, got %d (%q)",
			MaxTokenSymbolBytes, len(b), token)
	}
	return new(big.Int).SetBytes(b), nil
}

// NoteCommit computes the tagged nested commitment chain
// cm = P2(P2(P2(P2(TAG_CM, npk), assetID), v), r).
func NoteCommit(npk, assetID *big.Int, v uint64, r *big.Int) *big.Int {
	c := Poseidon2(big.NewInt(TagCM), npk)
	c = Poseidon2(c, assetID)
	c = Poseidon2(c, new(big.Int).SetUint64(v))
	return Poseidon2(c, r)
}

// NoteRho computes rho = P2(P2(TAG_RHO, cm), leafIndex), binding a note's
// nullifier to its tree position (one note, one nullifier).
func NoteRho(cm *big.Int, leafIndex uint64) *big.Int {
	return Poseidon2(Poseidon2(big.NewInt(TagRHO), cm), new(big.Int).SetUint64(leafIndex))
}

// NoteNullifier computes nf = P2(P2(TAG_NF, nk), rho).
func NoteNullifier(nk, rho *big.Int) *big.Int {
	return Poseidon2(Poseidon2(big.NewInt(TagNF), nk), rho)
}

// BindHash computes the bind public input: SHA-256 over u32-BE
// length-prefixed fields, reduced BE into Fr. The field layout of each
// request is canonical and pinned by the golden vector; must match Rust's
// `note::bind_hash`.
func BindHash(fields ...[]byte) *big.Int {
	h := sha256.New()
	for _, f := range fields {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(f)))
		h.Write(l[:])
		h.Write(f)
	}
	return FrFromBE(h.Sum(nil))
}

// ────────────────────── Incremental frontier ──────────────────────

// Frontier is the O(depth) append-only tree state the chain keeps: enough
// to append leaves and produce the root after every append. Mirrors the
// Rust client tree (`lib/chain/src/note_tree.rs`) byte-for-byte.
type Frontier struct {
	// filled[level] holds the completed left sibling subtree root at
	// `level` for the subtree the next leaf extends.
	filled [TreeDepth]*big.Int
	size   uint64
	root   *big.Int
}

// NewFrontier returns an empty tree whose root is EmptyRoot(TreeDepth).
func NewFrontier() *Frontier {
	f := &Frontier{size: 0, root: EmptyRoot(TreeDepth)}
	for i := range f.filled {
		f.filled[i] = EmptyRoot(0)
	}
	return f
}

// Size returns the number of leaves appended so far.
func (f *Frontier) Size() uint64 { return f.size }

// Root returns the current root over all appended leaves.
func (f *Frontier) Root() *big.Int { return new(big.Int).Set(f.root) }

// Append inserts a leaf and returns its index. Returns an error when the
// tree is full — callers must treat that as a permanent insert failure.
func (f *Frontier) Append(leaf *big.Int) (uint64, error) {
	if f.size >= 1<<TreeDepth {
		return 0, fmt.Errorf("note tree is full (%d leaves)", f.size)
	}
	index := f.size
	cur := new(big.Int).Set(leaf)
	for level := 0; level < TreeDepth; level++ {
		if (index>>uint(level))&1 == 0 {
			// Left child: remember it for the future right sibling and
			// pad the right side with the empty subtree for now.
			f.filled[level] = new(big.Int).Set(cur)
			cur = Poseidon2(cur, emptyRoots[level])
		} else {
			cur = Poseidon2(f.filled[level], cur)
		}
	}
	f.size++
	f.root = cur
	return index, nil
}

// FrontierState serializes the frontier for persistence (tree_state row).
type FrontierState struct {
	Size   uint64   `json:"size"`
	Filled []string `json:"filled"` // 64-char hex per level
	Root   string   `json:"root"`
}

// State snapshots the frontier into its serializable form.
func (f *Frontier) State() FrontierState {
	filled := make([]string, TreeDepth)
	for i, x := range f.filled {
		filled[i] = FrToHex(x)
	}
	return FrontierState{Size: f.size, Filled: filled, Root: FrToHex(f.root)}
}

// FrontierFromState rebuilds a frontier from its serialized form.
// The state must carry exactly TreeDepth filled entries of 64-char hex.
func FrontierFromState(s FrontierState) (*Frontier, error) {
	if len(s.Filled) != TreeDepth {
		return nil, fmt.Errorf("frontier state has %d levels, want %d", len(s.Filled), TreeDepth)
	}
	f := &Frontier{size: s.Size}
	for i, hx := range s.Filled {
		x, ok := new(big.Int).SetString(hx, 16)
		if !ok {
			return nil, fmt.Errorf("frontier level %d is not hex: %q", i, hx)
		}
		f.filled[i] = x
	}
	root, ok := new(big.Int).SetString(s.Root, 16)
	if !ok {
		return nil, fmt.Errorf("frontier root is not hex: %q", s.Root)
	}
	f.root = root
	return f, nil
}
