package consensus

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
)

// Poseidon2 over KoalaBear, width 16, x^3 S-box, 4 + 20 + 4 rounds: the
// permutation behind every PoB payment commitment (the allocation table of a
// budget cell). L2 cash and reward commitments are a different thing and stay
// on BN254 Poseidon (PoseidonCommit), shared with the wallet circuits.
//
// Ported from Plonky3, p3-koala-bear 0.8.0's `default_koalabear_poseidon2_16`.
// It has to agree with the Rust side bit for bit — the budget cell's balance proof
// (lib/budget-stark) is over commitments that Rust computes and this file
// reopens — and poseidon2_test.go pins it to vectors dumped from Rust.

// koalaBearP is the KoalaBear prime, 2^31 - 2^24 + 1.
const koalaBearP = 0x7f000001

const (
	p2Width    = 16
	digestLen  = 8
	randomLen  = 8
	amountLimb = 4
)

// kbMul multiplies two canonical field elements.
func kbMul(a, b uint32) uint32 {
	return uint32(uint64(a) * uint64(b) % koalaBearP)
}

// kbAdd adds two canonical field elements.
func kbAdd(a, b uint32) uint32 {
	s := a + b // both < 2^31, so no overflow
	if s >= koalaBearP {
		s -= koalaBearP
	}
	return s
}

// kbSub subtracts two canonical field elements.
func kbSub(a, b uint32) uint32 {
	if a >= b {
		return a - b
	}
	return a + koalaBearP - b
}

// kbPow raises a canonical field element to `e`.
func kbPow(a uint32, e uint64) uint32 {
	result := uint32(1)
	for ; e > 0; e >>= 1 {
		if e&1 == 1 {
			result = kbMul(result, a)
		}
		a = kbMul(a, a)
	}
	return result
}

// kbInv inverts a non-zero canonical field element.
func kbInv(a uint32) uint32 {
	return kbPow(a, koalaBearP-2)
}

// kbNeg negates a canonical field element.
func kbNeg(a uint32) uint32 {
	return kbSub(0, a)
}

// p2InternalDiag is the internal layer's diagonal, from p3-koala-bear:
// [-2, 1, 2, 1/2, 3, 4, -1/2, -3, -4, 1/2^8, 1/8, 1/2^24, -1/2^8, -1/8, -1/16, -1/2^24].
// The internal layer maps s_i to D_i·s_i + Σs.
var p2InternalDiag = func() [p2Width]uint32 {
	inv2k := func(k uint64) uint32 { return kbInv(kbPow(2, k)) }
	return [p2Width]uint32{
		kbNeg(2), 1, 2, inv2k(1), 3, 4, kbNeg(inv2k(1)), kbNeg(3), kbNeg(4),
		inv2k(8), inv2k(3), inv2k(24), kbNeg(inv2k(8)), kbNeg(inv2k(3)), kbNeg(inv2k(4)), kbNeg(inv2k(24)),
	}
}()

// Round constants, canonical form, from p3-koala-bear's
// KOALABEAR_POSEIDON2_RC_16_{EXTERNAL_INITIAL, INTERNAL, EXTERNAL_FINAL}.
var (
	p2ExternalInitial = [4][p2Width]uint32{
		{0x7ee56a48, 0x11367045, 0x12e41941, 0x7ebbc12b, 0x1970b7d5, 0x662b60e8, 0x3e4990c6, 0x679f91f5,
			0x350813bb, 0x00874ad4, 0x28a0081a, 0x18fa5872, 0x5f25b071, 0x5e5d5998, 0x5e6fd3e7, 0x5b2e2660},
		{0x6f1837bf, 0x3fe6182b, 0x1edd7ac5, 0x57470d00, 0x43d486d5, 0x1982c70f, 0x0ea53af9, 0x61d6165b,
			0x51639c00, 0x2dec352c, 0x2950e531, 0x2d2cb947, 0x08256cef, 0x1a0109f6, 0x1f51faf3, 0x5cef1c62},
		{0x3d65e50e, 0x33d91626, 0x133d5a1e, 0x0ff49b0d, 0x38900cd1, 0x2c22cc3f, 0x28852bb2, 0x06c65a02,
			0x7b2cf7bc, 0x68016e1a, 0x15e16bc0, 0x5248149a, 0x6dd212a0, 0x18d6830a, 0x5001be82, 0x64dac34e},
		{0x5902b287, 0x426583a0, 0x0c921632, 0x3fe028a5, 0x245f8e49, 0x43bb297e, 0x7873dbd9, 0x3cc987df,
			0x286bb4ce, 0x640a8dcd, 0x512a8e36, 0x03a4cf55, 0x481837a2, 0x03d6da84, 0x73726ac7, 0x760e7fdf},
	}
	p2Internal = [20]uint32{
		0x54dfeb5d, 0x7d40afd6, 0x722cb316, 0x106a4573, 0x45a7ccdb, 0x44061375, 0x154077a5, 0x45744faa,
		0x4eb5e5ee, 0x3794e83f, 0x47c7093c, 0x5694903c, 0x69cb6299, 0x373df84c, 0x46a0df58, 0x46b8758a,
		0x3241ebcb, 0x0b09d233, 0x1af42357, 0x1e66cec2,
	}
	p2ExternalFinal = [4][p2Width]uint32{
		{0x43e7dc24, 0x259a5d61, 0x27e85a3b, 0x1b9133fa, 0x343e5628, 0x485cd4c2, 0x16e269f5, 0x165b60c6,
			0x25f683d9, 0x124f81f9, 0x174331f9, 0x77344dc5, 0x5a821dba, 0x5fc4177f, 0x54153bf5, 0x5e3f1194},
		{0x3bdbf191, 0x088c84a3, 0x68256c9b, 0x3c90bbc6, 0x6846166a, 0x03f4238d, 0x463335fb, 0x5e3d3551,
			0x6e59ae6f, 0x32d06cc0, 0x596293f3, 0x6c87edb2, 0x08fc60b5, 0x34bcca80, 0x24f007f3, 0x62731c6f},
		{0x1e1db6c6, 0x0ca409bb, 0x585c1e78, 0x56e94edc, 0x16d22734, 0x18e11467, 0x7b2c3730, 0x770075e4,
			0x35d1b18c, 0x22be3db5, 0x4fb1fbb7, 0x477cb3ed, 0x7d5311c6, 0x5b62ae7d, 0x559c5fa8, 0x77f15048},
		{0x3211570b, 0x490fef6a, 0x77ec311f, 0x2247171b, 0x4e0ac711, 0x2edf69c9, 0x3b5a8850, 0x65809421,
			0x5619b4aa, 0x362019a7, 0x6bf9d4ed, 0x5b413dff, 0x617e181e, 0x5e7ab57b, 0x33ad7833, 0x3466c7ca},
	}
)

// cube is the S-box.
func cube(x uint32) uint32 {
	return kbMul(kbMul(x, x), x)
}

// mat4 multiplies one 4-element block by Plonky3's MDSMat4:
// [[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]].
func mat4(x []uint32) {
	t01 := kbAdd(x[0], x[1])
	t23 := kbAdd(x[2], x[3])
	t0123 := kbAdd(t01, t23)
	t01123 := kbAdd(t0123, x[1])
	t01233 := kbAdd(t0123, x[3])
	// Overwrite x[3] and x[1] before x[0] and x[2], which they still read.
	x[3] = kbAdd(t01233, kbAdd(x[0], x[0]))
	x[1] = kbAdd(t01123, kbAdd(x[2], x[2]))
	x[0] = kbAdd(t01123, t01)
	x[2] = kbAdd(t01233, t23)
}

// externalLinear is the external layer: MDSMat4 per block, then every
// element gets the sum of its column across blocks, i.e. multiplication by
// [[2M, M, M, M], [M, 2M, M, M], ...].
func externalLinear(state *[p2Width]uint32) {
	for b := 0; b < p2Width; b += 4 {
		mat4(state[b : b+4])
	}
	var sums [4]uint32
	for i, x := range state {
		sums[i%4] = kbAdd(sums[i%4], x)
	}
	for i := range state {
		state[i] = kbAdd(state[i], sums[i%4])
	}
}

// externalRound adds round constants, cubes every element and mixes.
func externalRound(state *[p2Width]uint32, rc *[p2Width]uint32) {
	for i := range state {
		state[i] = cube(kbAdd(state[i], rc[i]))
	}
	externalLinear(state)
}

// poseidon2Permute applies the permutation in place. Every element must be
// canonical (below koalaBearP).
func poseidon2Permute(state *[p2Width]uint32) {
	externalLinear(state)
	for r := range p2ExternalInitial {
		externalRound(state, &p2ExternalInitial[r])
	}
	for _, rc := range p2Internal {
		state[0] = cube(kbAdd(state[0], rc))
		var sum uint32
		for _, x := range state {
			sum = kbAdd(sum, x)
		}
		for i := range state {
			state[i] = kbAdd(kbMul(p2InternalDiag[i], state[i]), sum)
		}
	}
	for r := range p2ExternalFinal {
		externalRound(state, &p2ExternalFinal[r])
	}
}

// PaymentCommit commits to a payment `amount` under the blinding factor
// `randomHex`:
//
//	Poseidon2([limb_0..limb_3, random_0..random_7, 0, 0, 0, 0])[0..8]
//
// with the amount split into little-endian 16-bit limbs. The result is 64 hex
// characters: the eight output elements as little-endian u32s — the bytes a
// budget cell stores. This is the exact commitment lib/budget-stark proves
// the allocation table's balance over.
//
// `amount` must be non-negative and fit in a u64; `randomHex` must be 64 hex
// characters encoding eight canonical field elements (see
// NewPaymentRandomHex).
func PaymentCommit(amount *big.Int, randomHex string) (string, error) {
	if amount == nil {
		return "", fmt.Errorf("amount is missing")
	}
	if amount.Sign() < 0 || !amount.IsUint64() {
		return "", fmt.Errorf("amount %s is not a u64", amount)
	}
	random, err := decodePaymentRandom(randomHex)
	if err != nil {
		return "", err
	}

	var state [p2Width]uint32
	a := amount.Uint64()
	for j := 0; j < amountLimb; j++ {
		state[j] = uint32(a>>(16*j)) & 0xffff
	}
	copy(state[amountLimb:amountLimb+randomLen], random[:])
	poseidon2Permute(&state)

	out := make([]byte, 4*digestLen)
	for i := 0; i < digestLen; i++ {
		binary.LittleEndian.PutUint32(out[4*i:], state[i])
	}
	return hex.EncodeToString(out), nil
}

// decodePaymentRandom parses a 64-char hex blinding factor into its eight field
// elements, little-endian u32 each. A non-canonical element is refused rather
// than reduced: the Rust prover takes these words as they are, and two
// encodings of one value would open the same commitment.
func decodePaymentRandom(randomHex string) ([randomLen]uint32, error) {
	var out [randomLen]uint32
	if len(randomHex) != RandomHexLen {
		return out, fmt.Errorf("random must be %d hex chars, got %d", RandomHexLen, len(randomHex))
	}
	raw, err := hex.DecodeString(randomHex)
	if err != nil {
		return out, fmt.Errorf("decoding random %q: %w", randomHex, err)
	}
	for i := range out {
		out[i] = binary.LittleEndian.Uint32(raw[4*i:])
		if out[i] >= koalaBearP {
			return out, fmt.Errorf("random word %d (%#x) is not below the field order", i, out[i])
		}
	}
	return out, nil
}

// NewPaymentRandomHex draws a blinding factor for PaymentCommit from `rnd`:
// eight uniformly random canonical field elements (~248 bits), as 64 hex
// characters. Each word is rejection-sampled from 31 random bits, so none is
// biased and none needs reducing. `rnd` must be a cryptographic source: the
// factor is all that hides an allocation until the miner reveals it.
func NewPaymentRandomHex(rnd io.Reader) (string, error) {
	out := make([]byte, 4*randomLen)
	var word [4]byte
	for i := 0; i < randomLen; {
		if _, err := io.ReadFull(rnd, word[:]); err != nil {
			return "", fmt.Errorf("drawing a blinding factor: %w", err)
		}
		x := binary.LittleEndian.Uint32(word[:]) & 0x7fffffff
		if x >= koalaBearP {
			continue
		}
		binary.LittleEndian.PutUint32(out[4*i:], x)
		i++
	}
	return hex.EncodeToString(out), nil
}
