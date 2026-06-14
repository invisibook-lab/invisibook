package consensus

import (
	"encoding/binary"
	"math/big"
)

// CalcBlockScore computes a block's score as paymentAmount * vdfFactor,
// where vdfFactor is derived from the first 8 bytes of vdfOutput interpreted
// as a big-endian uint64.
// `paymentAmount` and `vdfOutput` must not be nil; `vdfOutput` must be >= 8 bytes.
func CalcBlockScore(paymentAmount *big.Int, vdfOutput []byte) *big.Int {
	vdfUint64 := binary.BigEndian.Uint64(vdfOutput[:8])
	vdfFactor := new(big.Int).SetUint64(vdfUint64)
	return new(big.Int).Mul(paymentAmount, vdfFactor)
}

// CalcCumulativeScore sums all provided block scores.
// Returns zero if `scores` is empty.
func CalcCumulativeScore(scores []*big.Int) *big.Int {
	total := new(big.Int)
	for _, s := range scores {
		total.Add(total, s)
	}
	return total
}
