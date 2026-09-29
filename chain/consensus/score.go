package consensus

import (
	"encoding/binary"
	"math/big"
)

// CalcBlockScore computes a block's score as paymentAmount * vrfFactor,
// where vrfFactor is derived from the first 8 bytes of vrfOutput interpreted
// as a big-endian uint64.
// `paymentAmount` must not be nil; `vrfOutput` must be >= 8 bytes.
func CalcBlockScore(paymentAmount *big.Int, vrfOutput []byte) *big.Int {
	vrfUint64 := binary.BigEndian.Uint64(vrfOutput[:8])
	vrfFactor := new(big.Int).SetUint64(vrfUint64)
	return new(big.Int).Mul(paymentAmount, vrfFactor)
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
