// Package miner is the operator's side of Proof-of-Buy: deciding how much to
// prepay on L1 and how to divide it among L2 heights, keeping the openings
// that make those allocations usable, and declaring them to the node.
//
// It sits above both `consensus` and `ckb` because it needs both — the
// consensus book that declarations land in, and the CKB wallet that pays —
// and is what the browser console and `cmd/pob-miner` share.
package miner

import (
	"fmt"
	"math/big"
	"strings"
)

// ShannonPerCKB is how many shannon make one CKB. Everything on the wire to L1
// is in shannon; the console speaks CKB because that is what a person thinks
// in.
const ShannonPerCKB = 100_000_000

// ckbDecimals is the number of fractional digits a CKB amount can carry.
const ckbDecimals = 8

// ParseCKB converts a decimal CKB amount such as "1500" or "0.25" to shannon.
// It rejects signs, exponents, more than 8 fractional digits, and zero.
func ParseCKB(s string) (*big.Int, error) {
	s = strings.TrimSpace(s)
	whole, frac, _ := strings.Cut(s, ".")
	if whole == "" && frac == "" {
		return nil, fmt.Errorf("%q is not a CKB amount", s)
	}
	if len(frac) > ckbDecimals {
		return nil, fmt.Errorf("%q has more than %d decimal places", s, ckbDecimals)
	}
	// Right-pad the fraction so the digits read as shannon directly.
	digits := whole + frac + strings.Repeat("0", ckbDecimals-len(frac))
	if strings.TrimLeft(digits, "0123456789") != "" {
		return nil, fmt.Errorf("%q is not a CKB amount", s)
	}
	shannon, ok := new(big.Int).SetString(digits, 10)
	if !ok || shannon.Sign() <= 0 {
		return nil, fmt.Errorf("%q is not a positive CKB amount", s)
	}
	return shannon, nil
}

// FormatCKB renders shannon as a decimal CKB amount with trailing zeros
// trimmed, the inverse of ParseCKB. `shannon` must not be negative.
func FormatCKB(shannon *big.Int) string {
	whole, frac := new(big.Int).QuoRem(shannon, big.NewInt(ShannonPerCKB), new(big.Int))
	if frac.Sign() == 0 {
		return whole.String()
	}
	fracDigits := fmt.Sprintf("%0*d", ckbDecimals, frac)
	return whole.String() + "." + strings.TrimRight(fracDigits, "0")
}
