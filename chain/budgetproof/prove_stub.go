//go:build !budgetstark

package budgetproof

// prove is the no-cgo stub: this binary cannot prove.
func prove(_ []uint64, _ []byte) (*Proof, error) {
	return nil, ErrUnavailable
}
