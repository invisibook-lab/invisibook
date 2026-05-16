package core

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// VerifyMpcMac checks the SPDZ MAC relationship for both the `cmp` and
// `r_loser` authenticated values produced by the two-party MPC settle protocol.
//
// For each value v with shares (s_A, s_B), MACs (m_A, m_B), and MAC-key
// shares (delta_A, delta_B), the invariant is:
//
//	m_A + m_B == (delta_A + delta_B) * (s_A + s_B)   (mod BN254 scalar field)
//
// Both `cmp` (the comparison result) and `r_loser` (the loser's random) are
// verified under the same MAC key.
func VerifyMpcMac(shareA, shareB *MpcShareData) error {
	deltaA, err := parseFr(shareA.MacKeyShare, "A.mac_key_share")
	if err != nil {
		return err
	}
	deltaB, err := parseFr(shareB.MacKeyShare, "B.mac_key_share")
	if err != nil {
		return err
	}
	// delta = delta_A + delta_B
	var delta fr.Element
	delta.Add(&deltaA, &deltaB)

	// Verify cmp shares
	if err := verifyOneValue(
		shareA.CmpShare, shareB.CmpShare,
		shareA.CmpMac, shareB.CmpMac,
		&delta, "cmp",
	); err != nil {
		return err
	}

	// Verify r_smaller shares
	if err := verifyOneValue(
		shareA.RSmallerShare, shareB.RSmallerShare,
		shareA.RSmallerMac, shareB.RSmallerMac,
		&delta, "r_smaller",
	); err != nil {
		return err
	}

	return nil
}

// verifyOneValue checks (mac_A + mac_B) == delta * (share_A + share_B).
func verifyOneValue(
	shareAStr, shareBStr string,
	macAStr, macBStr string,
	delta *fr.Element,
	label string,
) error {
	sA, err := parseFr(shareAStr, label+".share_A")
	if err != nil {
		return err
	}
	sB, err := parseFr(shareBStr, label+".share_B")
	if err != nil {
		return err
	}
	mA, err := parseFr(macAStr, label+".mac_A")
	if err != nil {
		return err
	}
	mB, err := parseFr(macBStr, label+".mac_B")
	if err != nil {
		return err
	}

	// lhs = mac_A + mac_B
	var lhs fr.Element
	lhs.Add(&mA, &mB)

	// rhs = delta * (share_A + share_B)
	var sum, rhs fr.Element
	sum.Add(&sA, &sB)
	rhs.Mul(delta, &sum)

	if lhs != rhs {
		return fmt.Errorf("MPC MAC check failed for %s: (mac_A + mac_B) != delta * (share_A + share_B)", label)
	}
	return nil
}

// parseFr parses a decimal string into a BN254 scalar field element.
func parseFr(s, label string) (fr.Element, error) {
	var e fr.Element
	if _, err := e.SetString(s); err != nil {
		return e, fmt.Errorf("invalid Fr decimal for %s: %w", label, err)
	}
	return e, nil
}
