package core

// bumpLastDigit replaces the trailing decimal digit of `s` with a different
// one so the resulting field element no longer matches the original.
//
// The account package has its own copy: an unexported test helper cannot be
// shared across packages, and duplicating eight lines beats exporting a
// tampering utility from production code.
func bumpLastDigit(s string) string {
	if s == "" {
		return "1"
	}
	last := s[len(s)-1]
	next := byte('0')
	if last == '0' {
		next = '1'
	}
	return s[:len(s)-1] + string(next)
}
