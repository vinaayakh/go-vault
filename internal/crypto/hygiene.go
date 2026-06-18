package crypto

import "crypto/subtle"

// Zero overwrites b with zeros in place. Call it on key material and plaintext
// buffers as soon as they are no longer needed.
//
// Honesty about limits: Go's garbage collector may copy a slice's backing array
// (e.g. when a stack-allocated buffer escapes, or during heap compaction) before
// Zero runs, leaving copies that cannot be wiped. Zero reduces the window in
// which secrets sit in a known buffer; it is not a guarantee that no copy of the
// secret remains anywhere in process memory.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ConstantTimeEqual reports whether a and b are equal in constant time relative
// to their contents, preventing timing side channels when comparing secrets
// (e.g. auth hashes). It returns false for differing lengths.
func ConstantTimeEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
