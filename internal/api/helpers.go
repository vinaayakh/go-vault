package api

import "crypto/rand"

func randReadCrypto(b []byte) (int, error) {
	return rand.Read(b)
}

func parseIntParam(s string) (int, error) {
	var n int
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, errBadInt
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}

var errBadInt = &intParseError{}

type intParseError struct{}

func (e *intParseError) Error() string { return "invalid integer" }
