package mfa

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

const recoveryCodeCount = 10

// GenerateTOTPSecret creates a new base32 TOTP secret for the account.
func GenerateTOTPSecret(issuer, accountName string) (secret, provisioningURL string, err error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: accountName,
		Period:      30,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		return "", "", fmt.Errorf("generate totp key: %w", err)
	}
	return key.Secret(), key.URL(), nil
}

// ValidateTOTP checks a six-digit code against the secret (30s window, ±1 step).
func ValidateTOTP(secret, code string) bool {
	secret = strings.TrimSpace(strings.ToUpper(secret))
	code = strings.TrimSpace(code)
	if secret == "" || code == "" {
		return false
	}
	if _, err := base32.StdEncoding.DecodeString(secret); err != nil {
		if _, err2 := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret); err2 != nil {
			return false
		}
	}
	return totp.Validate(code, secret)
}

// GenerateRecoveryCodes returns plaintext codes and their SHA-256 hashes.
func GenerateRecoveryCodes() (codes []string, hashes [][]byte, err error) {
	codes = make([]string, recoveryCodeCount)
	hashes = make([][]byte, recoveryCodeCount)
	for i := range codes {
		c, err := randomRecoveryCode()
		if err != nil {
			return nil, nil, err
		}
		codes[i] = c
		hashes[i] = HashRecoveryCode(c)
	}
	return codes, hashes, nil
}

func randomRecoveryCode() (string, error) {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	raw := strings.ToUpper(hex.EncodeToString(b))
	return raw[:4] + "-" + raw[4:], nil
}

// HashRecoveryCode returns SHA-256 of the normalized recovery code.
func HashRecoveryCode(code string) []byte {
	norm := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(code), "-", ""))
	h := sha256.Sum256([]byte(norm))
	return h[:]
}

// VerifyRecoveryCode compares a code to its stored hash in constant time.
func VerifyRecoveryCode(code string, storedHash []byte) bool {
	candidate := HashRecoveryCode(code)
	return subtle.ConstantTimeCompare(candidate, storedHash) == 1
}
