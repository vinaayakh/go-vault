package crypto

// WrapTOTPSecret encrypts a TOTP secret under the vault key for at-rest storage.
func WrapTOTPSecret(vaultKey []byte, secret string) ([]byte, error) {
	return Seal(vaultKey, []byte(secret), []byte("totp-secret-v1"))
}

// UnwrapTOTPSecret decrypts a vault-key-wrapped TOTP secret.
func UnwrapTOTPSecret(vaultKey, wrapped []byte) (string, error) {
	plain, err := Open(vaultKey, wrapped, []byte("totp-secret-v1"))
	if err != nil {
		return "", err
	}
	defer Zero(plain)
	return string(plain), nil
}
