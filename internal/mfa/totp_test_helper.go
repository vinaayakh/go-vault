package mfa

import (
	"time"

	"github.com/pquerna/otp/totp"
)

func generateTestCode(secret string) (string, error) {
	return totp.GenerateCode(secret, time.Now())
}
