package mfa

import "testing"

func TestValidateTOTP(t *testing.T) {
	secret, _, err := GenerateTOTPSecret("Test", "user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	// Generate a valid code using the library's validate path is hard without time;
	// use totp.GenerateCode in test - import totp
	code, err := generateTestCode(secret)
	if err != nil {
		t.Fatal(err)
	}
	if !ValidateTOTP(secret, code) {
		t.Fatal("expected valid TOTP code")
	}
	if ValidateTOTP(secret, "000000") {
		t.Fatal("expected invalid code to fail")
	}
}

func TestRecoveryCodes(t *testing.T) {
	codes, hashes, err := GenerateRecoveryCodes()
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != recoveryCodeCount {
		t.Fatalf("want %d codes, got %d", recoveryCodeCount, len(codes))
	}
	for i, c := range codes {
		if !VerifyRecoveryCode(c, hashes[i]) {
			t.Fatalf("recovery code %d verify failed", i)
		}
		if VerifyRecoveryCode(c+"x", hashes[i]) {
			t.Fatalf("wrong code should not verify")
		}
	}
}
