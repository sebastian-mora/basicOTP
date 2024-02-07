package basicOTP_test

import (
	"strconv"
	"testing"

	"github.com/sebastian-mora/basicOTP"
)

func TestOTPLength(t *testing.T) {
	secretKey := []byte("test")
	codeLength := 6

	otp := basicOTP.NewOTP(secretKey, basicOTP.SHA1, codeLength)

	// Check the length of the generated TOTP
	output := otp.Generate(2)
	if len(output) != codeLength {
		t.Errorf("Generated TOTP length is not %d digits. Got: %d", codeLength, len(output))
	}
}

func TestOTPConsistency(t *testing.T) {
	secretKey := []byte("test")
	codeLength := 6

	otp := basicOTP.NewOTP(secretKey, basicOTP.SHA1, codeLength)

	// Check for consistency by generating multiple OTPs with the same input
	for i := 0; i < 5; i++ {
		output := otp.Generate(2)
		newOutput := otp.Generate(2)
		if newOutput != output {
			t.Errorf("Inconsistent TOTP generation. Expected: %s, Got: %s", output, newOutput)
		}
	}
}

func TestOTPNumericFormat(t *testing.T) {
	secretKey := []byte("test")
	codeLength := 6

	otp := basicOTP.NewOTP(secretKey, basicOTP.SHA1, codeLength)

	// Check that the OTP consists only of numeric characters
	output := otp.Generate(2)
	if _, err := strconv.Atoi(output); err != nil {
		t.Errorf("Generated TOTP contains non-numeric characters. Got: %s", output)
	}
}

func TestOTPNonZeroInput(t *testing.T) {
	secretKey := []byte("test")
	codeLength := 6

	otp := basicOTP.NewOTP(secretKey, basicOTP.SHA1, codeLength)

	// Verify that generating an OTP with a non-zero input produces a non-empty result
	nonZeroOutput := otp.Generate(1)
	if len(nonZeroOutput) == 0 {
		t.Errorf("Generated TOTP with non-zero input is empty.")
	}
}

func TestOTPRandomness(t *testing.T) {
	secretKey := []byte("test")
	codeLength := 6

	otp := basicOTP.NewOTP(secretKey, basicOTP.SHA1, codeLength)

	// Confirm that generating OTPs with different inputs results in different OTPs
	output1 := otp.Generate(1)
	output2 := otp.Generate(2)
	if output1 == output2 {
		t.Errorf("Different inputs produce the same TOTP. Input 1: %s, Input 2: %s", output1, output2)
	}
}
