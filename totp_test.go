package basicOTP_test

import (
	"fmt"
	"testing"

	"github.com/sebastian-mora/basicOTP"
)

func TestGenerateAt(t *testing.T) {
	secretKey := []byte("TEST")
	codeLength := 4

	testCases := []struct {
		timeStamp int64
		hashType  basicOTP.HashType
		expected  string
	}{
		// Test Case 1: Using SHA-256 and timestamp 1706984502
		{1706984502, basicOTP.SHA256, "0133"},

		// Test Case 2: Using SHA-256 and a different timestamp
		{1706984600, basicOTP.SHA256, "1183"},

		// Test Case 3: Using SHA-512 and timestamp 1706984502
		{1706984502, basicOTP.SHA512, "4442"},

		// Test Case 4: Using SHA-512 and a different timestamp
		{1706984835, basicOTP.SHA512, "4434"},

		// Test Case 3: Using SHA-1 and timestamp 1706984502
		{1706984502, basicOTP.SHA1, "8253"},

		// Test Case 4: Using SHA-1 and a different timestamp
		{1706984835, basicOTP.SHA1, "0267"},

		// Add more test cases as needed
	}

	t.Parallel()

	for _, testCase := range testCases {

		t.Run(fmt.Sprintf("Timestamp %d", testCase.timeStamp), func(t *testing.T) {
			totpConfig := basicOTP.TOTPConfig{
				TimeInterval: 30,
				CodeLength:   4,
				HashType:     testCase.hashType,
				Secret:       secretKey,
			}

			totp := basicOTP.NewTOTP(totpConfig)

			// Generate TOTP based on the provided time
			output := totp.GenerateAt(testCase.timeStamp)

			// Check the generated TOTP against the expected value
			if output != testCase.expected {
				t.Errorf("Generated TOTP is incorrect. Expected: %s, Got: %s", testCase.expected, output)
			}

			// Check the length of the generated TOTP
			if len(output) != codeLength {
				t.Errorf("Generated TOTP length is not %d digits. Got: %d", codeLength, len(output))
			}

			t.Log(output)
		})
	}
}

func TestValidateAt(t *testing.T) {
	secretKey := []byte("TEST")

	testCases := []struct {
		timeStamp int64
		hashType  basicOTP.HashType
		inputCode string
		expected  bool
	}{
		// Test Case 1: Valid Code
		{1706984502, basicOTP.SHA256, "0133", true},

		// Test Case 2: Invalid Code
		{1706984502, basicOTP.SHA256, "1111", false},

		// Test Case 3: Expired Code
		{1706984502, basicOTP.SHA256, "1234", false},
	}

	t.Parallel()
	for _, testCase := range testCases {

		t.Run(fmt.Sprintf("Timestamp %d", testCase.timeStamp), func(t *testing.T) {
			totpConfig := basicOTP.TOTPConfig{
				TimeInterval: 30,
				CodeLength:   4,
				HashType:     testCase.hashType,
				Secret:       secretKey,
			}

			totp := basicOTP.NewTOTP(totpConfig)

			// Generate TOTP based on the provided time
			output := totp.ValidateAt(testCase.timeStamp, testCase.inputCode)

			// Check the generated TOTP against the expected value
			if output != testCase.expected {
				t.Errorf("Code validation failed. Expected: %v, Got: %v", testCase.expected, output)
			}

			t.Log(output)
		})
	}
}

func TestValidate(t *testing.T) {
	secretKey := []byte("TEST")

	totpConfig := basicOTP.TOTPConfig{
		TimeInterval: 30,
		CodeLength:   4,
		HashType:     basicOTP.SHA1,
		Secret:       secretKey,
	}

	totp := basicOTP.NewTOTP(totpConfig)

	code := totp.Generate()
	result := totp.Validate(code)

	if result != true {
		t.Errorf("Code validation failed. Expected True, Got %v", result)
	}

	resultOfBadCode := totp.Validate("1234")

	if resultOfBadCode != false {
		t.Errorf("Code validation failed. Expected True, Got %v", resultOfBadCode)
	}
}

func TestTOTPURI(t *testing.T) {
	secretKey := []byte("Hello!")

	totpConfig := basicOTP.TOTPConfig{
		TimeInterval: 30,
		CodeLength:   4,
		HashType:     basicOTP.SHA1,
		Secret:       secretKey,
	}

	totp := basicOTP.NewTOTP(totpConfig)

	expectedURI := "otpauth://totp/TEST:alice@google.com?secret=JBSWY3DPEE&issuer=Example&algorithm=SHA1&digits=4"
	result := totp.URI("TEST:alice@google.com", "Example")
	if result != expectedURI {
		t.Errorf("Expected %s, Got %s", expectedURI, result)
	}

}

func TestTOTPDefaultTimeInterval(t *testing.T) {
	topt := basicOTP.NewTOTP(basicOTP.TOTPConfig{
		CodeLength: 6,
		HashType:   basicOTP.SHA1,
		Secret:     []byte("Hello!"),
	})

	if topt.TimePeriod != 30 {
		t.Error("TOPT default time period was not set to 30 seconds")
	}
}
