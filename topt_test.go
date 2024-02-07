package basicOTP

import (
	"fmt"
	"testing"
)

func TestGenerateAt(t *testing.T) {
	secretKey := []byte("TEST")
	codeLength := 4

	testCases := []struct {
		timeStamp int64
		hashType  HashType
		expected  string
	}{
		// Test Case 1: Using SHA-256 and timestamp 1706984502
		{1706984502, SHA256, "0133"},

		// Test Case 2: Using SHA-256 and a different timestamp
		{1706984600, SHA256, "1183"},

		// Test Case 3: Using SHA-512 and timestamp 1706984502
		{1706984502, SHA512, "4442"},

		// Test Case 4: Using SHA-512 and a different timestamp
		{1706984835, SHA512, "4434"},

		// Test Case 3: Using SHA-1 and timestamp 1706984502
		{1706984502, SHA1, "8253"},

		// Test Case 4: Using SHA-1 and a different timestamp
		{1706984835, SHA1, "0267"},

		// Add more test cases as needed
	}

	for _, testCase := range testCases {
		t.Run(fmt.Sprintf("Timestamp %d", testCase.timeStamp), func(t *testing.T) {
			totpConfig := TOTPConfig{
				TimeInterval: 30,
				CodeLength: 4,
				HashType: testCase.hashType,
				Secret: secretKey,
			}
			
			totp := NewTOTP(totpConfig)

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

func TestValidateAt(t *testing.T){
	secretKey := []byte("TEST")

	testCases := []struct {
		timeStamp int64
		hashType  HashType
		inputCode  string
		expected bool
	}{
		// Test Case 1: Valid Code
		{1706984502, SHA256, "0133", true},

		// Test Case 2: Invalid Code
		{1706984502, SHA256, "1111", false},

		// Test Case 3: Expired Code
		{1706984502, SHA256, "1234", false},

	}

	for _, testCase := range testCases {
		t.Run(fmt.Sprintf("Timestamp %d", testCase.timeStamp), func(t *testing.T) {
			totpConfig := TOTPConfig{
				TimeInterval: 30,
				CodeLength: 4,
				HashType: testCase.hashType,
				Secret: secretKey,
			}
			
			totp := NewTOTP(totpConfig)

			// Generate TOTP based on the provided time
			output := totp.ValidateAt(testCase.timeStamp, testCase.inputCode)

			// Check the generated TOTP against the expected value
			if output != testCase.expected{
				t.Errorf("Code validation failed. Expected: %v, Got: %v", testCase.expected, output)
			}
	

			t.Log(output)
		})
	}
}

func TestValidate(t *testing.T){
	secretKey := []byte("TEST")

	totpConfig := TOTPConfig{
			TimeInterval: 30,
			CodeLength: 4,
			HashType: SHA1,
			Secret: secretKey,
		}
	
	totp := NewTOTP(totpConfig)

	code := totp.Generate()
	result := totp.Validate(code)

	if result != true {
		t.Errorf("Code validation failed. Expected True, Got %v", result )
	}

	resultOfBadCode := totp.Validate("1234")

	if resultOfBadCode != false {
		t.Errorf("Code validation failed. Expected True, Got %v", resultOfBadCode )
	}
}

func TestURI(t *testing.T){
		secretKey := []byte("Hello!")

	totpConfig := TOTPConfig{
			TimeInterval: 30,
			CodeLength: 4,
			HashType: SHA1,
			Secret: secretKey,
	}
	
	totp := NewTOTP(totpConfig)

	expectedURI := "otpauth://totp/TEST%3Aalice%40google.com?secret=JBSWY3DPEE&issuer=Example&algorithm=sha1&digits=4"
	result := totp.URI("TEST:alice@google.com", "Example")
	if result != expectedURI {
		t.Errorf("Expected %s, Got %s", expectedURI,  result)
	}
	
}