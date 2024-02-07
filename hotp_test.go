package basicOTP_test

import (
	"fmt"
	"testing"

	"github.com/sebastian-mora/basicOTP"
)

/*
Test data was taken from https://datatracker.ietf.org/doc/html/rfc4226
Appendix D

	The following test data uses the ASCII string
	"12345678901234567890" for the secret:

	Secret = 0x3132333435363738393031323334353637383930
*/
var testCases = []struct {
	Counter  int
	Hex      string
	Decimal  int
	Expected string
}{
	{0, "4c93cf18", 1284755224, "755224"},
	{1, "41397eea", 1094287082, "287082"},
	{2, "82fef30", 137359152, "359152"},
	{3, "66ef7655", 1726969429, "969429"},
	{4, "61c5938a", 1640338314, "338314"},
	{5, "33c083d4", 868254676, "254676"},
	{6, "7256c032", 1918287922, "287922"},
	{7, "4e5b397", 82162583, "162583"},
	{8, "2823443f", 673399871, "399871"},
	{9, "2679dc69", 645520489, "520489"},
}

func TestHTOPGenerate(t *testing.T) {
	config := basicOTP.HOTPConfig{
		CodeLength: 6,
		HashType:   basicOTP.SHA1,
		Secret:     []byte("12345678901234567890"), // Sample secret, replace with actual secret
		Counter:    0,
	}
	hopt := basicOTP.NewHTOP(config)

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Count_%d", tc.Counter), func(t *testing.T) {
			generated := hopt.Generate()

			// Validate the generated code for a specific counter
			if generated != tc.Expected {
				t.Errorf("Expected: %s, Got: %s", tc.Expected, generated)
			}

			// Validate the hopt counter has increased
			if hopt.Counter != tc.Counter+1 {
				t.Errorf("HTOP did not increment, Expected: %d, Got %d", hopt.Counter, tc.Counter)
			}

		})
	}
}

func TestHTOPValidate(t *testing.T) {

	// Define the secret and initial counter for the server and client instances
	secret := []byte("12345678901234567890") // Sample secret, replace with actual secret
	serverCounter := 0
	clientCounter := 0

	// Create server and client instances of hopt with the same secret and initial counters
	serverConfig := basicOTP.HOTPConfig{
		CodeLength: 6,
		HashType:   basicOTP.SHA1,
		Secret:     secret,
		Counter:    serverCounter,
	}
	serverHTOP := basicOTP.NewHTOP(serverConfig)

	clientConfig := basicOTP.HOTPConfig{
		CodeLength: 6,
		HashType:   basicOTP.SHA1,
		Secret:     secret,
		Counter:    clientCounter,
	}
	clientHTOP := basicOTP.NewHTOP(clientConfig)

	for _, tc := range testCases {

		previousServerCounter := serverHTOP.Counter
		previousClientCounter := clientHTOP.Counter

		// Generate the OTP for the current test case on the server side
		clientOTPCode := clientHTOP.Generate()

		// Validate the OTP on the client side
		valid := serverHTOP.Validate(clientOTPCode)

		// Ensure the validation result matches the expectation
		if valid && clientOTPCode != tc.Expected {
			t.Errorf("Validation failed for count %d, expected %s, got %s", tc.Counter, tc.Expected, clientOTPCode)
		} else if !valid && clientOTPCode == tc.Expected {
			t.Errorf("Validation passed for count %d, expected validation to fail", tc.Counter)
		}

		// Ensure the server counter is updated correctly after validation
		if valid && serverHTOP.Counter != previousServerCounter+1 {
			t.Errorf("Server counter not updated correctly after validation for count %d", tc.Counter)
		}

		// The client counter should incremented even if rejected
		if !valid && clientHTOP.Counter != previousClientCounter {
			t.Errorf("Client counter not updated correctly after failing validation. Got %d Expected %d", clientHTOP.Counter, previousClientCounter+1)
		}
	}
}

func TestHTOPInvalidCodes(t *testing.T) {
	var testCases = []struct {
		Counter  int
		Input    string
		Expected bool
	}{
		{0, "755223", false}, // off by one
		{0, "aaaaaa", false},
		{99, "755223", false}, // off by one
	}

	config := basicOTP.HOTPConfig{
		CodeLength: 6,
		HashType:   basicOTP.SHA1,
		Secret:     []byte("12345678901234567890"), // Sample secret, replace with actual secret
		Counter:    0,
	}
	hopt := basicOTP.NewHTOP(config)

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Count_%d", tc.Counter), func(t *testing.T) {
			if hopt.Validate(tc.Input) != false {
				t.Errorf("Failed to validate input Expected: %v, Got: %v", false, true)
			}
		})
	}
}

func TestHOPTURI(t *testing.T) {
	secretKey := []byte("Hello!")

	hotpConfig := basicOTP.HOTPConfig{
		CodeLength: 4,
		HashType:   basicOTP.SHA1,
		Secret:     secretKey,
		Counter:    12,
	}

	hopt := basicOTP.NewHTOP(hotpConfig)

	expectedURI := "otpauth://hotp/TEST:alice@google.com?secret=JBSWY3DPEE&issuer=Example&algorithm=SHA1&digits=4&counter=12"
	result := hopt.URI("TEST:alice@google.com", "Example")
	if result != expectedURI {
		t.Errorf("Expected %s, Got %s", expectedURI, result)
	}

}
