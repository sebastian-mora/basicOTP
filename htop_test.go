package basicOTP

import (
	"fmt"
	"testing"
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
	config := HOTPConfig{
		CodeLength: 6,
		HashType:   SHA1,
		Secret:     []byte("12345678901234567890"), // Sample secret, replace with actual secret
		Counter:    0,
	}
	htop := NewHTOP(config)

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Count_%d", tc.Counter), func(t *testing.T) {
			generated := htop.Generate()

			// Validate the generated code for a specific counter
			if generated != tc.Expected {
				t.Errorf("Expected: %s, Got: %s", tc.Expected, generated)
			}

			// Validate the htop counter has increased
			if htop.Counter != tc.Counter+1 {
				t.Errorf("HTOP did not increment, Expected: %d, Got %d", htop.Counter, tc.Counter)
			}

		})
	}
}

func TestHTOPValidate(t *testing.T) {

	// Define the secret and initial counter for the server and client instances
	secret := []byte("12345678901234567890") // Sample secret, replace with actual secret
	serverCounter := 0
	clientCounter := 0

	// Create server and client instances of htop with the same secret and initial counters
	serverConfig := HOTPConfig{
		CodeLength: 6,
		HashType:   SHA1,
		Secret:     secret,
		Counter:    serverCounter,
	}
	serverHTOP := NewHTOP(serverConfig)

	clientConfig := HOTPConfig{
		CodeLength: 6,
		HashType:   SHA1,
		Secret:     secret,
		Counter:    clientCounter,
	}
	clientHTOP := NewHTOP(clientConfig)

	for _, tc := range testCases {

		// Generate the OTP for the current test case on the server side
		otp := serverHTOP.otp.Generate(tc.Counter)

		// Validate the OTP on the client side
		valid := clientHTOP.Validate(otp)

		// Ensure the validation result matches the expectation
		if valid && otp != tc.Expected {
			t.Errorf("Validation failed for count %d, expected %s, got %s", tc.Counter, tc.Expected, otp)
		} else if !valid && otp == tc.Expected {
			t.Errorf("Validation passed for count %d, expected validation to fail", tc.Counter)
		}

		// Ensure the client counter is updated correctly after validation
		if valid && clientHTOP.Counter != tc.Counter+1 {
			t.Errorf("Client counter not updated correctly after validation for count %d", tc.Counter)
		}

		// Ensure the server counter remains unchanged after validation on the client side
		if valid && serverHTOP.Counter != serverCounter {
			t.Errorf("Server counter should remain unchanged after validation on the client side")
		}
	}
}
