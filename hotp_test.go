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

	// Create server and client instances of hopt with the same secret and initial counters
	serverConfig := basicOTP.HOTPConfig{
		CodeLength: 6,
		HashType:   basicOTP.SHA1,
		Secret:     secret,
		Counter:    serverCounter,
	}
	hotp := basicOTP.NewHTOP(serverConfig)

	for _, tc := range testCases {
		if !hotp.Validate(tc.Expected) {
			t.Errorf("Failed to validate code: %s, counter: %d", tc.Expected, hotp.Counter)
		}

		// ensure the counter incrementing
		if hotp.Counter != tc.Counter+1 {
			t.Errorf("Counter did not increment Got: %d, Expected: %d", hotp.Counter, tc.Counter)
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

func TestHOTPSuccessfulValidationOfOutOfSync(t *testing.T) {

	/*
		The test cases are valid for C=0, setting C=-3 represents
		the server is 3 codes behind the client. The Sync limit is 10
		so all codes should be valid.
	*/
	config := basicOTP.HOTPConfig{
		CodeLength:           6,
		HashType:             basicOTP.SHA1,
		Secret:               []byte("12345678901234567890"), // Sample secret, replace with actual secret
		Counter:              -3,
		SynchronizationLimit: 10,
	}
	hopt := basicOTP.NewHTOP(config)

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Count_%d", tc.Counter), func(t *testing.T) {
			result := hopt.Validate(tc.Expected)

			// Check if the forward lookup worked and returned true
			if !result {
				t.Error("Validation failed, forward look up did not work")
			}

			// Ensure the server synced with the client
			if result && hopt.Counter != tc.Counter {
				t.Errorf("The counter was not synced correctly, Expected %d, Got: %d", 0, hopt.Counter)
			}

		})
	}
}

func TestHOTPSFailedValidationOfOutOfSync(t *testing.T) {

	/*
		The test cases are valid for C=0, setting C=-300 represents
		the server is 300 codes behind the client. The Sync limit is 10
		so all codes should be invalid.
	*/
	config := basicOTP.HOTPConfig{
		CodeLength:           6,
		HashType:             basicOTP.SHA1,
		Secret:               []byte("12345678901234567890"), // Sample secret, replace with actual secret
		Counter:              -300,
		SynchronizationLimit: 10,
	}
	hopt := basicOTP.NewHTOP(config)

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Count_%d", tc.Counter), func(t *testing.T) {
			result := hopt.Validate(tc.Expected)

			// Check if the forward lookup worked and returned true
			if result {
				t.Error("Validation failed, did not stop forward lookup")
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
