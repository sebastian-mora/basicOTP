package basicOTP

import (
	"encoding/base32"
	"fmt"
	"net/url"
)

// HTOP represents a Sequence-based One-Time Password generator.
type HTOP struct {
	otp                  OTP
	Counter              int
	synchronizationLimit int
}

// HOTPConfig holds configuration parameters for HOTP generation.
type HOTPConfig struct {
	CodeLength           int      // CodeLength is the length of the generated OTP code.
	HashType             HashType // HashType is the hash algorithm used for OTP generation.
	Secret               []byte   // Secret is the shared secret key used for OTP generation.
	Counter              int      // Counter is the initial counter value for HOTP generation.
	SynchronizationLimit int      // SynchronizationLimit sets the limit for synchronization in HOTP validation.

	// SynchronizationLimit specifies the maximum number of steps to look ahead during OTP validation.
	// If SynchronizationLimit is 0 or negative, no synchronization is performed, and the Counter value remains unchanged.
	// If SynchronizationLimit is greater than 0, Validate() will check HOTPs ahead of the current Counter value up to the specified limit.
	// If a valid OTP is found, Validate() returns true and advances the Counter value to synchronize with the client.
}

// NewHTOP creates a new instance of hopt based on the provided HOTPConfig.
func NewHTOP(config HOTPConfig) *HTOP {

	return &HTOP{
		otp:                  NewOTP(config.Secret, config.HashType, config.CodeLength),
		Counter:              config.Counter,
		synchronizationLimit: config.SynchronizationLimit,
	}
}

// Generate returns a string representing a HOTP code.
// generating a code increments the HOTP counter
func (h *HTOP) Generate() string {
	code := h.otp.Generate(h.Counter)
	h.Counter = h.Counter + 1
	return code
}

// Validate validates an input OTP code against the current counter value.
// the function will attempt to look ahead for codes using
// synchronizationLimit as the upper bound.
func (h *HTOP) Validate(input string) bool {

	// first check if input matches the current counter
	if h.otp.Generate(h.Counter) == input {
		h.Counter++
		return true
	}

	// If we did not match, look ahead and sync if needed.
	// i=1 as we have checked the first index already
	for i := 1; i < h.synchronizationLimit; i++ {
		if h.otp.Generate(h.Counter+i) == input {
			h.Counter += i // Fast-forward counter to sync
			return true
		}
	}

	return false
}

// URI generates the URI according to the Google Authenticator Key URI Format.
// See: https://github.com/google/google-authenticator/wiki/Key-Uri-Format
func (t *HTOP) URI(label string, issuer string) string {
	// Encode secret in Base32 without padding
	encodedSecret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(t.otp.secret)

	// URL encode issuer and label
	encodedIssuer := url.PathEscape(issuer)
	encodedLabel := url.PathEscape(label)

	// Construct the URI
	return fmt.Sprintf("otpauth://hotp/%s?secret=%s&issuer=%s&algorithm=%s&digits=%d&counter=%d",
		encodedLabel,
		encodedSecret,
		encodedIssuer,
		t.otp.HashType,
		t.otp.CodeLength,
		t.Counter)
}
