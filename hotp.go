package basicOTP

import (
	"encoding/base32"
	"fmt"
	"net/url"
)

// hotp represents a Sequence-based One-Time Password generator.
type hotp struct {
	otp     OTP
	Counter int
}

// HOTPConfig holds configuration parameters for HOTP generation.
type HOTPConfig struct {
	CodeLength int      // CodeLength is the length of the generated OTP code.
	HashType   HashType // HashType is the hash algorithm used for OTP generation.
	Secret     []byte   // Secret is the shared secret key used for OTP generation.
	Counter    int      // Counter is the initial counter value for HOTP generation.
}

// NewHTOP creates a new instance of hopt based on the provided HOTPConfig.
func NewHTOP(config HOTPConfig) *hotp {
	return &hotp{
		otp:     NewOTP(config.Secret, config.HashType, config.CodeLength),
		Counter: config.Counter,
	}
}

// Generate generates a HOTP code.
func (h *hotp) Generate() string {
	code := h.otp.Generate(h.Counter)
	h.Counter = h.Counter + 1
	return code
}

// Validate validates an input OTP code against the current counter value.
func (h *hotp) Validate(input string) bool {
	if h.otp.Generate(h.Counter) == input {
		h.Counter = h.Counter + 1
		return true
	}
	return false
}

// URI generates the URI according to the Google Authenticator Key URI Format.
// See: https://github.com/google/google-authenticator/wiki/Key-Uri-Format
func (t *hotp) URI(label string, issuer string) string {
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
		t.otp.hashType,
		t.otp.codeLength,
		t.Counter)
}
