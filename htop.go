package basicOTP

import (
	"encoding/base32"
	"fmt"
	"net/url"
)

// HTOP represents a Sequence-based One-Time Password generator.
type hopt struct {
	otp     OTP
	Counter int
}

// HOTPConfig holds configuration parameters for HOTP generation.
type HOTPConfig struct {
	CodeLength int
	HashType   HashType
	Secret     []byte
	Counter    int
}

func NewHTOP(config HOTPConfig) *hopt {
	return &hopt{
		otp:     NewOTP(config.Secret, config.HashType, config.CodeLength),
		Counter: config.Counter,
	}
}

func (h *hopt) Generate() string {
	code := h.otp.Generate(h.Counter)
	h.Counter = h.Counter + 1
	return code
}

func (h *hopt) Validate(input string) bool {
	if h.otp.Generate(h.Counter) == input {
		h.Counter = h.Counter + 1
		return true
	}
	return false
}

// URI generates the URI for the TOTP according to the Google Authenticator Key URI Format.
// See: https://github.com/google/google-authenticator/wiki/Key-Uri-Format
func (t *hopt) URI(label string, issuer string) string {
	// Encode secret in Base32 without padding
	encodedSecret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(t.otp.secret)

	// URL encode issuer and label
	encodedIssuer := url.PathEscape(issuer)
	encodedLabel := url.PathEscape(label)

	// Construct the URI
	return fmt.Sprintf("otpauth://hopt/%s?secret=%s&issuer=%s&algorithm=%s&digits=%d",
		encodedLabel,
		encodedSecret,
		encodedIssuer,
		t.otp.hashType,
		t.otp.codeLength)
}
