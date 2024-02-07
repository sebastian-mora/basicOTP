package basicOTP

import (
	"encoding/base32"
	"fmt"
	"net/url"
	"time"
)

// TOTP represents a Time-based One-Time Password generator.
type TOTP struct {
	otp        OTP
	timePeriod int
}

// TOTPConfig holds configuration parameters for TOTP generation.
type TOTPConfig struct {
	TimeInterval int
	CodeLength   int
	HashType     HashType
	Secret       []byte
}

// NewTOTP creates a new instance of TOTP based on the provided configuration.
func NewTOTP(config TOTPConfig) *TOTP {

	if len(config.Secret) <= 0 {
		panic("a secret must be provided for TOTP")
	}

	if config.TimeInterval == 0 {
		// Set default time to 30 seconds, recommended in rfc6238
		config.TimeInterval = 30
	}

	if config.CodeLength == 0 {
		config.CodeLength = 6
	}

	return &TOTP{
		otp:        NewOTP(config.Secret, config.HashType, config.CodeLength),
		timePeriod: config.TimeInterval,
	}
}

// Generate generates a TOTP for the current time interval.
func (t *TOTP) Generate() string {
	currentTime := time.Now()
	timecode := t.timecode(currentTime.Unix())
	return t.otp.Generate(int(timecode))
}

// Generate generates a TOTP for the given Unix timestamp.
func (t *TOTP) GenerateAt(unixTimeStamp int64) string {
	timeCode := int(t.timecode(unixTimeStamp))
	return t.otp.Generate(timeCode)
}

// Validate validates a TOTP against the current time interval.
func (t *TOTP) Validate(code string) bool {
	return t.Generate() == code
}

// ValidateAt validates a TOTP against a given unix timestamp.
func (t *TOTP) ValidateAt(unixTimestamp int64, code string) bool {
	return t.GenerateAt(unixTimestamp) == code
}

// URI generates the URI for the TOTP according to the Google Authenticator Key URI Format.
// See: https://github.com/google/google-authenticator/wiki/Key-Uri-Format
func (t *TOTP) URI(label string, issuer string) string {
	// Encode secret in Base32 without padding
	encodedSecret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(t.otp.secret)

	// URL encode issuer and label
	encodedIssuer := url.PathEscape(issuer)
	encodedLabel := url.PathEscape(label)

	// Construct the URI
	return fmt.Sprintf("otpauth://totp/%s?secret=%s&issuer=%s&algorithm=%s&digits=%d",
		encodedLabel,
		encodedSecret,
		encodedIssuer,
		t.otp.hashType,
		t.otp.codeLength)
}

// timecode calculates the timecode based on the provided Unix timestamp.
func (t *TOTP) timecode(unixTimeStamp int64) int {
	return int(unixTimeStamp) / t.timePeriod
}
