package basicOTP

import (
	"encoding/base32"
	"fmt"
	"net/url"
	"time"
)

// TOTP represents a Time-based One-Time Password generator.
type TOTP struct {
	otp        OTP // otp is the underlying OTP generator.
	TimePeriod int // TimePeriod is the time period in seconds used for TOTP generation.
}

// TOTPConfig holds configuration parameters for TOTP generation.
type TOTPConfig struct {
	TimeInterval int      // TimeInterval is the time interval in seconds for TOTP generation.
	CodeLength   int      // CodeLength is the length of the generated TOTP code.
	HashType     HashType // HashType is the hash algorithm used for TOTP generation.
	Secret       []byte   // Secret is the shared secret key used for TOTP generation.
}

// NewTOTP creates a new instance of TOTP based on the provided configuration.
func NewTOTP(config TOTPConfig) *TOTP {
	if config.TimeInterval == 0 {
		// Set the default time interval to 30 seconds, recommended in RFC 6238.
		config.TimeInterval = 30
	}

	return &TOTP{
		otp:        NewOTP(config.Secret, config.HashType, config.CodeLength),
		TimePeriod: config.TimeInterval,
	}
}

// Generate generates a TOTP for the current time interval.
func (t *TOTP) Generate() string {
	currentTime := time.Now()
	timecode := t.timecode(currentTime.Unix())
	return t.otp.Generate(int(timecode))
}

// GenerateAt generates a TOTP for the given Unix timestamp.
func (t *TOTP) GenerateAt(unixTimeStamp int64) string {
	timeCode := int(t.timecode(unixTimeStamp))
	return t.otp.Generate(timeCode)
}

// Validate validates a TOTP against the current time interval.
func (t *TOTP) Validate(code string) bool {
	return t.Generate() == code
}

// ValidateAt validates a TOTP against a given Unix timestamp.
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
		t.otp.HashType,
		t.otp.CodeLength)
}

// timecode calculates the timecode based on the provided Unix timestamp and the TimePeriod.
func (t *TOTP) timecode(unixTimeStamp int64) int {
	return int(unixTimeStamp) / t.TimePeriod
}
