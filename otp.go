// Package basicOTP implements One-Time Password (OTP) generation according to RFC 4226 and RFC 6238.
// It provides functionality to generate OTP codes using HMAC-based algorithms like SHA-1, SHA-256, and SHA-512.
// This package is useful for implementing two-factor authentication (2FA) systems.
package basicOTP

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"
	"math"
)

// HashType represents the type of hash algorithm supported.
type HashType string

const (
	SHA1   HashType = "SHA1"
	SHA256 HashType = "SHA256"
	SHA512 HashType = "SHA512"
)

// OTP represents a One-Time Password generator.
type OTP struct {
	hashFunc   func() hash.Hash // hashFunc is the hash function used for OTP generation.
	HashType   HashType         // HashType is the type of hash algorithm used.
	secret     []byte           // secret is the shared secret key used for OTP generation.
	CodeLength int              // CodeLength is the length of the generated OTP code.
}

// NewOTP creates a new instance of OTP based on the provided configuration.
// The function will substitute default values for parameters as per the specification:
//   - codeLength defaults to 6.
//   - hashFunc will default to SHA1.
//   - A secret is required but length is not enforced. RFC recommends a shared secret of at least 128 bits.
func NewOTP(secret []byte, hashType HashType, codeLength int) OTP {
	if len(secret) <= 0 {
		panic("OTP requires a secret to be set")
	}

	if codeLength == 0 {
		codeLength = 6 // default in RFC 4226
	}

	var hashFunc func() hash.Hash
	switch hashType {
	case SHA1:
		hashFunc = sha1.New
	case SHA256:
		hashFunc = sha256.New
	case SHA512:
		hashFunc = sha512.New
	default: // if hashType is unknown, default to SHA1
		hashFunc = sha1.New
		hashType = SHA1
	}

	return OTP{
		secret:     secret,
		hashFunc:   hashFunc,
		HashType:   hashType,
		CodeLength: codeLength,
	}
}

// Generate generates an OTP code based on the provided input.
func (o OTP) Generate(input int) string {
	hmac := hmac.New(o.hashFunc, []byte(o.secret))
	buf := itob(input)

	hmac.Write(buf)
	hmacData := hmac.Sum(nil)
	code := truncate(hmacData, o.CodeLength)

	formatString := fmt.Sprintf("%%0%dd", o.CodeLength)
	return fmt.Sprintf(formatString, code)
}

// truncate truncates the HMAC result to the desired length.
// The dynamic truncation (DT) algorithm is found in RFC 4226.
func truncate(input []byte, codeLength int) int {
	offset := int(input[len(input)-1] & 0xf)
	code := ((int(input[offset]) & 0x7f) << 24) |
		((int(input[offset+1] & 0xff)) << 16) |
		((int(input[offset+2] & 0xff)) << 8) |
		(int(input[offset+3]) & 0xff)

	code = code % int(math.Pow10(codeLength))

	return code
}

// itob converts an integer to a big-endian byte array.
func itob(integer int) []byte {
	byteArr := make([]byte, 8)
	binary.BigEndian.PutUint64(byteArr, uint64(integer))
	return byteArr
}
