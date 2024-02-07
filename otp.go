package basicOTP

// implements https://datatracker.ietf.org/doc/html/rfc6238

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

// HashType represents the type of hash algorithm.
type HashType string

const (
	SHA1   HashType = "SHA1"
	SHA256 HashType = "SHA256"
	SHA512 HashType = "SHA512"
)

type OTP struct {
	hashFunc   func() hash.Hash
	hashType   HashType
	secret     []byte
	codeLength int
}

// NewOTP creates a new instance of OTP based on the provided configuration.
func NewOTP(secret []byte, hashType HashType, codeLength int) OTP {
	var hashFunc func() hash.Hash

	switch hashType {
	case SHA1:
		hashFunc = sha1.New
	case SHA256:
		hashFunc = sha256.New
	case SHA512:
		hashFunc = sha512.New
	default:
		hashFunc = sha1.New
	}

	return OTP{
		secret:     secret,
		hashFunc:   hashFunc,
		hashType:   hashType,
		codeLength: codeLength,
	}
}

/*
This is the base implenation, the input here can be used for TOP (Time based) or HOPT (incremental)
*/
func (o OTP) Generate(input int) string {
	if input < 0 {
		panic("Input must be < 0")
	}

	hmac := hmac.New(o.hashFunc, []byte(o.secret))
	buf := Itob(input)

	hmac.Write(buf)
	hmacData := hmac.Sum(nil)
	code := truncate(hmacData, o.codeLength)

	formatString := fmt.Sprintf("%%0%dd", o.codeLength)
	return fmt.Sprintf(formatString, code)
}

func truncate(input []byte, codeLength int) int {
	offset := int(input[len(input)-1] & 0xf)
	code := ((int(input[offset]) & 0x7f) << 24) |
		((int(input[offset+1] & 0xff)) << 16) |
		((int(input[offset+2] & 0xff)) << 8) |
		(int(input[offset+3]) & 0xff)

	code = code % int(math.Pow10(codeLength))

	return code
}

func Itob(integer int) []byte {
	byteArr := make([]byte, 8)
	binary.BigEndian.PutUint64(byteArr, uint64(integer))
	return byteArr
}
