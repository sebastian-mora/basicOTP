package basicOTP

// HTOP represents a Sequence-based One-Time Password generator.
type htop struct {
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

func NewHTOP(config HOTPConfig) *htop {
	return &htop{
		otp:     NewOTP(config.Secret, config.HashType, config.CodeLength),
		Counter: config.Counter,
	}
}

func (h *htop) Generate() string {
	code := h.otp.Generate(h.Counter)
	h.Counter = h.Counter + 1
	return code
}

func (h *htop) Validate(input string) bool {
	if h.otp.Generate(h.Counter) == input {
		h.Counter = h.Counter + 1
		return true
	}
	return false
}
