# BasicOTP

BasicOTP is a Go library for generating and validating one-time passwords (OTP). It provides implementations for both Time-based One-Time Passwords (TOTP) and Sequence-based One-Time Passwords (HTOP).

## Overview

The BasicOTP library aims to simplify the generation and validation of one-time passwords in Go applications. It consists of three main components:

1. **HTOP**: Represents a Sequence-based One-Time Password generator.
2. **TOTP**: Represents a Time-based One-Time Password generator.
3. **OTP**: Provides the underlying functionality for generating and validating one-time passwords.

## Features

- **Support for TOTP and HTOP**: BasicOTP supports both Time-based (TOTP) and Sequence-based (HTOP) OTP generation and validation.
- **Configurable Hash Algorithms**: Users can choose from different hash algorithms including SHA1, SHA256, and SHA512 according to their security requirements.
- **Customizable Code Length**: BasicOTP allows customization of the length of generated OTP codes to meet specific application needs.
- **URI Generation**: BasicOTP provides a convenient method for generating URIs according to the Google Authenticator Key URI Format, facilitating integration with OTP token apps.

## Use Cases

BasicOTP is suitable for a variety of use cases including:

- **Two-Factor Authentication (2FA)**: Implementing OTP-based 2FA for user authentication in web or mobile applications.
- **Secure Transaction Authorization**: Generating OTPs for authorizing sensitive transactions or operations in financial or enterprise systems.
- **Passwordless Authentication**: Using OTPs as an alternative to traditional password-based authentication for improved security and user experience.

## Tech Stack

BasicOTP is built using Go and leverages standard cryptographic libraries for hash functions and HMAC calculation. It is compatible with modern Go development environments and integrates seamlessly into existing projects using Go modules.

## Installation

To use BasicOTP in your Go project, you can import it using Go modules:

```bash
go get github.com/sebatian-mora/basicOTP
```

## Example

```go

package main

import (
    "fmt"
    "github.com/sebatian-mora/basicOTP"
)

func main() {
    // Create a new TOTP instance
    totp := basicOTP.NewTOTP(basicOTP.TOTPConfig{
        TimeInterval: 30, // Time interval in seconds (default is 30 seconds)
        CodeLength: 6, // Length of generated OTP code (default is 6)
        HashType: basicOTP.SHA1, // Hash algorithm (SHA1, SHA256, or SHA512)
        Secret: []byte("mysecret"),
    })

    // Generate a TOTP code
    code := totp.Generate()

    fmt.Println("Generated TOTP:", code)

    // Validate a TOTP code
    isValid := totp.Validate(code)

    fmt.Println("Is valid TOTP:", isValid)

    // Generate URI for TOTP
    uri := totp.URI("MyLabel", "MyIssuer")

    fmt.Println("TOTP URI:", uri)

}

```
