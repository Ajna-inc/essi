package utils

import (
	"errors"
	"math/big"
)

// Base58 alphabet used for Bitcoin-style base58 encoding
const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

var (
	// base58Map provides quick lookup for decoding
	base58Map [256]byte
	// bigRadix represents the base (58)
	bigRadix = big.NewInt(58)
	// bigZero represents zero
	bigZero = big.NewInt(0)
)

func init() {
	for i := 0; i < len(base58Map); i++ {
		base58Map[i] = 255
	}
	for i, char := range base58Alphabet {
		base58Map[char] = byte(i)
	}
}

// EncodeBase58 - DEPRECATED: Use pkg/core/encoding.EncodeBase58 instead
func EncodeBase58(input []byte) string {
	panic("EncodeBase58 has been moved to pkg/core/encoding - update your imports")
}

// DecodeBase58 - DEPRECATED: Use pkg/core/encoding.DecodeBase58 instead
func DecodeBase58(input string) ([]byte, error) {
	panic("DecodeBase58 has been moved to pkg/core/encoding - update your imports")
}

// IsValidBase58 checks if a string contains only valid base58 characters
func IsValidBase58(input string) bool {
	if len(input) == 0 {
		return true
	}

	for _, char := range input {
		if int(char) >= len(base58Map) || base58Map[char] == 255 {
			return false
		}
	}

	return true
}

// Base58Check encoding/decoding (used in some contexts)

// EncodeBase58Check encodes data with base58check encoding
func EncodeBase58Check(input []byte) string {
	// Calculate checksum
	hash1 := CalculateSHA256HashBytes(input)
	hash2 := CalculateSHA256HashBytes(hash1)
	checksum := hash2[:4]

	// Append checksum to input
	payload := append(input, checksum...)

	return EncodeBase58(payload)
}

// DecodeBase58Check decodes a base58check encoded string
func DecodeBase58Check(input string) ([]byte, error) {
	decoded, err := DecodeBase58(input)
	if err != nil {
		return nil, err
	}
	if len(decoded) < 4 {
		return nil, errors.New("invalid base58check string")
	}

	// Split payload and checksum
	payload := decoded[:len(decoded)-4]
	checksum := decoded[len(decoded)-4:]

	// Calculate expected checksum
	hash1 := CalculateSHA256HashBytes(payload)
	hash2 := CalculateSHA256HashBytes(hash1)
	expectedChecksum := hash2[:4]

	// Verify checksum
	for i := 0; i < 4; i++ {
		if checksum[i] != expectedChecksum[i] {
			return nil, errors.New("invalid base58check checksum")
		}
	}

	return payload, nil
}

// Multibase support for Base58

// EncodeMultibaseBase58BTC encodes with multibase base58btc prefix ('z')
func EncodeMultibaseBase58BTC(input []byte) string {
	return "z" + EncodeBase58(input)
}

// DecodeMultibaseBase58BTC decodes multibase base58btc encoded string
func DecodeMultibaseBase58BTC(input string) ([]byte, error) {
	if len(input) == 0 {
		return nil, errors.New("empty input")
	}

	if input[0] != 'z' {
		return nil, errors.New("not a base58btc multibase string (missing 'z' prefix)")
	}

	return DecodeBase58(input[1:])
}

// IsMultibaseBase58BTC checks if string is multibase base58btc encoded
func IsMultibaseBase58BTC(input string) bool {
	return len(input) > 0 && input[0] == 'z' && IsValidBase58(input[1:])
}

// Helper functions for common use cases

// EncodeBase58FromHex encodes a hex string to base58
func EncodeBase58FromHex(hexStr string) (string, error) {
	bytes, err := DecodeHexString(hexStr)
	if err != nil {
		return "", err
	}
	return EncodeBase58(bytes), nil
}

// DecodeBase58ToHex decodes base58 to hex string
func DecodeBase58ToHex(base58Str string) (string, error) {
	bytes, err := DecodeBase58(base58Str)
	if err != nil {
		return "", err
	}
	return EncodeHexString(bytes), nil
}

// ValidateBase58Length validates that a base58 string decodes to expected byte length
func ValidateBase58Length(input string, expectedLength int) error {
	decoded, err := DecodeBase58(input)
	if err != nil {
		return err
	}

	if len(decoded) != expectedLength {
		return errors.New("decoded length does not match expected length")
	}

	return nil
}
