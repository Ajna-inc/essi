package encoding

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
	// Initialize the base58 character mapping
	for i := 0; i < len(base58Map); i++ {
		base58Map[i] = 255
	}
	for i, char := range base58Alphabet {
		base58Map[char] = byte(i)
	}
}

// EncodeBase58 encodes a byte slice to base58 string
func EncodeBase58(input []byte) string {
	if len(input) == 0 {
		return ""
	}

	// Convert to big integer
	x := big.NewInt(0).SetBytes(input)

	// Encode to base58
	var result []byte
	for x.Cmp(bigZero) > 0 {
		mod := &big.Int{}
		x.DivMod(x, bigRadix, mod)
		result = append(result, base58Alphabet[mod.Int64()])
	}

	// Add leading zeros
	for _, b := range input {
		if b == 0 {
			result = append(result, base58Alphabet[0])
		} else {
			break
		}
	}

	// Reverse the result
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}

	return string(result)
}

// DecodeBase58 decodes a base58 string to a byte slice
func DecodeBase58(input string) ([]byte, error) {
	if len(input) == 0 {
		return nil, nil
	}

	// Count leading zeros
	var leadingZeros int
	for _, char := range input {
		if char == rune(base58Alphabet[0]) {
			leadingZeros++
		} else {
			break
		}
	}

	// Convert string to big integer
	x := big.NewInt(0)
	for i, char := range input {
		if int(char) >= len(base58Map) || base58Map[char] == 255 {
			return nil, errors.New("invalid base58 character")
		}

		x.Mul(x, bigRadix)
		x.Add(x, big.NewInt(int64(base58Map[char])))

		// Check for overflow (basic protection)
		if i > 100 { // Reasonable limit for DID keys
			return nil, errors.New("base58 string too long")
		}
	}

	// Convert to bytes
	result := x.Bytes()

	// Add leading zeros
	if leadingZeros > 0 {
		padding := make([]byte, leadingZeros)
		result = append(padding, result...)
	}

	return result, nil
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