package utils

import (
	"encoding/hex"
	"errors"
	"strings"
)

// EncodeHexString encodes a byte slice to a hex string
func EncodeHexString(data []byte) string {
	return hex.EncodeToString(data)
}

// EncodeHexStringWithPrefix encodes a byte slice to a hex string with 0x prefix
func EncodeHexStringWithPrefix(data []byte) string {
	return "0x" + hex.EncodeToString(data)
}

// DecodeHexString decodes a hex string to a byte slice
func DecodeHexString(hexStr string) ([]byte, error) {
	// Remove 0x prefix if present
	if strings.HasPrefix(hexStr, "0x") || strings.HasPrefix(hexStr, "0X") {
		hexStr = hexStr[2:]
	}

	// Ensure even length
	if len(hexStr)%2 != 0 {
		hexStr = "0" + hexStr
	}

	return hex.DecodeString(hexStr)
}

// IsValidHexString checks if a string is a valid hex string
func IsValidHexString(hexStr string) bool {
	// Remove 0x prefix if present
	if strings.HasPrefix(hexStr, "0x") || strings.HasPrefix(hexStr, "0X") {
		hexStr = hexStr[2:]
	}

	// Check if all characters are valid hex
	for _, char := range hexStr {
		if !((char >= '0' && char <= '9') ||
			(char >= 'a' && char <= 'f') ||
			(char >= 'A' && char <= 'F')) {
			return false
		}
	}

	return true
}

// NormalizeHexString normalizes a hex string to lowercase without prefix
func NormalizeHexString(hexStr string) string {
	// Remove 0x prefix if present
	if strings.HasPrefix(hexStr, "0x") || strings.HasPrefix(hexStr, "0X") {
		hexStr = hexStr[2:]
	}

	return strings.ToLower(hexStr)
}

// HexStringToBytes converts hex string to bytes with validation
func HexStringToBytes(hexStr string) ([]byte, error) {
	if !IsValidHexString(hexStr) {
		return nil, errors.New("invalid hex string")
	}

	return DecodeHexString(hexStr)
}

// BytesToHexString converts bytes to hex string
func BytesToHexString(data []byte) string {
	return EncodeHexString(data)
}

// CompareHexStrings compares two hex strings for equality (case-insensitive)
func CompareHexStrings(hex1, hex2 string) bool {
	return NormalizeHexString(hex1) == NormalizeHexString(hex2)
}

// PadHexString pads a hex string to a specific length
func PadHexString(hexStr string, length int) string {
	normalized := NormalizeHexString(hexStr)
	if len(normalized) >= length {
		return normalized
	}

	padding := strings.Repeat("0", length-len(normalized))
	return padding + normalized
}

// TrimHexPrefix removes 0x prefix from hex string
func TrimHexPrefix(hexStr string) string {
	if strings.HasPrefix(hexStr, "0x") || strings.HasPrefix(hexStr, "0X") {
		return hexStr[2:]
	}
	return hexStr
}

// AddHexPrefix adds 0x prefix to hex string if not present
func AddHexPrefix(hexStr string) string {
	if strings.HasPrefix(hexStr, "0x") || strings.HasPrefix(hexStr, "0X") {
		return hexStr
	}
	return "0x" + hexStr
}
