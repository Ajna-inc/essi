package utils

import (
	"bytes"
	"crypto/rand"
	"fmt"
)

// GenerateUUID - DEPRECATED: Use pkg/core/common.GenerateUUID instead
func GenerateUUID() string {
	panic("GenerateUUID has been moved to pkg/core/common - update your imports")
}

// CurrentTimestamp - DEPRECATED: Use pkg/core/common.CurrentTimestamp instead
func CurrentTimestamp() string {
	panic("CurrentTimestamp has been moved to pkg/core/common - update your imports")
}

// GenerateNonce generates a random nonce of specified length
func GenerateNonce(length int) ([]byte, error) {
	nonce := make([]byte, length)
	_, err := rand.Read(nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	return nonce, nil
}

// GenerateRandomBytes generates random bytes of specified length
func GenerateRandomBytes(length int) ([]byte, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return bytes, nil
}

// StringInSlice checks if a string exists in a slice
func StringInSlice(target string, slice []string) bool {
	for _, item := range slice {
		if item == target {
			return true
		}
	}
	return false
}

// RemoveStringFromSlice removes a string from a slice
func RemoveStringFromSlice(target string, slice []string) []string {
	result := make([]string, 0, len(slice))
	for _, item := range slice {
		if item != target {
			result = append(result, item)
		}
	}
	return result
}

// CopyMap creates a copy of a string map
func CopyMap(original map[string]string) map[string]string {
	copy := make(map[string]string)
	for k, v := range original {
		copy[k] = v
	}
	return copy
}

// TruncateString truncates a string to max length
func TruncateString(str string, maxLength int) string {
	if len(str) <= maxLength {
		return str
	}
	return str[:maxLength] + "..."
}

// AreSlicesEqual compares two byte slices for equality
func AreSlicesEqual(a, b []byte) bool {
	return bytes.Equal(a, b)
}
