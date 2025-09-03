package common

import (
	"bytes"
)

// AreSlicesEqual compares two byte slices for equality
func AreSlicesEqual(a, b []byte) bool {
	return bytes.Equal(a, b)
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