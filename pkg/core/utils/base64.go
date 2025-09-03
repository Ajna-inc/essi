package utils

import (
    "encoding/base64"
    "encoding/json"
    "strings"
)

// Base64ToBase64URL converts a standard base64 string to base64url format
func Base64ToBase64URL(base64Str string) string {
	// Replace characters as per base64url spec
	base64url := strings.ReplaceAll(base64Str, "+", "-")
	base64url = strings.ReplaceAll(base64url, "/", "_")
	// Remove padding
	base64url = strings.TrimRight(base64url, "=")
	return base64url
}

// Base64URLToBase64 converts a base64url string to standard base64 format
func Base64URLToBase64(base64url string) string {
	// Restore characters
	base64Str := strings.ReplaceAll(base64url, "-", "+")
	base64Str = strings.ReplaceAll(base64Str, "_", "/")

	switch len(base64Str) % 4 {
	case 2:
		base64Str += "=="
	case 3:
		base64Str += "="
	}

	return base64Str
}

// EncodeBase64 encodes bytes to standard base64 string
func EncodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// DecodeBase64 decodes a standard base64 string to bytes
func DecodeBase64(encoded string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(encoded)
}

// EncodeBase64URL encodes bytes to base64url string
func EncodeBase64URL(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// DecodeBase64URL decodes a base64url string to bytes
func DecodeBase64URL(encoded string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(encoded)
}

// EncodeBase64URLPadded encodes bytes to base64url string with padding
func EncodeBase64URLPadded(data []byte) string {
	return base64.URLEncoding.EncodeToString(data)
}

// DecodeBase64URLPadded decodes a base64url string with padding to bytes
func DecodeBase64URLPadded(encoded string) ([]byte, error) {
	return base64.URLEncoding.DecodeString(encoded)
}

// EncodeBase64URLString encodes bytes to base64url string without padding
func EncodeBase64URLString(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// DecodeBase64URLString decodes base64url string to bytes
func DecodeBase64URLString(data string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(data)
}
// EncodeBase64URLStringFromMap encodes a map to base64url(JSON)
func EncodeBase64URLStringFromMap(m map[string]interface{}) string {
    if m == nil { return "" }
    b, err := json.Marshal(m)
    if err != nil { return "" }
    return base64.RawURLEncoding.EncodeToString(b)
}
