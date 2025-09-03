package utils

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// ValidationResult represents the result of a validation
type ValidationResult struct {
	Valid   bool     `json:"valid"`
	Errors  []string `json:"errors,omitempty"`
	Message string   `json:"message,omitempty"`
}

// NewValidationResult creates a new validation result
func NewValidationResult(valid bool, message string) ValidationResult {
	return ValidationResult{
		Valid:   valid,
		Message: message,
		Errors:  []string{},
	}
}

// AddError adds an error to the validation result
func (vr *ValidationResult) AddError(error string) {
	vr.Valid = false
	vr.Errors = append(vr.Errors, error)
}

// HasErrors checks if the validation result has errors
func (vr ValidationResult) HasErrors() bool {
	return len(vr.Errors) > 0
}

// GetErrorString returns all errors as a single string
func (vr ValidationResult) GetErrorString() string {
	return strings.Join(vr.Errors, "; ")
}

// Common validation patterns
var (
	EmailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	// Allow http, https, ws, wss schemes for DIDComm endpoints
	URLRegex       = regexp.MustCompile(`^(https?|wss?)://[^\s/$.?#].[^\s]*$`)
	UUIDRegex      = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	UUIDv4Regex    = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)
	Base64Regex    = regexp.MustCompile(`^[A-Za-z0-9+/]*={0,2}$`)
	Base64URLRegex = regexp.MustCompile(`^[A-Za-z0-9_-]*$`)
	HexRegex       = regexp.MustCompile(`^[0-9a-fA-F]+$`)
	AlphaRegex     = regexp.MustCompile(`^[a-zA-Z]+$`)
	AlphaNumRegex  = regexp.MustCompile(`^[a-zA-Z0-9]+$`)
	NumericRegex   = regexp.MustCompile(`^[0-9]+$`)
	JSONRegex      = regexp.MustCompile(`^[\s]*[{\[].*[}\]][\s]*$`)
)

// String validation functions

// IsStringEmpty checks if a string is empty or only whitespace
func IsStringEmpty(s string) bool {
	return strings.TrimSpace(s) == ""
}

// IsNotEmpty checks if a string is not empty
func IsNotEmpty(s string) bool {
	return !IsStringEmpty(s)
}

// HasMinLength checks if string has minimum length
func HasMinLength(s string, minLength int) bool {
	return len(s) >= minLength
}

// HasMaxLength checks if string has maximum length
func HasMaxLength(s string, maxLength int) bool {
	return len(s) <= maxLength
}

// HasLengthBetween checks if string length is between min and max
func HasLengthBetween(s string, minLength, maxLength int) bool {
	length := len(s)
	return length >= minLength && length <= maxLength
}

// IsAlpha checks if string contains only alphabetic characters
func IsAlpha(s string) bool {
	return AlphaRegex.MatchString(s)
}

// IsAlphaNumeric checks if string contains only alphanumeric characters
func IsAlphaNumeric(s string) bool {
	return AlphaNumRegex.MatchString(s)
}

// IsNumeric checks if string contains only numeric characters
func IsNumeric(s string) bool {
	return NumericRegex.MatchString(s)
}

// IsHex checks if string is valid hexadecimal
func IsHex(s string) bool {
	return HexRegex.MatchString(s)
}

// Format validation functions

// IsValidEmail checks if string is a valid email address
func IsValidEmail(email string) bool {
	if len(email) > 254 {
		return false
	}
	return EmailRegex.MatchString(email)
}

// IsValidURL checks if string is a valid URL
func IsValidURL(urlStr string) bool {
	if _, err := url.ParseRequestURI(urlStr); err != nil {
		return false
	}
	return URLRegex.MatchString(urlStr)
}

// IsValidHTTPURL checks if string is a valid HTTP/HTTPS URL
func IsValidHTTPURL(urlStr string) bool {
	if !IsValidURL(urlStr) {
		return false
	}
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return false
	}
	return parsedURL.Scheme == "http" || parsedURL.Scheme == "https"
}

// IsValidBase64 checks if string is valid base64
func IsValidBase64(s string) bool {
	// Check length (must be multiple of 4)
	if len(s)%4 != 0 {
		return false
	}
	return Base64Regex.MatchString(s)
}

// IsValidBase64URL checks if string is valid base64url
func IsValidBase64URL(s string) bool {
	return Base64URLRegex.MatchString(s)
}

// IsValidJSON checks if string is valid JSON
func IsValidJSONString(s string) bool {
	var js interface{}
	return json.Unmarshal([]byte(s), &js) == nil
}

// IsValidDIDFormat checks if string matches basic DID format
func IsValidDIDFormat(did string) bool {
	// Basic DID format: did:method:method-specific-id
	parts := strings.Split(did, ":")
	if len(parts) < 3 {
		return false
	}
	if parts[0] != "did" {
		return false
	}
	// Method must be lowercase and contain only letters, numbers, and hyphens
	method := parts[1]
	if method == "" {
		return false
	}
	for _, r := range method {
		if !unicode.IsLower(r) && !unicode.IsDigit(r) && r != '-' {
			return false
		}
	}
	// Method-specific-id must not be empty
	return parts[2] != ""
}

// Numeric validation functions

// IsValidInt checks if string is a valid integer
func IsValidInt(s string) bool {
	_, err := strconv.Atoi(s)
	return err == nil
}

// IsValidFloat checks if string is a valid float
func IsValidFloat(s string) bool {
	_, err := strconv.ParseFloat(s, 64)
	return err == nil
}

// IsInRange checks if integer is within range
func IsInRange(value, min, max int) bool {
	return value >= min && value <= max
}

// IsPositive checks if integer is positive
func IsPositive(value int) bool {
	return value > 0
}

// IsNonNegative checks if integer is non-negative
func IsNonNegative(value int) bool {
	return value >= 0
}

// Network validation functions

// IsValidIP checks if string is a valid IP address
func IsValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

// IsValidIPv4 checks if string is a valid IPv4 address
func IsValidIPv4(ip string) bool {
	parsedIP := net.ParseIP(ip)
	return parsedIP != nil && parsedIP.To4() != nil
}

// IsValidIPv6 checks if string is a valid IPv6 address
func IsValidIPv6(ip string) bool {
	parsedIP := net.ParseIP(ip)
	return parsedIP != nil && parsedIP.To4() == nil
}

// IsValidPort checks if integer is a valid port number
func IsValidPort(port int) bool {
	return port >= 1 && port <= 65535
}

// IsValidPortString checks if string is a valid port number
func IsValidPortString(port string) bool {
	if !IsValidInt(port) {
		return false
	}
	portNum, _ := strconv.Atoi(port)
	return IsValidPort(portNum)
}

// Collection validation functions

// IsInSlice checks if value exists in slice
func IsInSlice[T comparable](value T, slice []T) bool {
	for _, v := range slice {
		if v == value {
			return true
		}
	}
	return false
}

// IsValidChoice checks if value is one of the allowed choices
func IsValidChoice[T comparable](value T, choices []T) bool {
	return IsInSlice(value, choices)
}

// AreAllUnique checks if all values in slice are unique
func AreAllUnique[T comparable](slice []T) bool {
	seen := make(map[T]bool)
	for _, v := range slice {
		if seen[v] {
			return false
		}
		seen[v] = true
	}
	return true
}

// IsValidSliceLength checks if slice has valid length
func IsValidSliceLength[T any](slice []T, minLength, maxLength int) bool {
	length := len(slice)
	return length >= minLength && length <= maxLength
}

// Complex validation functions

// ValidateRequired validates that required fields are not empty
func ValidateRequired(fields map[string]string) ValidationResult {
	result := NewValidationResult(true, "All required fields are present")

	for fieldName, fieldValue := range fields {
		if IsStringEmpty(fieldValue) {
			result.AddError(fmt.Sprintf("Field '%s' is required", fieldName))
		}
	}

	return result
}

// ValidateStringField validates a single string field with multiple criteria
func ValidateStringField(fieldName, value string, minLength, maxLength int, pattern *regexp.Regexp) ValidationResult {
	result := NewValidationResult(true, fmt.Sprintf("Field '%s' is valid", fieldName))

	if IsStringEmpty(value) {
		result.AddError(fmt.Sprintf("Field '%s' cannot be empty", fieldName))
		return result
	}

	if !HasMinLength(value, minLength) {
		result.AddError(fmt.Sprintf("Field '%s' must be at least %d characters long", fieldName, minLength))
	}

	if !HasMaxLength(value, maxLength) {
		result.AddError(fmt.Sprintf("Field '%s' must be at most %d characters long", fieldName, maxLength))
	}

	if pattern != nil && !pattern.MatchString(value) {
		result.AddError(fmt.Sprintf("Field '%s' does not match required pattern", fieldName))
	}

	return result
}

// ValidateEmail validates an email address with detailed error messages
func ValidateEmail(email string) ValidationResult {
	result := NewValidationResult(true, "Email is valid")

	if IsStringEmpty(email) {
		result.AddError("Email cannot be empty")
		return result
	}

	if len(email) > 254 {
		result.AddError("Email is too long (maximum 254 characters)")
	}

	if !IsValidEmail(email) {
		result.AddError("Email format is invalid")
	}

	return result
}

// ValidateURL validates a URL with detailed error messages
func ValidateURL(urlStr string) ValidationResult {
	result := NewValidationResult(true, "URL is valid")

	if IsStringEmpty(urlStr) {
		result.AddError("URL cannot be empty")
		return result
	}

	if !IsValidURL(urlStr) {
		result.AddError("URL format is invalid")
	}

	return result
}

// ValidateDID validates a DID with detailed error messages
func ValidateDID(did string) ValidationResult {
	result := NewValidationResult(true, "DID is valid")

	if IsStringEmpty(did) {
		result.AddError("DID cannot be empty")
		return result
	}

	if !IsValidDIDFormat(did) {
		result.AddError("DID format is invalid (must be 'did:method:method-specific-id')")
	}

	return result
}

// ValidateJSONWebKey validates basic JWK structure
func ValidateJSONWebKey(jwkMap map[string]interface{}) ValidationResult {
	result := NewValidationResult(true, "JWK is valid")

	// Check required fields
	requiredFields := []string{"kty"} // Key Type is always required
	for _, field := range requiredFields {
		if _, exists := jwkMap[field]; !exists {
			result.AddError(fmt.Sprintf("JWK missing required field: %s", field))
		}
	}

	// Validate key type
	if kty, exists := jwkMap["kty"]; exists {
		if ktyStr, ok := kty.(string); ok {
			validKeyTypes := []string{"RSA", "EC", "oct", "OKP"}
			if !IsValidChoice(ktyStr, validKeyTypes) {
				result.AddError(fmt.Sprintf("Invalid key type: %s", ktyStr))
			}
		} else {
			result.AddError("Key type (kty) must be a string")
		}
	}

	return result
}

// ValidateCredentialSubject validates W3C VC credential subject
func ValidateCredentialSubject(subject map[string]interface{}) ValidationResult {
	result := NewValidationResult(true, "Credential subject is valid")

	// Basic validation - at minimum should not be empty
	if len(subject) == 0 {
		result.AddError("Credential subject cannot be empty")
	}

	// If ID is present, it should be a valid URI
	if id, exists := subject["id"]; exists {
		if idStr, ok := id.(string); ok {
			if !IsValidURL(idStr) && !IsValidDIDFormat(idStr) {
				result.AddError("Credential subject ID must be a valid URI or DID")
			}
		} else {
			result.AddError("Credential subject ID must be a string")
		}
	}

	return result
}

// Batch validation functions

// ValidateBatch validates multiple items with the same validation function
func ValidateBatch[T any](items []T, validator func(T) ValidationResult) []ValidationResult {
	results := make([]ValidationResult, len(items))
	for i, item := range items {
		results[i] = validator(item)
	}
	return results
}

// HasValidationErrors checks if any validation results have errors
func HasValidationErrors(results []ValidationResult) bool {
	for _, result := range results {
		if result.HasErrors() {
			return true
		}
	}
	return false
}

// GetAllValidationErrors combines all validation errors into a single slice
func GetAllValidationErrors(results []ValidationResult) []string {
	var errors []string
	for _, result := range results {
		if !result.Valid {
			errors = append(errors, result.Errors...)
		}
	}
	return errors
}

// IsValidDid validates a DID string format (alias for IsValidDIDFormat)
func IsValidDid(did string) bool {
	return IsValidDIDFormat(did)
}

// SplitString splits a string by delimiter and returns array
func SplitString(s, delimiter string) []string {
	if s == "" {
		return []string{}
	}
	return strings.Split(s, delimiter)
}
