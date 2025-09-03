package utils

import (
	"regexp"
	"strings"

	"github.com/google/uuid"
)

// UUID generates a new UUID v4 string
func UUID() string {
	return uuid.New().String()
}

// IsValidUUID validates if a string is a valid UUID
func IsValidUUID(id string) bool {
	_, err := uuid.Parse(id)
	return err == nil
}

// IsValidUUIDv4 validates if a string is a valid UUID v4
func IsValidUUIDv4(id string) bool {
	// UUID v4 regex pattern
	uuidv4Regex := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	return uuidv4Regex.MatchString(strings.ToLower(id))
}

// NewUUID generates a new UUID v4
func NewUUID() uuid.UUID {
	return uuid.New()
}

// MustParseUUID parses a UUID string and panics if invalid
func MustParseUUID(s string) uuid.UUID {
	return uuid.MustParse(s)
}

// ParseUUID parses a UUID string
func ParseUUID(s string) (uuid.UUID, error) {
	return uuid.Parse(s)
}
