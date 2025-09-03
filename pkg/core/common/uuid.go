package common

import (
	"github.com/google/uuid"
)

// GenerateUUID generates a new UUID string
func GenerateUUID() string {
	return uuid.New().String()
}

// IsValidUUID checks if a string is a valid UUID format
func IsValidUUID(s string) bool {
	_, err := uuid.Parse(s)
	return err == nil
}