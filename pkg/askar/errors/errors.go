package errors

import (
	"fmt"

	askarerrors "github.com/Ajna-inc/askar-go/errors"
)

// AskarError represents an error from the Askar module
type AskarError struct {
	Code    string
	Message string
	Cause   error
}

// Error implements the error interface
func (e *AskarError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s (cause: %v)", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap returns the underlying error
func (e *AskarError) Unwrap() error {
	return e.Cause
}

// NewAskarError creates a new AskarError
func NewAskarError(code, message string, cause error) *AskarError {
	return &AskarError{
		Code:    code,
		Message: message,
		Cause:   cause,
	}
}

// Error codes
const (
	ErrCodeStoreNotFound      = "ASKAR_STORE_NOT_FOUND"
	ErrCodeStoreAlreadyExists = "ASKAR_STORE_ALREADY_EXISTS"
	ErrCodeStoreNotOpen       = "ASKAR_STORE_NOT_OPEN"
	ErrCodeInvalidConfig      = "ASKAR_INVALID_CONFIG"
	ErrCodeKeyNotFound        = "ASKAR_KEY_NOT_FOUND"
	ErrCodeKeyAlreadyExists   = "ASKAR_KEY_ALREADY_EXISTS"
	ErrCodeCryptoOperation    = "ASKAR_CRYPTO_OPERATION"
	ErrCodeStorageOperation   = "ASKAR_STORAGE_OPERATION"
	ErrCodeSessionOperation   = "ASKAR_SESSION_OPERATION"
	ErrCodeTransactionFailed  = "ASKAR_TRANSACTION_FAILED"
)

// WrapAskarError wraps an askar-go error into our error type
func WrapAskarError(err error) error {
	if err == nil {
		return nil
	}
	
	// Check if it's already our error type
	if askarErr, ok := err.(*AskarError); ok {
		return askarErr
	}
	
	// Check if it's an askar-go error
	if askarErr, ok := err.(*askarerrors.AskarError); ok {
		code := mapAskarErrorCode(askarErr.Code)
		return NewAskarError(code, askarErr.Message, askarErr)
	}
	
	// Generic error
	return NewAskarError(ErrCodeStorageOperation, err.Error(), err)
}

// mapAskarErrorCode maps askar-go error codes to our error codes
func mapAskarErrorCode(code askarerrors.ErrorCode) string {
	switch code {
	case askarerrors.ErrorCodeNotFound:
		return ErrCodeKeyNotFound
	case askarerrors.ErrorCodeDuplicate:
		return ErrCodeKeyAlreadyExists
	case askarerrors.ErrorCodeEncryption:
		return ErrCodeCryptoOperation
	case askarerrors.ErrorCodeInput:
		return ErrCodeInvalidConfig
	default:
		return ErrCodeStorageOperation
	}
}

// Common errors
var (
	ErrStoreNotFound      = NewAskarError(ErrCodeStoreNotFound, "store not found", nil)
	ErrStoreAlreadyExists = NewAskarError(ErrCodeStoreAlreadyExists, "store already exists", nil)
	ErrStoreNotOpen       = NewAskarError(ErrCodeStoreNotOpen, "store is not open", nil)
	ErrInvalidConfig      = NewAskarError(ErrCodeInvalidConfig, "invalid configuration", nil)
	ErrKeyNotFound        = NewAskarError(ErrCodeKeyNotFound, "key not found", nil)
	ErrKeyAlreadyExists   = NewAskarError(ErrCodeKeyAlreadyExists, "key already exists", nil)
)