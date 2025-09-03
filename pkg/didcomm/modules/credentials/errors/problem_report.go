package errors

import (
	"fmt"
)

// CredentialProblemReportReason represents credential problem report reasons
type CredentialProblemReportReason string

const (
	IssuanceAbandoned       CredentialProblemReportReason = "issuance-abandoned"
	InvalidCredentialOffer  CredentialProblemReportReason = "invalid-credential-offer"
	InvalidCredentialRequest CredentialProblemReportReason = "invalid-credential-request"
	InvalidCredential       CredentialProblemReportReason = "invalid-credential"
	InvalidAttribute        CredentialProblemReportReason = "invalid-attribute"
	MissingAttribute        CredentialProblemReportReason = "missing-attribute"
	ValueMismatch          CredentialProblemReportReason = "value-mismatch"
)

// ProblemReportError represents a problem that should be reported to the other party
type ProblemReportError struct {
	Message     string
	ProblemCode CredentialProblemReportReason
	Details     map[string]interface{}
}

// Error implements the error interface
func (e *ProblemReportError) Error() string {
	return fmt.Sprintf("Problem Report [%s]: %s", e.ProblemCode, e.Message)
}

// NewProblemReportError creates a new problem report error
func NewProblemReportError(message string, problemCode CredentialProblemReportReason) *ProblemReportError {
	return &ProblemReportError{
		Message:     message,
		ProblemCode: problemCode,
		Details:     make(map[string]interface{}),
	}
}

// WithDetail adds a detail to the problem report
func (e *ProblemReportError) WithDetail(key string, value interface{}) *ProblemReportError {
	e.Details[key] = value
	return e
}