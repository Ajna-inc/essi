package messages

import (
	"encoding/json"
	"time"

	"github.com/ajna-inc/essi/pkg/didcomm/messages"
)

const CredentialProblemReportV2Type = "https://didcomm.org/issue-credential/2.0/problem-report"

// CredentialProblemReportV2 represents a problem report for credential protocol v2
// @see https://github.com/hyperledger/aries-rfcs/blob/main/features/0035-report-problem/README.md
type CredentialProblemReportV2 struct {
	*messages.BaseMessage
	// Error code as per RFC 0035
	Code string `json:"code"`
	// Human-readable problem description
	Comment string `json:"comment,omitempty"`
	// Additional arguments for the problem
	Args []string `json:"args,omitempty"`
	// ISO 8601 timestamp of when the problem occurred
	ProblemTime *time.Time `json:"problem_time,omitempty"`
	// Message ID that triggered the problem
	ProblemItems []map[string]interface{} `json:"problem_items,omitempty"`
	// Fix hint
	FixHint string `json:"fix_hint,omitempty"`
	// Impact of the problem
	Impact string `json:"impact,omitempty"`
	// Where the problem occurred
	Where string `json:"where,omitempty"`
	// Noticed time
	NoticedTime *time.Time `json:"noticed_time,omitempty"`
	// Tracking URI for the problem
	TrackingURI string `json:"tracking_uri,omitempty"`
	// Escalation URI for the problem
	EscalationURI string `json:"escalation_uri,omitempty"`
}

// Common problem codes for credential exchange
const (
	// Protocol problems
	ProblemCodeProtocolError = "protocol-error"
	ProblemCodeInternalError = "internal-error"
	
	// Credential-specific problems
	ProblemCodeInvalidCredential = "invalid-credential"
	ProblemCodeInvalidAttribute  = "invalid-attribute"
	ProblemCodeValueMismatch     = "value-mismatch"
	ProblemCodeInvalidSchema     = "invalid-schema"
	ProblemCodeInvalidCredDef    = "invalid-credential-definition"
	
	// State problems
	ProblemCodeInvalidState = "invalid-state"
	ProblemCodeRejected     = "rejected"
	ProblemCodeAbandoned    = "abandoned"
	
	// Request problems
	ProblemCodeRequestNotAccepted = "request-not-accepted"
	ProblemCodeOfferNotAccepted   = "offer-not-accepted"
)

// NewCredentialProblemReportV2 creates a new problem report message
func NewCredentialProblemReportV2(code string, comment string) *CredentialProblemReportV2 {
	now := time.Now()
	return &CredentialProblemReportV2{
		BaseMessage:  messages.NewBaseMessage(CredentialProblemReportV2Type),
		Code:         code,
		Comment:      comment,
		ProblemTime:  &now,
		NoticedTime:  &now,
		Args:         []string{},
		ProblemItems: []map[string]interface{}{},
	}
}

// ToJSON serializes the message to JSON
func (m *CredentialProblemReportV2) ToJSON() ([]byte, error) {
	// Create a map to combine BaseMessage fields with problem report fields
	result := make(map[string]interface{})
	
	// First get BaseMessage fields
	baseJSON, err := m.BaseMessage.ToJSON()
	if err != nil {
		return nil, err
	}
	
	// Unmarshal BaseMessage to map
	if err := json.Unmarshal(baseJSON, &result); err != nil {
		return nil, err
	}
	
	// Add problem report specific fields
	result["code"] = m.Code
	if m.Comment != "" {
		result["comment"] = m.Comment
	}
	if len(m.Args) > 0 {
		result["args"] = m.Args
	}
	if m.ProblemTime != nil {
		result["problem_time"] = m.ProblemTime.Format(time.RFC3339)
	}
	if len(m.ProblemItems) > 0 {
		result["problem_items"] = m.ProblemItems
	}
	if m.FixHint != "" {
		result["fix_hint"] = m.FixHint
	}
	if m.Impact != "" {
		result["impact"] = m.Impact
	}
	if m.Where != "" {
		result["where"] = m.Where
	}
	if m.NoticedTime != nil {
		result["noticed_time"] = m.NoticedTime.Format(time.RFC3339)
	}
	if m.TrackingURI != "" {
		result["tracking_uri"] = m.TrackingURI
	}
	if m.EscalationURI != "" {
		result["escalation_uri"] = m.EscalationURI
	}
	
	// Marshal the complete map
	return json.Marshal(result)
}

// FromJSON deserializes the message from JSON
func (m *CredentialProblemReportV2) FromJSON(b []byte) error {
	// Custom unmarshal to handle time fields
	var temp struct {
		*messages.BaseMessage
		Code          string                   `json:"code"`
		Comment       string                   `json:"comment,omitempty"`
		Args          []string                 `json:"args,omitempty"`
		ProblemTime   string                   `json:"problem_time,omitempty"`
		ProblemItems  []map[string]interface{} `json:"problem_items,omitempty"`
		FixHint       string                   `json:"fix_hint,omitempty"`
		Impact        string                   `json:"impact,omitempty"`
		Where         string                   `json:"where,omitempty"`
		NoticedTime   string                   `json:"noticed_time,omitempty"`
		TrackingURI   string                   `json:"tracking_uri,omitempty"`
		EscalationURI string                   `json:"escalation_uri,omitempty"`
	}
	
	if err := json.Unmarshal(b, &temp); err != nil {
		return err
	}
	
	// Parse BaseMessage
	if m.BaseMessage == nil {
		m.BaseMessage = &messages.BaseMessage{}
	}
	if err := m.BaseMessage.FromJSON(b); err != nil {
		return err
	}
	
	// Set fields
	m.Code = temp.Code
	m.Comment = temp.Comment
	m.Args = temp.Args
	m.ProblemItems = temp.ProblemItems
	m.FixHint = temp.FixHint
	m.Impact = temp.Impact
	m.Where = temp.Where
	m.TrackingURI = temp.TrackingURI
	m.EscalationURI = temp.EscalationURI
	
	// Parse time fields
	if temp.ProblemTime != "" {
		if t, err := time.Parse(time.RFC3339, temp.ProblemTime); err == nil {
			m.ProblemTime = &t
		}
	}
	if temp.NoticedTime != "" {
		if t, err := time.Parse(time.RFC3339, temp.NoticedTime); err == nil {
			m.NoticedTime = &t
		}
	}
	
	return nil
}