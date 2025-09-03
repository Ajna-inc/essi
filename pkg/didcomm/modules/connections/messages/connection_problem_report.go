package messages

import (
	"encoding/json"
	"fmt"

	"github.com/ajna-inc/essi/pkg/didcomm/messages"
)

// ConnectionProblemReportMessage represents a connection problem report
type ConnectionProblemReportMessage struct {
	*messages.BaseMessage
	
	// Problem code - standardized error codes
	ProblemCode string `json:"problem-code"`
	
	// Human-readable explanation
	Explain string `json:"explain,omitempty"`
}

// Message type constants
const (
	ConnectionProblemReportType     = "https://didcomm.org/connections/1.0/problem-report"
	ConnectionProblemReportTypeV1_0 = "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/connections/1.0/problem-report"
)

// Connection problem codes following credo-ts
const (
	ConnectionProblemReportReasonRequestNotAccepted = "request_not_accepted"
	ConnectionProblemReportReasonRequestProcessingError = "request_processing_error"
	ConnectionProblemReportReasonResponseNotAccepted = "response_not_accepted" 
	ConnectionProblemReportReasonResponseProcessingError = "response_processing_error"
)

// NewConnectionProblemReportMessage creates a new problem report
func NewConnectionProblemReportMessage(problemCode string, explain string) *ConnectionProblemReportMessage {
	baseMessage := messages.NewBaseMessage(ConnectionProblemReportType)
	
	return &ConnectionProblemReportMessage{
		BaseMessage: baseMessage,
		ProblemCode: problemCode,
		Explain:     explain,
	}
}

// NewConnectionProblemReportFromMessage creates a problem report in response to another message
func NewConnectionProblemReportFromMessage(originalMessage messages.MessageInterface, problemCode string, explain string) *ConnectionProblemReportMessage {
	problemReport := NewConnectionProblemReportMessage(problemCode, explain)
	
	// Set threading to reference the original message
	if originalMessage.GetThreadId() != "" {
		problemReport.SetThreadId(originalMessage.GetThreadId())
	} else {
		problemReport.SetThreadId(originalMessage.GetId())
	}
	
	return problemReport
}

// SetProblemCode sets the problem code
func (m *ConnectionProblemReportMessage) SetProblemCode(code string) {
	m.ProblemCode = code
}

// GetProblemCode returns the problem code
func (m *ConnectionProblemReportMessage) GetProblemCode() string {
	return m.ProblemCode
}

// SetExplain sets the explanation
func (m *ConnectionProblemReportMessage) SetExplain(explain string) {
	m.Explain = explain
}

// GetExplain returns the explanation
func (m *ConnectionProblemReportMessage) GetExplain() string {
	return m.Explain
}

// Validate validates the problem report message
func (m *ConnectionProblemReportMessage) Validate() error {
	if err := m.BaseMessage.Validate(); err != nil {
		return err
	}
	
	if m.ProblemCode == "" {
		return fmt.Errorf("problem report must have a problem code")
	}
	
	// Problem reports should reference the original thread
	if m.GetThreadId() == "" {
		return fmt.Errorf("problem report must reference a thread")
	}
	
	return nil
}

// ToJSON converts the problem report to JSON
func (m *ConnectionProblemReportMessage) ToJSON() ([]byte, error) {
	return json.Marshal(m)
}

// FromJSON populates the problem report from JSON
func (m *ConnectionProblemReportMessage) FromJSON(data []byte) error {
	return json.Unmarshal(data, m)
}

// Clone creates a deep copy of the message
func (m *ConnectionProblemReportMessage) Clone() messages.MessageInterface {
	clone := &ConnectionProblemReportMessage{
		BaseMessage: m.BaseMessage.Clone().(*messages.BaseMessage),
		ProblemCode: m.ProblemCode,
		Explain:     m.Explain,
	}
	
	return clone
}