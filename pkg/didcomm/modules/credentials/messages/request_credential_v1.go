package messages

import (
	"encoding/json"

	"github.com/ajna-inc/essi/pkg/didcomm/messages"
)

const RequestCredentialV1Type = "https://didcomm.org/issue-credential/1.0/request-credential"

// RequestCredentialV1 represents an Aries RFC 0036 credential request message
type RequestCredentialV1 struct {
	*messages.BaseMessage
	Comment        string                         `json:"comment,omitempty"`
	RequestsAttach []messages.AttachmentDecorator `json:"requests~attach"`
}

// NewRequestCredentialV1 creates a new v1 credential request message
func NewRequestCredentialV1() *RequestCredentialV1 {
	return &RequestCredentialV1{
		BaseMessage: messages.NewBaseMessage(RequestCredentialV1Type),
	}
}

// ToJSON converts the message to JSON
func (m *RequestCredentialV1) ToJSON() ([]byte, error) {
	// Create a map to combine BaseMessage fields with request-specific fields
	result := make(map[string]interface{})
	
	// Add base message fields
	result["@type"] = m.GetType()
	result["@id"] = m.GetId()
	
	// Add thread decoration if present
	if m.GetThread() != nil {
		result["~thread"] = m.GetThread()
	}
	
	// Add request-specific fields
	result["requests~attach"] = m.RequestsAttach
	if m.Comment != "" {
		result["comment"] = m.Comment
	}
	
	// Marshal the complete map
	return json.Marshal(result)
}

// FromJSON populates the message from JSON
func (m *RequestCredentialV1) FromJSON(b []byte) error {
	return json.Unmarshal(b, &m)
}