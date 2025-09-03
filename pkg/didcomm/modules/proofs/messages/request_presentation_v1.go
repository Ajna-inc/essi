package messages

import (
	"encoding/json"

	"github.com/ajna-inc/essi/pkg/didcomm/messages"
)

const RequestPresentationV1Type = "https://didcomm.org/present-proof/1.0/request-presentation"

// RequestPresentationV1 represents an Aries RFC 0037 proof request message
type RequestPresentationV1 struct {
	*messages.BaseMessage
	Comment                      string                         `json:"comment,omitempty"`
	RequestPresentationsAttach   []messages.AttachmentDecorator `json:"request_presentations~attach"`
}

// NewRequestPresentationV1 creates a new v1 proof request message
func NewRequestPresentationV1() *RequestPresentationV1 {
	return &RequestPresentationV1{
		BaseMessage: messages.NewBaseMessage(RequestPresentationV1Type),
	}
}

// ToJSON converts the message to JSON
func (m *RequestPresentationV1) ToJSON() ([]byte, error) {
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
	if m.Comment != "" {
		result["comment"] = m.Comment
	}
	result["request_presentations~attach"] = m.RequestPresentationsAttach
	
	// Marshal the complete map
	return json.Marshal(result)
}

// FromJSON populates the message from JSON
func (m *RequestPresentationV1) FromJSON(b []byte) error {
	return json.Unmarshal(b, &m)
}