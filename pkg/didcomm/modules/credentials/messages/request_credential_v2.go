package messages

import (
	"encoding/json"

	"github.com/ajna-inc/essi/pkg/didcomm/messages"
)

// defined in issue_credential_v2.go

type RequestCredentialV2 struct {
	*messages.BaseMessage
	Formats        []FormatEntry                  `json:"formats,omitempty"`
	RequestsAttach []messages.AttachmentDecorator `json:"requests~attach,omitempty"`
}

func NewRequestCredentialV2() *RequestCredentialV2 {
	return &RequestCredentialV2{BaseMessage: messages.NewBaseMessage(RequestCredentialV2Type)}
}

func (m *RequestCredentialV2) ToJSON() ([]byte, error) {
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
	
	// Add request-specific fields
	result["formats"] = m.Formats
	result["requests~attach"] = m.RequestsAttach
	
	// Marshal the complete map
	return json.Marshal(result)
}
func (m *RequestCredentialV2) FromJSON(b []byte) error { return json.Unmarshal(b, &m) }
