package messages

import (
	"encoding/json"

	"github.com/ajna-inc/essi/pkg/didcomm/messages"
)

// Types for Issue Credential v2 (https://didcomm.org/issue-credential/2.0/)
const (
	RequestCredentialV2Type = "https://didcomm.org/issue-credential/2.0/request-credential"
	IssueCredentialV2Type   = "https://didcomm.org/issue-credential/2.0/issue-credential"
)

// Offer moved to offer_credential_v2.go

type IssueCredentialV2Request struct{ *messages.BaseMessage }

func NewIssueCredentialV2Request() *IssueCredentialV2Request {
	return &IssueCredentialV2Request{BaseMessage: messages.NewBaseMessage(RequestCredentialV2Type)}
}
func (m *IssueCredentialV2Request) ToJSON() ([]byte, error) { return m.BaseMessage.ToJSON() }
func (m *IssueCredentialV2Request) FromJSON(b []byte) error { return json.Unmarshal(b, &m) }

type IssueCredentialV2Credential struct {
	*messages.BaseMessage
	Formats           []FormatEntry                  `json:"formats"`
	CredentialsAttach []messages.AttachmentDecorator `json:"credentials~attach"`
}

func NewIssueCredentialV2Credential() *IssueCredentialV2Credential {
	return &IssueCredentialV2Credential{
		BaseMessage:       messages.NewBaseMessage(IssueCredentialV2Type),
		Formats:           []FormatEntry{},
		CredentialsAttach: []messages.AttachmentDecorator{},
	}
}

func (m *IssueCredentialV2Credential) ToJSON() ([]byte, error) {
	// Create a map to combine BaseMessage fields with credential-specific fields
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
	
	// Add credential-specific fields
	result["formats"] = m.Formats
	result["credentials~attach"] = m.CredentialsAttach
	
	// Marshal the complete map
	return json.Marshal(result)
}
func (m *IssueCredentialV2Credential) FromJSON(b []byte) error { return json.Unmarshal(b, &m) }
