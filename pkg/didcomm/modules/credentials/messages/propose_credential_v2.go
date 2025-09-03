package messages

import (
	"encoding/json"
	"github.com/ajna-inc/essi/pkg/didcomm/messages"
)

const ProposeCredentialV2Type = "https://didcomm.org/issue-credential/2.0/propose-credential"

// ProposeCredentialV2 represents a credential proposal message
// @see https://github.com/hyperledger/aries-rfcs/blob/main/features/0453-issue-credential-v2/README.md#propose-credential
type ProposeCredentialV2 struct {
	*messages.BaseMessage
	Comment           string                         `json:"comment,omitempty"`
	Goal              string                         `json:"goal,omitempty"`
	GoalCode          string                         `json:"goal_code,omitempty"`
	CredentialPreview *CredentialPreview             `json:"credential_preview,omitempty"`
	Formats           []FormatEntry                  `json:"formats"`
	ProposalsAttach   []messages.AttachmentDecorator `json:"proposals~attach"`
}

// NewProposeCredentialV2 creates a new credential proposal message
func NewProposeCredentialV2() *ProposeCredentialV2 {
	return &ProposeCredentialV2{
		BaseMessage:     messages.NewBaseMessage(ProposeCredentialV2Type),
		Formats:         []FormatEntry{},
		ProposalsAttach: []messages.AttachmentDecorator{},
	}
}

// ToJSON marshals the ProposeCredentialV2 message to JSON
func (m *ProposeCredentialV2) ToJSON() ([]byte, error) {
	// Create a map that includes both BaseMessage fields and ProposeCredentialV2 fields
	baseJSON, err := m.BaseMessage.ToJSON()
	if err != nil {
		return nil, err
	}
	
	var baseMap map[string]interface{}
	if err := json.Unmarshal(baseJSON, &baseMap); err != nil {
		return nil, err
	}
	
	// Add ProposeCredentialV2-specific fields
	if m.Comment != "" {
		baseMap["comment"] = m.Comment
	}
	if m.Goal != "" {
		baseMap["goal"] = m.Goal
	}
	if m.GoalCode != "" {
		baseMap["goal_code"] = m.GoalCode
	}
	if m.CredentialPreview != nil {
		baseMap["credential_preview"] = m.CredentialPreview
	}
	baseMap["formats"] = m.Formats
	baseMap["proposals~attach"] = m.ProposalsAttach
	
	return json.Marshal(baseMap)
}

// FromJSON unmarshals a JSON byte array into the ProposeCredentialV2 message
func (m *ProposeCredentialV2) FromJSON(data []byte) error {
	return json.Unmarshal(data, m)
}