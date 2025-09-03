package messages

import (
	"encoding/json"

	"github.com/ajna-inc/essi/pkg/didcomm/messages"
)

const OfferCredentialV1Type = "https://didcomm.org/issue-credential/1.0/offer-credential"

// CredentialPreviewV1Attribute represents a single attribute in the credential preview
type CredentialPreviewV1Attribute struct {
	Name     string `json:"name"`
	MimeType string `json:"mime-type,omitempty"`
	Value    string `json:"value"`
}

// CredentialPreviewV1 represents the v1 credential preview
type CredentialPreviewV1 struct {
	Type       string                          `json:"@type"`
	Attributes []CredentialPreviewV1Attribute `json:"attributes"`
}

// OfferCredentialV1 represents an Aries RFC 0036 credential offer message
type OfferCredentialV1 struct {
	*messages.BaseMessage
	CredentialPreview *CredentialPreviewV1           `json:"credential_preview"`
	OffersAttach      []messages.AttachmentDecorator `json:"offers~attach"`
	Comment           string                         `json:"comment,omitempty"`
}

// NewOfferCredentialV1 creates a new v1 credential offer message
func NewOfferCredentialV1() *OfferCredentialV1 {
	return &OfferCredentialV1{
		BaseMessage: messages.NewBaseMessage(OfferCredentialV1Type),
	}
}

// ToJSON converts the message to JSON
func (m *OfferCredentialV1) ToJSON() ([]byte, error) {
	// Create a map to combine BaseMessage fields with offer-specific fields
	result := make(map[string]interface{})
	
	// Add base message fields
	result["@type"] = m.GetType()
	result["@id"] = m.GetId()
	
	// Add thread decoration if present
	if m.GetThread() != nil {
		result["~thread"] = m.GetThread()
	}
	
	// Add offer-specific fields
	if m.CredentialPreview != nil {
		result["credential_preview"] = m.CredentialPreview
	}
	result["offers~attach"] = m.OffersAttach
	if m.Comment != "" {
		result["comment"] = m.Comment
	}
	
	// Marshal the complete map
	return json.Marshal(result)
}

// FromJSON populates the message from JSON
func (m *OfferCredentialV1) FromJSON(b []byte) error {
	return json.Unmarshal(b, &m)
}