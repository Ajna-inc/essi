package messages

import (
	"encoding/json"

	"github.com/ajna-inc/essi/pkg/didcomm/messages"
)

const OfferCredentialV2Type = "https://didcomm.org/issue-credential/2.0/offer-credential"

type FormatEntry struct {
	AttachID string `json:"attach_id"`
	Format   string `json:"format"`
}

// CredentialPreviewAttribute represents a single attribute in the credential preview
type CredentialPreviewAttribute struct {
	Name     string `json:"name"`
	MimeType string `json:"mime-type,omitempty"`
	Value    string `json:"value"`
}

// CredentialPreview represents the v2 credential preview
type CredentialPreview struct {
	Type       string                       `json:"@type"`
	Attributes []CredentialPreviewAttribute `json:"attributes"`
}

type OfferCredentialV2 struct {
	*messages.BaseMessage
	Formats           []FormatEntry                  `json:"formats,omitempty"`
	OffersAttach      []messages.AttachmentDecorator `json:"offers~attach,omitempty"`
	CredentialPreview *CredentialPreview             `json:"credential_preview,omitempty"`
}

func NewOfferCredentialV2() *OfferCredentialV2 {
	return &OfferCredentialV2{BaseMessage: messages.NewBaseMessage(OfferCredentialV2Type)}
}

func (m *OfferCredentialV2) ToJSON() ([]byte, error) {
	// Create a map to combine BaseMessage fields with offer-specific fields
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
	
	// Add offer-specific fields
	result["formats"] = m.Formats
	result["offers~attach"] = m.OffersAttach
	if m.CredentialPreview != nil {
		result["credential_preview"] = m.CredentialPreview
	}
	
	// Marshal the complete map
	return json.Marshal(result)
}
func (m *OfferCredentialV2) FromJSON(b []byte) error { return json.Unmarshal(b, &m) }
