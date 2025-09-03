package messages

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ajna-inc/essi/pkg/core/utils"
	"github.com/ajna-inc/essi/pkg/didcomm/messages"
)

// ConnectionInvitationMessage represents a connection invitation
type ConnectionInvitationMessage struct {
	*messages.BaseMessage

	// Connection invitation specific fields
	Label           string   `json:"label"`
	RecipientKeys   []string `json:"recipientKeys,omitempty"`
	ServiceEndpoint string   `json:"serviceEndpoint,omitempty"`
	RoutingKeys     []string `json:"routingKeys,omitempty"`
	Did             string   `json:"did,omitempty"`

	// Legacy fields for backward compatibility
	ImageUrl string `json:"imageUrl,omitempty"`
}

// Message type constants
const (
	ConnectionInvitationType     = "https://didcomm.org/connections/1.0/invitation"
	ConnectionInvitationTypeV1_0 = "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/connections/1.0/invitation"
)

// NewConnectionInvitationMessage creates a new connection invitation message
func NewConnectionInvitationMessage(label string) *ConnectionInvitationMessage {
	baseMessage := messages.NewBaseMessage(ConnectionInvitationType)

	return &ConnectionInvitationMessage{
		BaseMessage: baseMessage,
		Label:       label,
	}
}

// NewConnectionInvitationMessageWithId creates a new connection invitation message with specific ID
func NewConnectionInvitationMessageWithId(id, label string) *ConnectionInvitationMessage {
	baseMessage := messages.NewBaseMessageWithId(id, ConnectionInvitationType)

	return &ConnectionInvitationMessage{
		BaseMessage: baseMessage,
		Label:       label,
	}
}

// SetRecipientKeys sets the recipient keys for the invitation
func (m *ConnectionInvitationMessage) SetRecipientKeys(keys []string) {
	m.RecipientKeys = keys
}

// SetServiceEndpoint sets the service endpoint for the invitation
func (m *ConnectionInvitationMessage) SetServiceEndpoint(endpoint string) {
	m.ServiceEndpoint = endpoint
}

// SetRoutingKeys sets the routing keys for the invitation
func (m *ConnectionInvitationMessage) SetRoutingKeys(keys []string) {
	m.RoutingKeys = keys
}

// SetDid sets the DID for the invitation (alternative to recipient keys + service endpoint)
func (m *ConnectionInvitationMessage) SetDid(did string) {
	m.Did = did
}

// SetImageUrl sets the image URL for the invitation
func (m *ConnectionInvitationMessage) SetImageUrl(imageUrl string) {
	m.ImageUrl = imageUrl
}

// Validate validates the connection invitation message
func (m *ConnectionInvitationMessage) Validate() error {
	if err := m.BaseMessage.Validate(); err != nil {
		return err
	}

	if m.Label == "" {
		return fmt.Errorf("connection invitation must have a label")
	}

	// Must have either DID or (recipient keys + service endpoint)
	if m.Did == "" {
		if len(m.RecipientKeys) == 0 {
			return fmt.Errorf("connection invitation must have either 'did' or 'recipientKeys'")
		}
		if m.ServiceEndpoint == "" {
			return fmt.Errorf("connection invitation must have serviceEndpoint when using recipientKeys")
		}
	}

	// Validate DID format if provided
	if m.Did != "" {
		// Basic DID format validation
		if !utils.IsValidDid(m.Did) {
			return fmt.Errorf("invalid DID format: %s", m.Did)
		}
	}

	// Validate URLs if provided
	if m.ServiceEndpoint != "" {
		if !utils.IsValidURL(m.ServiceEndpoint) {
			return fmt.Errorf("invalid service endpoint URL: %s", m.ServiceEndpoint)
		}
	}

	if m.ImageUrl != "" {
		if !utils.IsValidURL(m.ImageUrl) {
			return fmt.Errorf("invalid image URL: %s", m.ImageUrl)
		}
	}

	return nil
}

// ToJSON converts the invitation to JSON
func (m *ConnectionInvitationMessage) ToJSON() ([]byte, error) {
	return json.Marshal(m)
}

// FromJSON populates the invitation from JSON
func (m *ConnectionInvitationMessage) FromJSON(data []byte) error {
	return json.Unmarshal(data, m)
}

// Clone creates a deep copy of the message
func (m *ConnectionInvitationMessage) Clone() messages.MessageInterface {
	clone := &ConnectionInvitationMessage{
		BaseMessage:     m.BaseMessage.Clone().(*messages.BaseMessage),
		Label:           m.Label,
		ServiceEndpoint: m.ServiceEndpoint,
		Did:             m.Did,
		ImageUrl:        m.ImageUrl,
	}

	// Clone slices
	if m.RecipientKeys != nil {
		clone.RecipientKeys = make([]string, len(m.RecipientKeys))
		copy(clone.RecipientKeys, m.RecipientKeys)
	}

	if m.RoutingKeys != nil {
		clone.RoutingKeys = make([]string, len(m.RoutingKeys))
		copy(clone.RoutingKeys, m.RoutingKeys)
	}

	return clone
}

// GetRecipientKeys returns the recipient keys
func (m *ConnectionInvitationMessage) GetRecipientKeys() []string {
	return m.RecipientKeys
}

// GetServiceEndpoint returns the service endpoint
func (m *ConnectionInvitationMessage) GetServiceEndpoint() string {
	return m.ServiceEndpoint
}

// GetRoutingKeys returns the routing keys
func (m *ConnectionInvitationMessage) GetRoutingKeys() []string {
	return m.RoutingKeys
}

// GetDid returns the DID
func (m *ConnectionInvitationMessage) GetDid() string {
	return m.Did
}

// GetLabel returns the label
func (m *ConnectionInvitationMessage) GetLabel() string {
	return m.Label
}

// GetImageUrl returns the image URL
func (m *ConnectionInvitationMessage) GetImageUrl() string {
	return m.ImageUrl
}

// IsDidInvitation checks if this is a DID-based invitation
func (m *ConnectionInvitationMessage) IsDidInvitation() bool {
	return m.Did != ""
}

// IsKeyBasedInvitation checks if this is a key-based invitation
func (m *ConnectionInvitationMessage) IsKeyBasedInvitation() bool {
	return m.Did == "" && len(m.RecipientKeys) > 0
}

// ToInvitationUrl converts the invitation to an invitation URL
func (m *ConnectionInvitationMessage) ToInvitationUrl(domain string) (string, error) {
	invitationJson, err := m.ToJSON()
	if err != nil {
		return "", fmt.Errorf("failed to serialize invitation: %w", err)
	}

	// Base64URL encode the invitation
	encodedInvitation := utils.EncodeBase64URLString(invitationJson)

	// Create the invitation URL
	if domain == "" {
		domain = "https://example.com"
	}

	invitationUrl := fmt.Sprintf("%s?c_i=%s", domain, encodedInvitation)

	return invitationUrl, nil
}

// ToOOBInvitationUrl converts to an out-of-band invitation URL format
func (m *ConnectionInvitationMessage) ToOOBInvitationUrl(domain string) (string, error) {
	invitationJson, err := m.ToJSON()
	if err != nil {
		return "", fmt.Errorf("failed to serialize invitation: %w", err)
	}

	// Base64URL encode the invitation
	encodedInvitation := utils.EncodeBase64URLString(invitationJson)

	// Create the OOB invitation URL
	if domain == "" {
		domain = "https://example.com"
	}

	invitationUrl := fmt.Sprintf("%s?oob=%s", domain, encodedInvitation)

	return invitationUrl, nil
}

// ParseInvitationFromUrl parses a connection invitation from an invitation URL
func ParseInvitationFromUrl(invitationUrl string) (*ConnectionInvitationMessage, error) {
	// Extract the invitation parameter from URL
	var encodedInvitation string

	// Check for different invitation URL formats
	if strings.Contains(invitationUrl, "c_i=") {
		// Standard connection invitation format
		parts := utils.SplitString(invitationUrl, "c_i=")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid invitation URL format")
		}
		encodedInvitation = parts[1]
	} else if strings.Contains(invitationUrl, "oob=") {
		// Out-of-band invitation format
		parts := utils.SplitString(invitationUrl, "oob=")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid OOB invitation URL format")
		}
		encodedInvitation = parts[1]
	} else {
		return nil, fmt.Errorf("unsupported invitation URL format")
	}

	// Remove any URL fragment or additional parameters
	if strings.Contains(encodedInvitation, "&") {
		parts := utils.SplitString(encodedInvitation, "&")
		encodedInvitation = parts[0]
	}
	if strings.Contains(encodedInvitation, "#") {
		parts := utils.SplitString(encodedInvitation, "#")
		encodedInvitation = parts[0]
	}

	// Decode the invitation
	invitationBytes, err := utils.DecodeBase64URLString(encodedInvitation)
	if err != nil {
		return nil, fmt.Errorf("failed to decode invitation: %w", err)
	}

	// Parse the invitation
	var invitation ConnectionInvitationMessage
	if err := json.Unmarshal(invitationBytes, &invitation); err != nil {
		return nil, fmt.Errorf("failed to parse invitation: %w", err)
	}

	// Validate the invitation
	if err := invitation.Validate(); err != nil {
		return nil, fmt.Errorf("invalid invitation: %w", err)
	}

	return &invitation, nil
}

// Helper functions for creating invitations

// CreateDidBasedInvitation creates a DID-based connection invitation
func CreateDidBasedInvitation(label, did string) *ConnectionInvitationMessage {
	invitation := NewConnectionInvitationMessage(label)
	invitation.SetDid(did)
	return invitation
}

// CreateKeyBasedInvitation creates a key-based connection invitation
func CreateKeyBasedInvitation(label, serviceEndpoint string, recipientKeys []string) *ConnectionInvitationMessage {
	invitation := NewConnectionInvitationMessage(label)
	invitation.SetServiceEndpoint(serviceEndpoint)
	invitation.SetRecipientKeys(recipientKeys)
	return invitation
}

// CreateKeyBasedInvitationWithRouting creates a key-based invitation with routing
func CreateKeyBasedInvitationWithRouting(label, serviceEndpoint string, recipientKeys, routingKeys []string) *ConnectionInvitationMessage {
	invitation := CreateKeyBasedInvitation(label, serviceEndpoint, recipientKeys)
	invitation.SetRoutingKeys(routingKeys)
	return invitation
}

// Support for legacy invitation formats

// ToLegacyFormat converts to legacy invitation format
func (m *ConnectionInvitationMessage) ToLegacyFormat() *ConnectionInvitationMessage {
	clone := m.Clone().(*ConnectionInvitationMessage)
	clone.SetType(ConnectionInvitationTypeV1_0)
	return clone
}

// IsLegacyFormat checks if this is a legacy format invitation
func (m *ConnectionInvitationMessage) IsLegacyFormat() bool {
	return m.GetType() == ConnectionInvitationTypeV1_0
}
