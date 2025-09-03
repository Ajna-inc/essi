package messages

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/ajna-inc/essi/pkg/core/utils"
	"github.com/ajna-inc/essi/pkg/didcomm/messages"
	connMessages "github.com/ajna-inc/essi/pkg/didcomm/modules/connections/messages"
)

// OutOfBandInvitationMessage represents an out-of-band invitation
type OutOfBandInvitationMessage struct {
	*messages.BaseMessage

	// Out-of-band specific fields
	Label     string              `json:"label"`
	GoalCode  string              `json:"goal_code,omitempty"`
	Goal      string              `json:"goal,omitempty"`
	Accept    []string            `json:"accept,omitempty"`
	Handshake []HandshakeProtocol `json:"handshake_protocols,omitempty"`
	Services  []OutOfBandService  `json:"services"`
	Requests  []interface{}       `json:"requests~attach,omitempty"`
	ImageUrl  string              `json:"imageUrl,omitempty"`
}

// HandshakeProtocol represents a supported handshake protocol
type HandshakeProtocol struct {
	ProtocolId string   `json:"protocol_id"`
	Roles      []string `json:"roles,omitempty"`
}

// OutOfBandService represents a service in an OOB invitation
type OutOfBandService struct {
	Id              string      `json:"id"`
	Type            string      `json:"type"`
	RecipientKeys   []string    `json:"recipientKeys,omitempty"`
	RoutingKeys     []string    `json:"routingKeys,omitempty"`
	ServiceEndpoint interface{} `json:"serviceEndpoint"`
	Accept          []string    `json:"accept,omitempty"`
}

// Message type constants
const (
	OutOfBandInvitationType     = "https://didcomm.org/out-of-band/1.1/invitation"
	OutOfBandInvitationTypeV2_0 = "https://didcomm.org/out-of-band/2.0/invitation"
)

// Goal codes
const (
	GoalCodeIssueVC      = "aries.vc.issue"
	GoalCodeRequestProof = "aries.vc.verify"
	GoalCodeP2PMessaging = "aries.rel.build"
)

// Service types
const (
	ServiceTypeDIDCommMessaging = "DIDCommMessaging"
	ServiceTypeDIDComm          = "did-communication"
)

// MarshalJSON ensures handshake_protocols serializes as string[] for Credo-TS compatibility
func (m *OutOfBandInvitationMessage) MarshalJSON() ([]byte, error) {
	type ser struct {
		Type      string                 `json:"@type"`
		Id        string                 `json:"@id"`
		Thread    map[string]interface{} `json:"~thread,omitempty"`
		Transport map[string]interface{} `json:"~transport,omitempty"`

		Label     string        `json:"label"`
		GoalCode  string        `json:"goal_code,omitempty"`
		Goal      string        `json:"goal,omitempty"`
		Accept    []string      `json:"accept,omitempty"`
		Handshake []string      `json:"handshake_protocols,omitempty"`
		Services  []interface{} `json:"services"`
		Requests  []interface{} `json:"requests~attach,omitempty"`
		ImageUrl  string        `json:"imageUrl,omitempty"`
	}
	var hs []string
	if m.Handshake != nil {
		hs = make([]string, 0, len(m.Handshake))
		for _, p := range m.Handshake {
			if p.ProtocolId != "" {
				hs = append(hs, p.ProtocolId)
			}
		}
	}
	// Serialize services: DID services as plain string, inline services as objects
	var servicesSerialized []interface{}
	if m.Services != nil {
		servicesSerialized = make([]interface{}, 0, len(m.Services))
		for _, svc := range m.Services {
			if endpoint, ok := svc.ServiceEndpoint.(string); ok && utils.IsValidDid(endpoint) {
				servicesSerialized = append(servicesSerialized, endpoint)
			} else {
				servicesSerialized = append(servicesSerialized, svc)
			}
		}
	}
	s := ser{
		Type:      m.BaseMessage.GetType(),
		Id:        m.BaseMessage.GetId(),
		Label:     m.Label,
		GoalCode:  m.GoalCode,
		Goal:      m.Goal,
		Accept:    m.Accept,
		Handshake: hs,
		Services:  servicesSerialized,
		Requests:  m.Requests,
		ImageUrl:  m.ImageUrl,
	}
	if thid := m.BaseMessage.GetThreadId(); thid != "" {
		s.Thread = map[string]interface{}{"thid": thid}
	}
	return json.Marshal(&s)
}

// NewOutOfBandInvitationMessage creates a new out-of-band invitation
func NewOutOfBandInvitationMessage(label string) *OutOfBandInvitationMessage {
    baseMessage := messages.NewBaseMessage(OutOfBandInvitationType)

    return &OutOfBandInvitationMessage{
        BaseMessage: baseMessage,
        Label:       label,
        Services:    []OutOfBandService{},
        Handshake:   []HandshakeProtocol{},
        Accept:      []string{"didcomm/aip1", "didcomm/aip2;env=rfc19"},
    }
}

// NewOutOfBandInvitationMessageWithId creates a new OOB invitation with specific ID
func NewOutOfBandInvitationMessageWithId(id, label string) *OutOfBandInvitationMessage {
    baseMessage := messages.NewBaseMessageWithId(id, OutOfBandInvitationType)

    return &OutOfBandInvitationMessage{
        BaseMessage: baseMessage,
        Label:       label,
        Services:    []OutOfBandService{},
        Handshake:   []HandshakeProtocol{},
        Accept:      []string{"didcomm/aip1", "didcomm/aip2;env=rfc19"},
    }
}

// SetGoal sets the goal and goal code for the invitation
func (m *OutOfBandInvitationMessage) SetGoal(goalCode, goal string) {
	m.GoalCode = goalCode
	m.Goal = goal
}

// SetImageUrl sets the image URL for the invitation
func (m *OutOfBandInvitationMessage) SetImageUrl(imageUrl string) {
	m.ImageUrl = imageUrl
}

// AddHandshakeProtocol adds a handshake protocol to the invitation
func (m *OutOfBandInvitationMessage) AddHandshakeProtocol(protocolId string, roles []string) {
	protocol := HandshakeProtocol{
		ProtocolId: protocolId,
		Roles:      roles,
	}
	m.Handshake = append(m.Handshake, protocol)
}

// AddDidService adds a DID-based service to the invitation
func (m *OutOfBandInvitationMessage) AddDidService(did string) error {
	// Validate DID format
	if !utils.IsValidDid(did) {
		return fmt.Errorf("invalid DID format: %s", did)
	}

	// Add DID as service
	m.Services = append(m.Services, OutOfBandService{
		Id:              did,
		Type:            ServiceTypeDIDComm,
		ServiceEndpoint: did,
	})

	return nil
}

// AddInlineService adds an inline service to the invitation
func (m *OutOfBandInvitationMessage) AddInlineService(id, serviceEndpoint string, recipientKeys []string) error {
	// Validate service endpoint
	if !utils.IsValidURL(serviceEndpoint) {
		return fmt.Errorf("invalid service endpoint URL: %s", serviceEndpoint)
	}

	if len(recipientKeys) == 0 {
		return fmt.Errorf("recipient keys are required for inline service")
	}

	service := OutOfBandService{
		Id:              id,
		Type:            ServiceTypeDIDComm,
		RecipientKeys:   recipientKeys,
		ServiceEndpoint: serviceEndpoint,
		Accept:          []string{"didcomm/aip2;env=rfc587", "didcomm/aip2;env=rfc19"},
	}

	m.Services = append(m.Services, service)
	return nil
}

// AddInlineServiceWithRouting adds an inline service with routing keys
func (m *OutOfBandInvitationMessage) AddInlineServiceWithRouting(id, serviceEndpoint string, recipientKeys, routingKeys []string) error {
	if err := m.AddInlineService(id, serviceEndpoint, recipientKeys); err != nil {
		return err
	}

	// Update the last added service with routing keys
	if len(m.Services) > 0 {
		m.Services[len(m.Services)-1].RoutingKeys = routingKeys
	}

	return nil
}

// GetServices returns the services in the invitation
func (m *OutOfBandInvitationMessage) GetServices() []OutOfBandService {
	return m.Services
}

// GetHandshakeProtocols returns the handshake protocols
func (m *OutOfBandInvitationMessage) GetHandshakeProtocols() []HandshakeProtocol {
	return m.Handshake
}

// GetRequests returns the requests~attach entries (if any)
func (m *OutOfBandInvitationMessage) GetRequests() []interface{} {
	return m.Requests
}

// GetLabel returns the label
func (m *OutOfBandInvitationMessage) GetLabel() string {
	return m.Label
}

// GetGoal returns the goal and goal code
func (m *OutOfBandInvitationMessage) GetGoal() (string, string) {
	return m.GoalCode, m.Goal
}

// HasHandshakeProtocol checks if the invitation supports a specific handshake protocol
func (m *OutOfBandInvitationMessage) HasHandshakeProtocol(protocolId string) bool {
	for _, protocol := range m.Handshake {
		if protocol.ProtocolId == protocolId {
			return true
		}
	}
	return false
}

// IsConnectionInvitation checks if this is a connection-type invitation
func (m *OutOfBandInvitationMessage) IsConnectionInvitation() bool {
	return m.HasHandshakeProtocol("https://didcomm.org/connections/1.0") ||
		m.HasHandshakeProtocol("https://didcomm.org/didexchange/1.0")
}

// Validate validates the out-of-band invitation message
func (m *OutOfBandInvitationMessage) Validate() error {
	if err := m.BaseMessage.Validate(); err != nil {
		return err
	}

	if m.Label == "" {
		return fmt.Errorf("out-of-band invitation must have a label")
	}

	if len(m.Services) == 0 {
		return fmt.Errorf("out-of-band invitation must have at least one service")
	}

	// Validate services
	for i, service := range m.Services {
		if err := m.validateService(&service, i); err != nil {
			return fmt.Errorf("invalid service at index %d: %w", i, err)
		}
	}

	// Validate image URL if provided
	if m.ImageUrl != "" {
		if !utils.IsValidURL(m.ImageUrl) {
			return fmt.Errorf("invalid image URL: %s", m.ImageUrl)
		}
	}

	return nil
}

// validateService validates a single service
func (m *OutOfBandInvitationMessage) validateService(service *OutOfBandService, index int) error {
	if service.Id == "" {
		return fmt.Errorf("service must have an ID")
	}

	if service.Type == "" {
		return fmt.Errorf("service must have a type")
	}

	// Check service endpoint
	switch endpoint := service.ServiceEndpoint.(type) {
	case string:
		// Could be a DID or URL
		if utils.IsValidDid(endpoint) {
			// DID-based service - no recipient keys needed
			return nil
		}
		if !utils.IsValidURL(endpoint) {
			return fmt.Errorf("invalid service endpoint: %s", endpoint)
		}
		// URL-based service - requires recipient keys
		if len(service.RecipientKeys) == 0 {
			return fmt.Errorf("inline service must have recipient keys")
		}
	default:
		return fmt.Errorf("service endpoint must be a string")
	}

	return nil
}

// ToJSON converts the invitation to JSON
func (m *OutOfBandInvitationMessage) ToJSON() ([]byte, error) {
	// Serialize handshake_protocols as array of strings for Credo-TS compatibility
	type ser struct {
		Type      string                 `json:"@type"`
		Id        string                 `json:"@id"`
		Thread    map[string]interface{} `json:"~thread,omitempty"`
		Transport map[string]interface{} `json:"~transport,omitempty"`

		Label     string        `json:"label"`
		GoalCode  string        `json:"goal_code,omitempty"`
		Goal      string        `json:"goal,omitempty"`
		Accept    []string      `json:"accept,omitempty"`
		Handshake []string      `json:"handshake_protocols,omitempty"`
		Services  []interface{} `json:"services"`
		Requests  []interface{} `json:"requests~attach,omitempty"`
		ImageUrl  string        `json:"imageUrl,omitempty"`
	}
	var hs []string
	if m.Handshake != nil {
		hs = make([]string, 0, len(m.Handshake))
		for _, p := range m.Handshake {
			if p.ProtocolId != "" {
				hs = append(hs, p.ProtocolId)
			}
		}
	}
	// Serialize services: DID services as plain string, inline services as objects
	var servicesSerialized []interface{}
	if m.Services != nil {
		servicesSerialized = make([]interface{}, 0, len(m.Services))
		for _, svc := range m.Services {
			if endpoint, ok := svc.ServiceEndpoint.(string); ok && utils.IsValidDid(endpoint) {
				servicesSerialized = append(servicesSerialized, endpoint)
			} else {
				servicesSerialized = append(servicesSerialized, svc)
			}
		}
	}
	s := ser{
		Type:      m.BaseMessage.GetType(),
		Id:        m.BaseMessage.GetId(),
		Label:     m.Label,
		GoalCode:  m.GoalCode,
		Goal:      m.Goal,
		Accept:    m.Accept,
		Handshake: hs,
		Services:  servicesSerialized,
		Requests:  m.Requests,
		ImageUrl:  m.ImageUrl,
	}
	if thid := m.BaseMessage.GetThreadId(); thid != "" {
		s.Thread = map[string]interface{}{"thid": thid}
	}
	return json.Marshal(&s)
}

// FromJSON populates the invitation from JSON
func (m *OutOfBandInvitationMessage) FromJSON(data []byte) error {
	return json.Unmarshal(data, m)
}

// Clone creates a deep copy of the message
func (m *OutOfBandInvitationMessage) Clone() messages.MessageInterface {
	clone := &OutOfBandInvitationMessage{
		BaseMessage: m.BaseMessage.Clone().(*messages.BaseMessage),
		Label:       m.Label,
		GoalCode:    m.GoalCode,
		Goal:        m.Goal,
		ImageUrl:    m.ImageUrl,
	}

	// Clone accept array
	if m.Accept != nil {
		clone.Accept = make([]string, len(m.Accept))
		copy(clone.Accept, m.Accept)
	}

	// Clone handshake protocols
	if m.Handshake != nil {
		clone.Handshake = make([]HandshakeProtocol, len(m.Handshake))
		for i, protocol := range m.Handshake {
			clone.Handshake[i] = HandshakeProtocol{
				ProtocolId: protocol.ProtocolId,
				Roles:      append([]string(nil), protocol.Roles...),
			}
		}
	}

	// Clone services
	if m.Services != nil {
		clone.Services = make([]OutOfBandService, len(m.Services))
		for i, service := range m.Services {
			clone.Services[i] = OutOfBandService{
				Id:              service.Id,
				Type:            service.Type,
				RecipientKeys:   append([]string(nil), service.RecipientKeys...),
				RoutingKeys:     append([]string(nil), service.RoutingKeys...),
				ServiceEndpoint: service.ServiceEndpoint,
				Accept:          append([]string(nil), service.Accept...),
			}
		}
	}

	return clone
}

// ToInvitationUrl converts the invitation to an OOB invitation URL
func (m *OutOfBandInvitationMessage) ToInvitationUrl(domain string) (string, error) {
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

	// Parse domain to ensure it's valid
	parsedUrl, err := url.Parse(domain)
	if err != nil {
		return "", fmt.Errorf("invalid domain: %w", err)
	}

	// Add OOB parameter
	parsedUrl.RawQuery = "oob=" + encodedInvitation

	return parsedUrl.String(), nil
}

// ParseOutOfBandInvitationFromUrl parses an OOB invitation from a URL
func ParseOutOfBandInvitationFromUrl(invitationUrl string) (*OutOfBandInvitationMessage, error) {
	// Parse the URL
	parsedUrl, err := url.Parse(invitationUrl)
	if err != nil {
		return nil, fmt.Errorf("invalid invitation URL: %w", err)
	}

	// Extract the OOB parameter
	oobParam := parsedUrl.Query().Get("oob")
	if oobParam == "" {
		return nil, fmt.Errorf("missing 'oob' parameter in URL")
	}

	// Decode the invitation
	invitationBytes, err := utils.DecodeBase64URLString(oobParam)
	if err != nil {
		return nil, fmt.Errorf("failed to decode invitation: %w", err)
	}

	// Parse the invitation
	var invitation OutOfBandInvitationMessage
	if err := json.Unmarshal(invitationBytes, &invitation); err != nil {
		return nil, fmt.Errorf("failed to parse invitation: %w", err)
	}

	// Validate the invitation
	if err := invitation.Validate(); err != nil {
		return nil, fmt.Errorf("invalid invitation: %w", err)
	}

	return &invitation, nil
}

// Helper functions for creating OOB invitations

// CreateDidBasedOOBInvitation creates a DID-based OOB invitation
func CreateDidBasedOOBInvitation(label, did string) (*OutOfBandInvitationMessage, error) {
	invitation := NewOutOfBandInvitationMessage(label)

	if err := invitation.AddDidService(did); err != nil {
		return nil, err
	}

	// Add default handshake protocols
	invitation.AddHandshakeProtocol("https://didcomm.org/didexchange/1.0", []string{})
	invitation.AddHandshakeProtocol("https://didcomm.org/connections/1.0", []string{})

	return invitation, nil
}

// CreateInlineOOBInvitation creates an inline service OOB invitation
func CreateInlineOOBInvitation(label, serviceEndpoint string, recipientKeys []string) (*OutOfBandInvitationMessage, error) {
	invitation := NewOutOfBandInvitationMessage(label)

	serviceId := "did:sov:inline-" + invitation.GetId()
	if err := invitation.AddInlineService(serviceId, serviceEndpoint, recipientKeys); err != nil {
		return nil, err
	}

	// Add default handshake protocols
	invitation.AddHandshakeProtocol("https://didcomm.org/didexchange/1.0", []string{})
	invitation.AddHandshakeProtocol("https://didcomm.org/connections/1.0", []string{})

	return invitation, nil
}

// CreateInlineOOBInvitationWithRouting creates an inline OOB invitation with routing
func CreateInlineOOBInvitationWithRouting(label, serviceEndpoint string, recipientKeys, routingKeys []string) (*OutOfBandInvitationMessage, error) {
	invitation := NewOutOfBandInvitationMessage(label)

	serviceId := "did:sov:inline-" + invitation.GetId()
	if err := invitation.AddInlineServiceWithRouting(serviceId, serviceEndpoint, recipientKeys, routingKeys); err != nil {
		return nil, err
	}

	// Add default handshake protocols
	invitation.AddHandshakeProtocol("https://didcomm.org/didexchange/1.0", []string{})
	invitation.AddHandshakeProtocol("https://didcomm.org/connections/1.0", []string{})

	return invitation, nil
}

// Support for converting to/from legacy connection invitations

// ToConnectionInvitation converts OOB invitation to legacy connection invitation format
func (m *OutOfBandInvitationMessage) ToConnectionInvitation() (*connMessages.ConnectionInvitationMessage, error) {
	if len(m.Services) == 0 {
		return nil, fmt.Errorf("no services available to convert")
	}

	// Use the first service
	service := m.Services[0]

	// Create connection invitation
	invitation := connMessages.NewConnectionInvitationMessage(m.Label)
	invitation.SetImageUrl(m.ImageUrl)

	// Handle different service types
	switch endpoint := service.ServiceEndpoint.(type) {
	case string:
		if utils.IsValidDid(endpoint) {
			// DID-based service
			invitation.SetDid(endpoint)
		} else {
			// Inline service
			invitation.SetServiceEndpoint(endpoint)
			invitation.SetRecipientKeys(service.RecipientKeys)
			if len(service.RoutingKeys) > 0 {
				invitation.SetRoutingKeys(service.RoutingKeys)
			}
		}
	default:
		return nil, fmt.Errorf("unsupported service endpoint type")
	}

	return invitation, nil
}

// FromConnectionInvitation creates an OOB invitation from a legacy connection invitation
func FromConnectionInvitation(connInvitation *connMessages.ConnectionInvitationMessage) (*OutOfBandInvitationMessage, error) {
	if connInvitation == nil {
		return nil, fmt.Errorf("connection invitation cannot be nil")
	}

	invitation := NewOutOfBandInvitationMessage(connInvitation.GetLabel())
	invitation.SetImageUrl(connInvitation.GetImageUrl())

	// Add handshake protocol for connections
	invitation.AddHandshakeProtocol("https://didcomm.org/connections/1.0", []string{})

	// Convert service
	if connInvitation.IsDidInvitation() {
		// DID-based
		if err := invitation.AddDidService(connInvitation.GetDid()); err != nil {
			return nil, err
		}
	} else {
		// Key-based
		serviceId := "did:sov:inline-" + invitation.GetId()
		if err := invitation.AddInlineServiceWithRouting(
			serviceId,
			connInvitation.GetServiceEndpoint(),
			connInvitation.GetRecipientKeys(),
			connInvitation.GetRoutingKeys(),
		); err != nil {
			return nil, err
		}
	}

	return invitation, nil
}

// Custom unmarshaling to handle handshake_protocols compatibility
func (m *OutOfBandInvitationMessage) UnmarshalJSON(data []byte) error {
	// Create a temporary struct to handle the JSON unmarshaling
	type TempMessage struct {
		// BaseMessage fields - we need to extract these manually
		Type      string          `json:"@type"`
		Id        string          `json:"@id"`
		Thread    json.RawMessage `json:"~thread,omitempty"`
		Transport json.RawMessage `json:"~transport,omitempty"`

		// OOB specific fields
		Label              string             `json:"label"`
		GoalCode           string             `json:"goal_code,omitempty"`
		Goal               string             `json:"goal,omitempty"`
		Accept             []string           `json:"accept,omitempty"`
		HandshakeProtocols json.RawMessage    `json:"handshake_protocols,omitempty"`
		Services           []json.RawMessage  `json:"services"`
		Requests           []interface{}      `json:"requests~attach,omitempty"`
		ImageUrl           string             `json:"imageUrl,omitempty"`
	}

	var temp TempMessage
	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}

	// Initialize BaseMessage if it's nil
	if m.BaseMessage == nil {
		m.BaseMessage = messages.NewBaseMessageWithId(temp.Id, temp.Type)
	} else {
		// Update existing BaseMessage fields
		m.BaseMessage.SetType(temp.Type)
		m.BaseMessage.SetId(temp.Id)
	}

	// Handle thread decorator if present
	if len(temp.Thread) > 0 {
		var thread map[string]interface{}
		if err := json.Unmarshal(temp.Thread, &thread); err == nil {
			// Extract thid/pthid if present
			if thidRaw, ok := thread["thid"].(string); ok && thidRaw != "" {
				m.BaseMessage.SetThreadId(thidRaw)
			}
			if pthidRaw, ok := thread["pthid"].(string); ok && pthidRaw != "" {
				m.BaseMessage.SetParentThreadId(pthidRaw)
			}
		}
	}

	// Copy OOB specific fields to the original message
	m.Label = temp.Label
	m.GoalCode = temp.GoalCode
	m.Goal = temp.Goal
	m.Accept = temp.Accept
	m.Requests = temp.Requests
	m.ImageUrl = temp.ImageUrl

	// Handle handshake_protocols - can be either array of strings or array of objects
	if len(temp.HandshakeProtocols) > 0 {
		// Try to unmarshal as array of strings first (credo-ts format)
		var stringProtocols []string
		if err := json.Unmarshal(temp.HandshakeProtocols, &stringProtocols); err == nil {
			// Convert strings to HandshakeProtocol objects
			m.Handshake = make([]HandshakeProtocol, len(stringProtocols))
			for i, protocolStr := range stringProtocols {
				m.Handshake[i] = HandshakeProtocol{
					ProtocolId: protocolStr,
					Roles:      []string{}, // Empty roles for string format
				}
			}
		} else {
			// Try to unmarshal as array of HandshakeProtocol objects
			var protocols []HandshakeProtocol
			if err := json.Unmarshal(temp.HandshakeProtocols, &protocols); err != nil {
				return fmt.Errorf("failed to unmarshal handshake_protocols: %w", err)
			}
			m.Handshake = protocols
		}
	}

	// Handle services: may be array of strings (DIDs) and/or objects
	m.Services = nil
	for _, raw := range temp.Services {
		// Try string DID first
		var asString string
		if err := json.Unmarshal(raw, &asString); err == nil && asString != "" {
			_ = m.AddDidService(asString)
			continue
		}
		// Else try as object
		var svc OutOfBandService
		if err := json.Unmarshal(raw, &svc); err == nil {
			m.Services = append(m.Services, svc)
			continue
		}
		// Unknown entry – skip silently
	}

	return nil
}

// OutOfBandInvitationMessageFromAny attempts to reconstruct an invitation message from a generic value
func OutOfBandInvitationMessageFromAny(v interface{}) (*OutOfBandInvitationMessage, bool) {
	if v == nil {
		return nil, false
	}
	switch vv := v.(type) {
	case *OutOfBandInvitationMessage:
		return vv, true
	case map[string]interface{}:
		if b, err := json.Marshal(vv); err == nil {
			tmp := &OutOfBandInvitationMessage{}
			if err := json.Unmarshal(b, tmp); err == nil {
				return tmp, true
			}
		}
	default:
		// Best-effort via JSON for other types
		if b, err := json.Marshal(v); err == nil {
			tmp := &OutOfBandInvitationMessage{}
			if err := json.Unmarshal(b, tmp); err == nil {
				return tmp, true
			}
		}
	}
	return nil, false
}
