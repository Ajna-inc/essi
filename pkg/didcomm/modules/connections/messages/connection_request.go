package messages

import (
	"encoding/json"
	"fmt"

	"github.com/ajna-inc/essi/pkg/dids"
	"github.com/ajna-inc/essi/pkg/core/utils"
	"github.com/ajna-inc/essi/pkg/didcomm/messages"
)

// ConnectionRequestMessage represents a connection request
type ConnectionRequestMessage struct {
	*messages.BaseMessage

	// Connection request specific fields
	Label      string          `json:"label"`
	Connection *ConnectionInfo `json:"connection"`
	ImageUrl   string          `json:"imageUrl,omitempty"`
}

// ConnectionInfo represents the connection information in a request
type ConnectionInfo struct {
	Did    string       `json:"did"`
	DidDoc *dids.DidDoc `json:"didDoc,omitempty"`
}

// Message type constants
const (
	ConnectionRequestType     = "https://didcomm.org/connections/1.0/request"
	ConnectionRequestTypeV1_0 = "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/connections/1.0/request"
)

// NewConnectionRequestMessage creates a new connection request message
func NewConnectionRequestMessage(label, did string) *ConnectionRequestMessage {
	baseMessage := messages.NewBaseMessage(ConnectionRequestType)

	return &ConnectionRequestMessage{
		BaseMessage: baseMessage,
		Label:       label,
		Connection: &ConnectionInfo{
			Did: did,
		},
	}
}

// NewConnectionRequestMessageWithId creates a new connection request message with specific ID
func NewConnectionRequestMessageWithId(id, label, did string) *ConnectionRequestMessage {
	baseMessage := messages.NewBaseMessageWithId(id, ConnectionRequestType)

	return &ConnectionRequestMessage{
		BaseMessage: baseMessage,
		Label:       label,
		Connection: &ConnectionInfo{
			Did: did,
		},
	}
}

// SetDidDoc sets the DID document for the connection
func (m *ConnectionRequestMessage) SetDidDoc(didDoc *dids.DidDoc) {
	if m.Connection == nil {
		m.Connection = &ConnectionInfo{}
	}
	m.Connection.DidDoc = didDoc
}

// SetImageUrl sets the image URL for the request
func (m *ConnectionRequestMessage) SetImageUrl(imageUrl string) {
	m.ImageUrl = imageUrl
}

// SetParentThreadId sets the parent thread id decorator (pthid/parent_thread_id)
func (m *ConnectionRequestMessage) SetParentThreadId(parentThreadId string) {
	m.BaseMessage.SetParentThreadId(parentThreadId)
}

// GetDid returns the DID from the connection info
func (m *ConnectionRequestMessage) GetDid() string {
	if m.Connection == nil {
		return ""
	}
	return m.Connection.Did
}

// GetDidDoc returns the DID document from the connection info
func (m *ConnectionRequestMessage) GetDidDoc() *dids.DidDoc {
	if m.Connection == nil {
		return nil
	}
	return m.Connection.DidDoc
}

// GetLabel returns the label
func (m *ConnectionRequestMessage) GetLabel() string { return m.Label }

// GetImageUrl returns the image URL
func (m *ConnectionRequestMessage) GetImageUrl() string { return m.ImageUrl }

// GetConnection returns the connection info
func (m *ConnectionRequestMessage) GetConnection() *ConnectionInfo { return m.Connection }

// Validate validates the connection request message
func (m *ConnectionRequestMessage) Validate() error {
	if err := m.BaseMessage.Validate(); err != nil { return err }
	if m.Label == "" { return fmt.Errorf("connection request must have a label") }
	if m.Connection == nil { return fmt.Errorf("connection request must have connection info") }
	if m.Connection.Did == "" { return fmt.Errorf("connection request must have a DID") }
	if !utils.IsValidDid(m.Connection.Did) { return fmt.Errorf("invalid DID format: %s", m.Connection.Did) }
	if m.Connection.DidDoc != nil {
		if err := m.Connection.DidDoc.Validate(); err != nil { return fmt.Errorf("invalid DID document: %w", err) }
		if m.Connection.DidDoc.Id != m.Connection.Did { return fmt.Errorf("DID document ID does not match connection DID") }
	}
	if m.ImageUrl != "" && !utils.IsValidURL(m.ImageUrl) { return fmt.Errorf("invalid image URL: %s", m.ImageUrl) }
	return nil
}

// ToJSON converts the request to JSON
func (m *ConnectionRequestMessage) ToJSON() ([]byte, error) { return json.Marshal(m) }

// FromJSON populates the request from JSON
func (m *ConnectionRequestMessage) FromJSON(data []byte) error { return json.Unmarshal(data, m) }

// Clone creates a deep copy of the message
func (m *ConnectionRequestMessage) Clone() messages.MessageInterface {
	clone := &ConnectionRequestMessage{ BaseMessage: m.BaseMessage.Clone().(*messages.BaseMessage), Label: m.Label, ImageUrl: m.ImageUrl }
	if m.Connection != nil {
		clone.Connection = &ConnectionInfo{ Did: m.Connection.Did }
		if m.Connection.DidDoc != nil { clone.Connection.DidDoc = m.Connection.DidDoc.Clone() }
	}
	return clone
}

// CreateReplyMessage creates a threaded reply to this message
func (m *ConnectionRequestMessage) CreateReplyMessage(messageType string) *messages.BaseMessage { return m.BaseMessage.CreateReplyMessage(messageType) }

// IsThreadedReplyTo checks if this message is a threaded reply to another message
func (m *ConnectionRequestMessage) IsThreadedReplyTo(originalMessage messages.MessageInterface) bool { return m.BaseMessage.IsThreadedReplyTo(originalMessage) }

// GetThreadId returns the thread ID of this message
func (m *ConnectionRequestMessage) GetThreadId() string { return m.BaseMessage.GetThreadId() }

// SetThreadId sets the thread ID of this message
func (m *ConnectionRequestMessage) SetThreadId(threadId string) { m.BaseMessage.SetThreadId(threadId) }

// Helper functions for creating connection requests

// CreateConnectionRequestFromInvitation creates a connection request in response to an invitation
func CreateConnectionRequestFromInvitation(invitation *ConnectionInvitationMessage, label, did string) *ConnectionRequestMessage {
	request := NewConnectionRequestMessage(label, did)
	request.SetThreadId(invitation.GetId())
	return request
}

// CreateConnectionRequestWithDidDoc creates a connection request with embedded DID document
func CreateConnectionRequestWithDidDoc(label string, didDoc *dids.DidDoc) *ConnectionRequestMessage {
	if didDoc == nil { return nil }
	request := NewConnectionRequestMessage(label, didDoc.Id)
	request.SetDidDoc(didDoc)
	return request
}

// Support for legacy request formats
func (m *ConnectionRequestMessage) ToLegacyFormat() *ConnectionRequestMessage { clone := m.Clone().(*ConnectionRequestMessage); clone.SetType(ConnectionRequestTypeV1_0); return clone }
func (m *ConnectionRequestMessage) IsLegacyFormat() bool { return m.GetType() == ConnectionRequestTypeV1_0 }

// Utility methods for connection management
func (m *ConnectionRequestMessage) ExtractServiceEndpoint() (string, error) {
	if m.Connection == nil || m.Connection.DidDoc == nil { return "", fmt.Errorf("no DID document available") }
	for _, service := range m.Connection.DidDoc.Service {
		if service.Type == "DIDCommMessaging" || service.Type == "did-communication" {
			if endpoint, ok := service.ServiceEndpoint.(string); ok { return endpoint, nil }
		}
	}
	return "", fmt.Errorf("no DIDComm service endpoint found")
}

func (m *ConnectionRequestMessage) ExtractRecipientKeys() ([]string, error) {
	if m.Connection == nil || m.Connection.DidDoc == nil { return nil, fmt.Errorf("no DID document available") }
	keys := m.Connection.DidDoc.GetRecipientKeys()
	if len(keys) == 0 { return nil, fmt.Errorf("no recipient keys found in DID document") }
	return keys, nil
}

func (m *ConnectionRequestMessage) ValidateAgainstInvitation(invitation *ConnectionInvitationMessage) error {
	if invitation == nil { return fmt.Errorf("invitation cannot be nil") }
	if !m.IsThreadedReplyTo(invitation) { return fmt.Errorf("request is not a threaded reply to the invitation") }
	if err := m.Validate(); err != nil { return fmt.Errorf("invalid request: %w", err) }
	return nil
}
