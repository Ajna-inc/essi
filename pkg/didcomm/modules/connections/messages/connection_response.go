package messages

import (
	"encoding/json"
	"fmt"

	"github.com/ajna-inc/essi/pkg/dids"
	peer "github.com/ajna-inc/essi/pkg/dids/methods/peer"
	"github.com/ajna-inc/essi/pkg/core/encoding"
	"github.com/ajna-inc/essi/pkg/core/utils"
	"github.com/ajna-inc/essi/pkg/didcomm/decorators/signature"
	"github.com/ajna-inc/essi/pkg/didcomm/messages"
)

// ConnectionResponseMessage represents a connection response
type ConnectionResponseMessage struct {
	*messages.BaseMessage

	// Connection response specific fields
	Connection    *ConnectionInfo               `json:"connection,omitempty"`
	ConnectionSig *signature.SignatureDecorator `json:"connection~sig,omitempty"`
	ImageUrl      string                        `json:"imageUrl,omitempty"`
}

// ConnectionSig represents the signed connection information
type ConnectionSig struct {
	Type      string `json:"@type"`
	SigData   string `json:"sig_data"`
	Signer    string `json:"signer"`
	Signature string `json:"signature"`
}

// Message type constants
const (
	ConnectionResponseType     = "https://didcomm.org/connections/1.0/response"
	ConnectionResponseTypeV1_0 = "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/connections/1.0/response"
)

// NewConnectionResponseMessage creates a new connection response
func NewConnectionResponseMessage() *ConnectionResponseMessage {
	baseMessage := messages.NewBaseMessage(ConnectionResponseType)

	return &ConnectionResponseMessage{
		BaseMessage: baseMessage,
	}
}

// NewConnectionResponseMessageWithId creates a new connection response with specific ID
func NewConnectionResponseMessageWithId(id string) *ConnectionResponseMessage {
	baseMessage := messages.NewBaseMessageWithId(id, ConnectionResponseType)

	return &ConnectionResponseMessage{
		BaseMessage: baseMessage,
	}
}

// NewConnectionResponseFromRequest creates a connection response from a request
func NewConnectionResponseFromRequest(request *ConnectionRequestMessage, connectionDid string, didDoc *dids.DidDoc) (*ConnectionResponseMessage, error) {
	if request == nil {
		return nil, fmt.Errorf("connection request cannot be nil")
	}

	response := NewConnectionResponseMessage()

	// Set threading to reference the request
	if request.GetThreadId() != "" {
		response.SetThreadId(request.GetThreadId())
	} else {
		response.SetThreadId(request.GetId())
	}

	// Create connection info
	connectionInfo := &ConnectionInfo{
		Did:    connectionDid,
		DidDoc: didDoc,
	}

	response.SetConnection(connectionInfo)

	return response, nil
}

// SetConnection sets the connection information
func (m *ConnectionResponseMessage) SetConnection(connection *ConnectionInfo) {
	m.Connection = connection
}

// GetConnection returns the connection information
func (m *ConnectionResponseMessage) GetConnection() *ConnectionInfo {
	return m.Connection
}

// SetImageUrl sets the image URL
func (m *ConnectionResponseMessage) SetImageUrl(imageUrl string) {
	m.ImageUrl = imageUrl
}

// GetImageUrl returns the image URL
func (m *ConnectionResponseMessage) GetImageUrl() string {
	return m.ImageUrl
}

// SetConnectionDid sets the connection DID
func (m *ConnectionResponseMessage) SetConnectionDid(did string) {
	if m.Connection == nil {
		m.Connection = &ConnectionInfo{}
	}
	m.Connection.Did = did
}

// GetConnectionDid returns the connection DID
func (m *ConnectionResponseMessage) GetConnectionDid() string {
	if m.Connection == nil {
		return ""
	}
	return m.Connection.Did
}

// SetDidDocument sets the DID document
func (m *ConnectionResponseMessage) SetDidDocument(didDoc *dids.DidDoc) {
	if m.Connection == nil {
		m.Connection = &ConnectionInfo{}
	}
	m.Connection.DidDoc = didDoc
}

// GetDidDocument returns the DID document
func (m *ConnectionResponseMessage) GetDidDocument() *dids.DidDoc {
	if m.Connection == nil {
		return nil
	}
	return m.Connection.DidDoc
}

// Validate validates the connection response message
func (m *ConnectionResponseMessage) Validate() error {
	if err := m.BaseMessage.Validate(); err != nil {
		return err
	}

	if m.Connection == nil {
		return fmt.Errorf("connection response must have connection information")
	}

	if m.Connection.Did == "" {
		return fmt.Errorf("connection response must have a DID")
	}

	// Validate DID format
	if !utils.IsValidDid(m.Connection.Did) {
		return fmt.Errorf("invalid DID format: %s", m.Connection.Did)
	}

	// Validate DID document if provided
	if m.Connection.DidDoc != nil {
		if err := m.Connection.DidDoc.Validate(); err != nil {
			return fmt.Errorf("invalid DID document: %w", err)
		}

		// Ensure DID document ID matches connection DID
		if m.Connection.DidDoc.Id != m.Connection.Did {
			return fmt.Errorf("DID document ID does not match connection DID")
		}
	}

	// Validate image URL if provided
	if m.ImageUrl != "" {
		if !utils.IsValidURL(m.ImageUrl) {
			return fmt.Errorf("invalid image URL: %s", m.ImageUrl)
		}
	}

	// Validate threading - response should have thread ID
	if m.GetThreadId() == "" {
		return fmt.Errorf("connection response must reference a thread")
	}

	return nil
}

// ValidateAgainstRequest validates the response against the original request
func (m *ConnectionResponseMessage) ValidateAgainstRequest(request *ConnectionRequestMessage) error {
	if request == nil {
		return fmt.Errorf("request cannot be nil")
	}

	// Validate basic response structure
	if err := m.Validate(); err != nil {
		return err
	}

	// Check threading relationship
	expectedThreadId := request.GetThreadId()
	if expectedThreadId == "" {
		expectedThreadId = request.GetId()
	}

	if m.GetThreadId() != expectedThreadId {
		return fmt.Errorf("response thread ID does not match request thread ID")
	}

	return nil
}

// ToJSON converts the response to JSON
func (m *ConnectionResponseMessage) ToJSON() ([]byte, error) {
	return json.Marshal(m)
}

// FromJSON populates the response from JSON
func (m *ConnectionResponseMessage) FromJSON(data []byte) error {
	return json.Unmarshal(data, m)
}

// Clone creates a deep copy of the message
func (m *ConnectionResponseMessage) Clone() messages.MessageInterface {
	clone := &ConnectionResponseMessage{
		BaseMessage: m.BaseMessage.Clone().(*messages.BaseMessage),
		ImageUrl:    m.ImageUrl,
	}

	// Clone connection info
	if m.Connection != nil {
		clone.Connection = &ConnectionInfo{
			Did: m.Connection.Did,
		}

		// Clone DID document if present
		if m.Connection.DidDoc != nil {
			clone.Connection.DidDoc = m.Connection.DidDoc.Clone()
		}
	}

	return clone
}

// GetRecipientKeys extracts recipient keys from the DID document
func (m *ConnectionResponseMessage) GetRecipientKeys() ([]string, error) {
	if m.Connection == nil || m.Connection.DidDoc == nil {
		return nil, fmt.Errorf("no DID document available")
	}

	return m.Connection.DidDoc.GetRecipientKeys(), nil
}

// GetServiceEndpoints extracts service endpoints from the DID document
func (m *ConnectionResponseMessage) GetServiceEndpoints() ([]string, error) {
	if m.Connection == nil || m.Connection.DidDoc == nil {
		return nil, fmt.Errorf("no DID document available")
	}

	var endpoints []string
	for _, service := range m.Connection.DidDoc.Service {
		if endpoint, ok := service.ServiceEndpoint.(string); ok {
			endpoints = append(endpoints, endpoint)
		}
	}

	return endpoints, nil
}

// Helper functions for creating connection responses

// CreateConnectionResponseFromDid creates a connection response with just a DID
func CreateConnectionResponseFromDid(requestMessage *ConnectionRequestMessage, connectionDid string) (*ConnectionResponseMessage, error) {
	if requestMessage == nil {
		return nil, fmt.Errorf("request message cannot be nil")
	}

	if connectionDid == "" {
		return nil, fmt.Errorf("connection DID cannot be empty")
	}

	response := NewConnectionResponseMessage()

	// Set threading
	threadId := requestMessage.GetThreadId()
	if threadId == "" {
		threadId = requestMessage.GetId()
	}
	response.SetThreadId(threadId)

	// Set connection DID
	response.SetConnectionDid(connectionDid)

	return response, nil
}

// CreateConnectionResponseWithDidDoc creates a connection response with DID and document
func CreateConnectionResponseWithDidDoc(requestMessage *ConnectionRequestMessage, connectionDid string, didDoc *dids.DidDoc) (*ConnectionResponseMessage, error) {
	response, err := CreateConnectionResponseFromDid(requestMessage, connectionDid)
	if err != nil {
		return nil, err
	}

	if didDoc == nil {
		return nil, fmt.Errorf("DID document cannot be nil")
	}

	// Validate that DID document matches DID
	if didDoc.Id != connectionDid {
		return nil, fmt.Errorf("DID document ID does not match connection DID")
	}

	response.SetDidDocument(didDoc)

	return response, nil
}

// CreateConnectionResponseWithPeerDid creates a connection response with a peer DID
func CreateConnectionResponseWithPeerDid(requestMessage *ConnectionRequestMessage, publicKey []byte, serviceEndpoint string) (*ConnectionResponseMessage, error) {
	if requestMessage == nil {
		return nil, fmt.Errorf("request message cannot be nil")
	}

	if len(publicKey) == 0 {
		return nil, fmt.Errorf("public key cannot be empty")
	}

	// Create peer DID from public key
	peerDid, err := createPeerDidFromKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create peer DID: %w", err)
	}

	// Create DID document
	didDoc, err := createDidDocumentForPeerDid(peerDid, publicKey, serviceEndpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to create DID document: %w", err)
	}

	return CreateConnectionResponseWithDidDoc(requestMessage, peerDid, didDoc)
}

// Helper function to create peer DID from key
func createPeerDidFromKey(publicKey []byte) (string, error) {
	fingerprint, err := peer.Ed25519Fingerprint(publicKey)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("did:peer:0%s", fingerprint), nil
}

// Helper function to create DID document for peer DID
func createDidDocumentForPeerDid(peerDid string, publicKey []byte, serviceEndpoint string) (*dids.DidDoc, error) {
	didDoc := dids.NewDidDoc(peerDid)

	// Create verification method
	vmId := peerDid + "#key-1"
	pk := &dids.PublicKey{
		Id:              vmId,
		Type:            dids.VerificationMethodTypeEd25519VerificationKey2018,
		Controller:      peerDid,
		PublicKeyBase58: encoding.EncodeBase58(publicKey),
	}

	didDoc.AddPublicKey(pk)

	// Add authentication referencing the public key id
	didDoc.AddAuthentication(&dids.Authentication{Type: dids.AuthenticationTypeEd25519Signature2018, PublicKey: pk})

	// Add service if provided
	if serviceEndpoint != "" {
		service := &dids.Service{
			Id:              peerDid + "#service-1",
			Type:            dids.ServiceTypeDIDComm,
			ServiceEndpoint: serviceEndpoint,
			// recipientKeys should reference the verification method id per Aries 0160
			RecipientKeys:   []string{vmId},
		}
		didDoc.AddService(service)
	}

	return didDoc, nil
}

// CreateConnectionResponseWithSignature creates a response with a signed connection
func CreateConnectionResponseWithSignature(threadId string, connectionSig *signature.SignatureDecorator) *ConnectionResponseMessage {
	msg := NewConnectionResponseMessage()
	msg.SetThreadId(threadId)
	msg.ConnectionSig = connectionSig
	return msg
}

// GetConnectionFromSignature extracts and verifies the connection from the signature
func (m *ConnectionResponseMessage) GetConnectionFromSignature() (*ConnectionInfo, error) {
	if m.ConnectionSig == nil {
		return nil, fmt.Errorf("no connection signature found")
	}

	var connection ConnectionInfo
	if err := signature.UnpackAndVerifySignature(m.ConnectionSig, &connection); err != nil {
		return nil, fmt.Errorf("failed to verify connection signature: %w", err)
	}

	return &connection, nil
}
