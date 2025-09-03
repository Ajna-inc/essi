package services

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/core/di"
	"github.com/ajna-inc/essi/pkg/core/storage"
	"github.com/ajna-inc/essi/pkg/core/common"
	"github.com/ajna-inc/essi/pkg/core/encoding"
	"github.com/ajna-inc/essi/pkg/core/utils"
	"github.com/ajna-inc/essi/pkg/core/wallet"
	"github.com/ajna-inc/essi/pkg/didcomm/messages"
	conmsg "github.com/ajna-inc/essi/pkg/didcomm/modules/connections/messages"
	"github.com/ajna-inc/essi/pkg/didcomm/modules/oob"
	oobMessages "github.com/ajna-inc/essi/pkg/didcomm/modules/oob/messages"
	dids "github.com/ajna-inc/essi/pkg/dids"
	"github.com/ajna-inc/essi/pkg/dids/api"
	"github.com/ajna-inc/essi/pkg/dids/domain"
	keyresolver "github.com/ajna-inc/essi/pkg/dids/methods/key"
	peer "github.com/ajna-inc/essi/pkg/dids/methods/peer"
)

// Register ConnectionRecord type with the factory at startup
func init() {
	storage.RegisterRecordType("ConnectionRecord", func() storage.Record {
		return &ConnectionRecord{
			BaseRecord: &storage.BaseRecord{
				Type: "ConnectionRecord",
				Tags: make(map[string]string),
			},
		}
	})
}

// ConnectionState represents the state of a connection
type ConnectionState string

const (
	ConnectionStateNull      ConnectionState = "null"
	ConnectionStateInvited   ConnectionState = "invited"
	ConnectionStateRequested ConnectionState = "requested"
	ConnectionStateResponded ConnectionState = "responded"
	ConnectionStateComplete  ConnectionState = "complete"
	ConnectionStateAbandoned ConnectionState = "abandoned"
)

// ConnectionRecord represents a connection record
type ConnectionRecord struct {
	*storage.BaseRecord

	State         ConnectionState `json:"state"`
	Role          string          `json:"role"`
	Did           string          `json:"did,omitempty"`
	TheirDid      string          `json:"theirDid,omitempty"`
	TheirLabel    string          `json:"theirLabel,omitempty"`
	TheirEndpoint string          `json:"theirEndpoint,omitempty"`
	// MyKeyId stores the wallet key id used to represent our DID for this connection
	MyKeyId              string   `json:"myKeyId,omitempty"`
	Alias                string   `json:"alias,omitempty"`
	AutoAcceptConnection bool     `json:"autoAcceptConnection"`
	ImageUrl             string   `json:"imageUrl,omitempty"`
	InvitationDid        string   `json:"invitationDid,omitempty"`
	OutOfBandId          string   `json:"outOfBandId,omitempty"`
	InvitationKey        string   `json:"invitationKey,omitempty"`
	TheirRecipientKey    string   `json:"theirRecipientKey,omitempty"`
	Protocol             string   `json:"protocol"`
	RoutingKeys          []string `json:"routingKeys,omitempty"`
	// DID rotation support - following credo-ts pattern
	PreviousDids      []string `json:"previousDids,omitempty"`
	PreviousTheirDids []string `json:"previousTheirDids,omitempty"`
}

// ToJSON serializes the entire ConnectionRecord including all fields
func (r *ConnectionRecord) ToJSON() ([]byte, error) {
	return json.Marshal(r)
}

// FromJSON deserializes the entire ConnectionRecord including all fields
func (r *ConnectionRecord) FromJSON(data []byte) error {
	return json.Unmarshal(data, r)
}

// ConnectionRepository interface for connection storage
type ConnectionRepository interface {
	Save(ctx *context.AgentContext, record *ConnectionRecord) error
	FindById(ctx *context.AgentContext, id string) (*ConnectionRecord, error)
	FindByOutOfBandId(ctx *context.AgentContext, oobId string) ([]*ConnectionRecord, error)
	FindByDid(ctx *context.AgentContext, did string) (*ConnectionRecord, error)
	FindByInvitationKey(ctx *context.AgentContext, key string) (*ConnectionRecord, error)
	GetAll(ctx *context.AgentContext) ([]*ConnectionRecord, error)
	Update(ctx *context.AgentContext, record *ConnectionRecord) error
	Delete(ctx *context.AgentContext, id string) error
}

// SimpleConnectionRepository removed - use repository.ConnectionRepository with StorageService instead

// ConnectionService handles connection protocol operations
type ConnectionService struct {
	context       *context.AgentContext
	repository    ConnectionRepository
	walletService *wallet.WalletService
	didsApi       *api.DidsApi
}

// normalizeRecipientKey converts did:key or base58 variants to base58 raw Ed25519 for storage
func normalizeRecipientKey(k string) string {
	if strings.HasPrefix(k, "did:key:") {
		// Strip optional fragment
		if idx := strings.Index(k, "#"); idx != -1 {
			k = k[:idx]
		}
		// Remove did:key: prefix and multibase 'z'
		msid := strings.TrimPrefix(k, "did:key:")
		if strings.HasPrefix(msid, "z") {
			msid = msid[1:]
		}
		rawWithCodec, err := encoding.DecodeBase58(msid)
		if err != nil || len(rawWithCodec) < 3 {
			return k
		}
		// Remove 0xed01 prefix when present
		if rawWithCodec[0] == 0xed && rawWithCodec[1] == 0x01 {
			raw := rawWithCodec[2:]
			return encoding.EncodeBase58(raw)
		}
		if rawWithCodec[0] == 0xed {
			raw := rawWithCodec[1:]
			return encoding.EncodeBase58(raw)
		}
		return k
	}
	return k
}

// NewConnectionService creates a new connection service
func NewConnectionService(ctx *context.AgentContext, repository ConnectionRepository, walletService *wallet.WalletService) *ConnectionService {
	return &ConnectionService{
		context:       ctx,
		repository:    repository,
		walletService: walletService,
	}
}

// SetDidsApi injects the DidsApi from DI
func (cs *ConnectionService) SetDidsApi(api *api.DidsApi) { cs.didsApi = api }

// GetContext returns the agent context
func (cs *ConnectionService) GetContext() *context.AgentContext {
	return cs.context
}

// GetDefaultServiceEndpoint returns the preferred service endpoint for this agent
func (cs *ConnectionService) GetDefaultServiceEndpoint() string {
	if cs == nil || cs.context == nil || cs.context.Config == nil {
		return "http://localhost:3001"
	}
	if len(cs.context.Config.Endpoints) > 0 && cs.context.Config.Endpoints[0] != "" {
		return cs.context.Config.Endpoints[0]
	}
	if cs.context.Config.InboundPort > 0 {
		host := cs.context.Config.InboundHost
		if host == "" {
			host = "localhost"
		}
		return fmt.Sprintf("http://%s:%d", host, cs.context.Config.InboundPort)
	}
	return "http://localhost:3001"
}

// ProcessConnectionRequest processes an incoming connection request message
func (cs *ConnectionService) ProcessConnectionRequest(request *conmsg.ConnectionRequestMessage, recipientKey string, senderKey string) (*ConnectionRecord, *conmsg.ConnectionResponseMessage, error) {
	log.Printf("🔄 Processing connection request from: %s", request.GetLabel())

	// Extract connection info from request
	connectionInfo := request.GetConnection()
	if connectionInfo == nil || connectionInfo.DidDoc == nil {
		return nil, nil, fmt.Errorf("connection request must include connection info with DID document")
	}

	// Create connection record for the inviter role
	connectionId := common.GenerateUUID()
	connectionRecord := &ConnectionRecord{
		BaseRecord: &storage.BaseRecord{
			ID:   connectionId,
			Type: "ConnectionRecord",
			Tags: map[string]string{
				"threadId": request.GetThreadId(),
				"state":    string(ConnectionStateRequested),
			},
		},
		State:             ConnectionStateRequested,
		Role:              "inviter",
		TheirDid:          connectionInfo.Did,
		TheirLabel:        request.GetLabel(),
		Protocol:          "https://didcomm.org/connections/1.0",
		InvitationKey:     normalizeRecipientKey(recipientKey),
		TheirRecipientKey: normalizeRecipientKey(senderKey),
	}

	// Extract their endpoint from DID document
	if len(connectionInfo.DidDoc.Service) > 0 {
		service := connectionInfo.DidDoc.Service[0]
		if endpoint, ok := service.ServiceEndpoint.(string); ok {
			connectionRecord.TheirEndpoint = endpoint
		}
	}

	// Generate our key for this connection
	ourKey, err := cs.walletService.CreateKey(wallet.KeyTypeEd25519)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create key for connection: %w", err)
	}

	fingerprint, err := peer.Ed25519Fingerprint(ourKey.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create fingerprint: %w", err)
	}
	peerDid := fmt.Sprintf("did:peer:0%s", fingerprint)

	// Store our DID and key
	connectionRecord.Did = peerDid
	connectionRecord.MyKeyId = ourKey.Id

	// Save the connection record
	if err := cs.repository.Save(cs.context, connectionRecord); err != nil {
		return nil, nil, fmt.Errorf("failed to save connection record: %w", err)
	}

	didDoc, err := cs.createDidDocumentForPeerDid(peerDid, ourKey.PublicKey, cs.GetDefaultServiceEndpoint())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create DID document: %w", err)
	}

	response, err := conmsg.NewConnectionResponseFromRequest(request, peerDid, didDoc)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create connection response: %w", err)
	}

	// Update state to responded
	connectionRecord.State = ConnectionStateResponded
	connectionRecord.Tags["state"] = string(ConnectionStateResponded)
	if err := cs.repository.Update(cs.context, connectionRecord); err != nil {
		log.Printf("⚠️ Failed to update connection state: %v", err)
	}

	log.Printf("✅ Created connection response for request from: %s", request.GetLabel())

	return connectionRecord, response, nil
}

// ProcessConnectionResponse processes an incoming connection response message
func (cs *ConnectionService) ProcessConnectionResponse(response *conmsg.ConnectionResponseMessage) (*ConnectionRecord, error) {
	log.Printf("🔄 Processing connection response")

	// Find connection record by thread ID
	threadId := response.GetThreadId()
	if threadId == "" {
		return nil, fmt.Errorf("connection response must have thread ID")
	}

	// Find connection by thread ID
	connections, err := cs.repository.GetAll(cs.context)
	if err != nil {
		return nil, fmt.Errorf("failed to get connections: %w", err)
	}

	var connectionRecord *ConnectionRecord
	for _, conn := range connections {
		if conn.Tags != nil && conn.Tags["threadId"] == threadId {
			connectionRecord = conn
			break
		}
	}

	if connectionRecord == nil {
		return nil, fmt.Errorf("no connection found for thread ID: %s", threadId)
	}

	// Verify we're in the right state
	if connectionRecord.State != ConnectionStateRequested && connectionRecord.State != ConnectionStateInvited {
		return nil, fmt.Errorf("connection in wrong state for response: %s", connectionRecord.State)
	}

	// Extract connection info from response
	connectionInfo := response.GetConnection()
	if connectionInfo == nil {
		// Try to get from signature if present
		if response.ConnectionSig != nil {
			info, err := response.GetConnectionFromSignature()
			if err != nil {
				return nil, fmt.Errorf("failed to extract connection from signature: %w", err)
			}
			connectionInfo = info
		} else {
			return nil, fmt.Errorf("connection response must include connection info")
		}
	}

	// Update connection record with their info
	connectionRecord.TheirDid = connectionInfo.Did
	if connectionInfo.DidDoc != nil {
		// Extract their endpoint
		if len(connectionInfo.DidDoc.Service) > 0 {
			service := connectionInfo.DidDoc.Service[0]
			if endpoint, ok := service.ServiceEndpoint.(string); ok {
				connectionRecord.TheirEndpoint = endpoint
			}
		}
		// Extract their recipient key
		if len(connectionInfo.DidDoc.GetRecipientKeys()) > 0 {
			connectionRecord.TheirRecipientKey = normalizeRecipientKey(connectionInfo.DidDoc.GetRecipientKeys()[0])
		}
	}

	// Update state to complete
	connectionRecord.State = ConnectionStateComplete
	connectionRecord.Tags["state"] = string(ConnectionStateComplete)

	// Save updated connection
	if err := cs.repository.Update(cs.context, connectionRecord); err != nil {
		return nil, fmt.Errorf("failed to update connection record: %w", err)
	}

	log.Printf("✅ Connection complete with: %s", connectionRecord.TheirDid)

	return connectionRecord, nil
}

// CreateConnectionResponse creates a connection response for a received request
func (cs *ConnectionService) CreateConnectionResponse(connectionId string) (*conmsg.ConnectionResponseMessage, error) {
	// Find connection record
	connectionRecord, err := cs.repository.FindById(cs.context, connectionId)
	if err != nil {
		return nil, fmt.Errorf("failed to find connection: %w", err)
	}

	if connectionRecord.State != ConnectionStateRequested {
		return nil, fmt.Errorf("connection must be in requested state to create response")
	}

	ourKey, err := cs.walletService.GetKey(connectionRecord.MyKeyId)
	if err != nil {
		return nil, fmt.Errorf("failed to get our key: %w", err)
	}

	didDoc, err := cs.createDidDocumentForPeerDid(connectionRecord.Did, ourKey.PublicKey, cs.GetDefaultServiceEndpoint())
	if err != nil {
		return nil, fmt.Errorf("failed to create DID document: %w", err)
	}

	response := conmsg.NewConnectionResponseMessage()
	response.SetThreadId(connectionRecord.Tags["threadId"])
	response.SetConnectionDid(connectionRecord.Did)
	response.SetDidDocument(didDoc)

	return response, nil
}

// ProcessOOBInvitation processes an out-of-band invitation and creates a connection request
func (cs *ConnectionService) ProcessOOBInvitation(invitation *oobMessages.OutOfBandInvitationMessage, config ProcessInvitationConfig) (*ConnectionRecord, interface{}, *oob.OutOfBandRecord, error) {
	log.Printf("🔄 Processing OOB invitation: %s", invitation.GetLabel())

	// Determine first supported handshake protocol respecting minor-version tolerance and requested order
	var useProtocol string
	requested := invitation.GetHandshakeProtocols()
	if len(requested) > 0 {
		for _, rp := range requested {
			// Supported set in our agent (preference order)
			supported := []string{"https://didcomm.org/didexchange/1.1", "https://didcomm.org/connections/1.0"}
			// Parse requested and compare
			reqParsed, err := oob.ParseProtocolUri(rp.ProtocolId)
			if err != nil {
				continue
			}
			for _, s := range supported {
				supParsed, err := oob.ParseProtocolUri(s)
				if err != nil {
					continue
				}
				if oob.SupportsProtocolVersion(supParsed, reqParsed) {
					useProtocol = supParsed.FullUri
					break
				}
			}
			if useProtocol != "" {
				break
			}
		}
	}
	if useProtocol == "" {
		// Default preference if none requested or mismatch
		useProtocol = "https://didcomm.org/didexchange/1.1"
	}
	log.Printf("🔄 Using handshake protocol: %s", useProtocol)

	oobRecord := &oob.OutOfBandRecord{
		ID:                  common.GenerateUUID(),
		Role:                oob.OutOfBandRoleReceiver,
		State:               "initial",
		OutOfBandInvitation: invitation,
		ReusableConnection:  false,
		Tags:                make(map[string]string),
		CreatedAt:           time.Now(),
		UpdatedAt:           time.Now(),
	}

	// Attempt connection reuse only if requested
	if config.ReuseConnection {
		if conns, err := cs.repository.GetAll(cs.context); err == nil {
			services := invitation.GetServices()
			if len(services) > 0 {
				svc := services[0]
				// DID-based service
				if endpoint, ok := svc.ServiceEndpoint.(string); ok && utils.IsValidDid(endpoint) {
					if existing, err := cs.repository.FindByDid(cs.context, endpoint); err == nil && existing != nil {
						log.Printf("🔁 Reusing existing connection by DID: %s", endpoint)
						// Best-effort handshake-reuse can be sent by higher-level API (Agent) to avoid cycles
						return existing, nil, oobRecord, nil
					}
				}
				// Inline service with recipient keys
				if len(svc.RecipientKeys) > 0 {
					norm := normalizeRecipientKey(svc.RecipientKeys[0])
					for _, c := range conns {
						if c != nil && (c.TheirRecipientKey == norm || c.InvitationKey == norm) {
							log.Printf("🔁 Reusing existing connection by recipient key")
							// Best-effort handshake-reuse can be sent by higher-level API (Agent) to avoid cycles
							return c, nil, oobRecord, nil
						}
					}
				}
			}
		}
	}

	connectionId := common.GenerateUUID()
	connectionRecord := &ConnectionRecord{
		BaseRecord: &storage.BaseRecord{
			ID:   connectionId,
			Type: "ConnectionRecord",
			Tags: map[string]string{
				"outOfBandId": invitation.GetId(),
				"state":       string(ConnectionStateInvited),
			},
		},
		State:                ConnectionStateInvited,
		Role:                 "invitee",
		TheirLabel:           invitation.GetLabel(),
		Alias:                config.Alias,
		AutoAcceptConnection: config.AutoAcceptConnection,
		OutOfBandId:          invitation.GetId(),
		Protocol:             useProtocol,
	}

	// Extract invitation details
	services := invitation.GetServices()
	if len(services) > 0 {
		service := services[0]

		// Handle different service types
		switch endpoint := service.ServiceEndpoint.(type) {
		case string:
			if utils.IsValidDid(endpoint) {
				// DID-based service
				connectionRecord.InvitationDid = endpoint
				log.Printf("📋 Using DID-based service: %s", endpoint)
			} else {
				// Inline service with URL endpoint
				connectionRecord.TheirEndpoint = endpoint
				if len(service.RecipientKeys) > 0 {
					rk := service.RecipientKeys[0]
					// IMPORTANT: Keep the original did:key format for TheirRecipientKey
					// Credo-TS expects messages encrypted to the exact did:key from the invitation
					connectionRecord.TheirRecipientKey = rk                    // Keep original did:key format
					connectionRecord.InvitationKey = normalizeRecipientKey(rk) // Can normalize for internal use
					log.Printf("📋 Using key-based service with recipient key (original): %s", rk)
					log.Printf("📋 Set TheirRecipientKey for encryption (did:key format): %s", connectionRecord.TheirRecipientKey)
					log.Printf("📋 Set InvitationKey (normalized for internal use): %s", connectionRecord.InvitationKey)
				}
				// Store routing keys if provided
				if len(service.RoutingKeys) > 0 {
					connectionRecord.RoutingKeys = service.RoutingKeys
				}
			}
		}
	}

	// Get DidsApi from typed dependency manager
	if cs.didsApi == nil {
		return nil, nil, nil, fmt.Errorf("failed to resolve DidsApi: DidsApi not available")
	}

	// Generate a new key for this connection
	ourKey, err := cs.walletService.CreateKey(wallet.KeyTypeEd25519)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create key for connection: %w", err)
	}

	// Determine our service endpoint (use first configured endpoint if available)
	serviceEndpoint := ""
	if cs.context.Config != nil && len(cs.context.Config.Endpoints) > 0 {
		serviceEndpoint = cs.context.Config.Endpoints[0]
	}
	log.Printf("🧭 Using service endpoint for DIDDoc: %s", serviceEndpoint)

	// Build DID Document with DIDComm service and derive did:peer:4 long-form for request
	didKey, derr := keyresolver.CreateDidKeyFromEd25519PublicKey(ourKey.PublicKey)
	if derr != nil {
		return nil, nil, nil, fmt.Errorf("failed to create did:key: %w", derr)
	}
	var peerDid string
	didDocFor4 := dids.NewDidDocument("")
	// Add Ed25519 verification method and use local reference in service
	vm := &dids.VerificationMethod{
		Id: "#key-1",
		// For numalgo 4 embedded DID Document use 2020 + publicKeyMultibase
		Type:       dids.VerificationMethodTypeEd25519VerificationKey2020,
		Controller: "#id",
		PublicKeyMultibase: func() string {
			fp, _ := peer.Ed25519Fingerprint(ourKey.PublicKey)
			return fp
		}(),
	}
	didDocFor4.AddVerificationMethod(vm)
	didDocFor4.AddAuthentication(dids.NewVerificationMethodRefString(vm.Id))
	didDocFor4.AddAssertionMethod(dids.NewVerificationMethodRefString(vm.Id))
	didDocFor4.AddCapabilityInvocation(dids.NewVerificationMethodRefString(vm.Id))
	didDocFor4.AddCapabilityDelegation(dids.NewVerificationMethodRefString(vm.Id))
	// Use DIDComm v1 (did-communication) service type here for Credo-TS compatibility
	// Credo-TS DidCommDocumentService currently resolves only IndyAgent & did-communication services
	didDocFor4.AddService(&dids.Service{
		Id:              "#inline-0",
		Type:            dids.ServiceTypeDIDComm,
		ServiceEndpoint: serviceEndpoint,
		RecipientKeys:   []string{"#key-1"},
		RoutingKeys:     []string{},
		Accept:          []string{"didcomm/aip2;env=rfc587", "didcomm/aip2;env=rfc19"},
	})
	_, longDid4, perr := peer.CreateDidPeerNumAlgo4FromDidDocument(didDocFor4)
	if perr != nil || longDid4 == "" {
		// Fallback to numalgo2 if 4 fails
		// Fallback element also uses did-communication for the same reason
		svc := map[string]interface{}{
			"id":              "#inline-0",
			"type":            dids.ServiceTypeDIDComm,
			"serviceEndpoint": serviceEndpoint,
			"recipientKeys":   []string{didKey},
			"routingKeys":     []string{},
			"accept":          []string{"didcomm/aip2;env=rfc587", "didcomm/aip2;env=rfc19"},
		}
		elem, perr2 := peer.CreatePeerDidElement(peer.PurposeService, dids.ServiceTypeDIDComm, svc)
		if perr2 != nil {
			return nil, nil, nil, fmt.Errorf("failed to build peer did element: %w", perr2)
		}
		peerDid2, perr2 := peer.CreateDidPeerNumAlgo2([]peer.PeerDidElement{*elem})
		if perr2 != nil {
			return nil, nil, nil, fmt.Errorf("failed to create did:peer:2: %w", perr2)
		}
		peerDid = peerDid2
	} else {
		peerDid = longDid4
	}

	didDoc, err := cs.createDidDocumentForPeerDid(peerDid, ourKey.PublicKey, serviceEndpoint)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create DID document: %w", err)
	}
	// Log DIDDoc service details for debugging
	if didDoc != nil && len(didDoc.Service) > 0 {
		if ep, ok := didDoc.Service[0].ServiceEndpoint.(string); ok {
			log.Printf("📡 Advertised DIDDoc service endpoint: %s", ep)
		}
		if len(didDoc.Service[0].RecipientKeys) > 0 {
			log.Printf("🔑 Advertised DIDDoc recipientKeys: %v", didDoc.Service[0].RecipientKeys)
		}
	}

	didDocument := &dids.DidDocument{
		Id:         peerDid,
		Controller: []string{peerDid},
	}

	_, err = cs.didsApi.Create(&dids.DidCreateOptions{
		Method: "peer",
		Options: map[string]interface{}{
			"did":         peerDid,
			"didDocument": didDocument,
			"keys": []domain.DidDocumentKey{
				{
					DidDocumentRelativeKeyId: "#key-1",
					KmsKeyId:                 ourKey.Id,
				},
			},
		},
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create peer DID through DidsApi: %w", err)
	}

	// Store our DID and key in the connection record and persist identifying tags for key continuity
	connectionRecord.Did = peerDid
	connectionRecord.MyKeyId = ourKey.Id
	if connectionRecord.Tags == nil {
		connectionRecord.Tags = map[string]string{}
	}
	if fp, _ := peer.Ed25519Fingerprint(ourKey.PublicKey); fp != "" {
		connectionRecord.Tags["myFingerprint"] = fp
	}
	connectionRecord.Tags["myKeyId"] = ourKey.Id

	log.Printf("🔑 Generated our peer DID: %s", peerDid)

	// Save the connection record
	if err := cs.repository.Save(cs.context, connectionRecord); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to save connection record: %w", err)
	}

	request := cs.createConnectionRequest(invitation, connectionRecord, didDoc, config)

	log.Printf("✅ Created connection request for invitation: %s", invitation.GetLabel())

	return connectionRecord, request, oobRecord, nil
}

// createConnectionRequest creates a connection request message (either DID Exchange or Connections 1.0)
func (cs *ConnectionService) createConnectionRequest(invitation *oobMessages.OutOfBandInvitationMessage, connectionRecord *ConnectionRecord, didDoc *dids.DidDoc, config ProcessInvitationConfig) interface{} {
	// Check which protocol to use
	if connectionRecord.Protocol == "https://didcomm.org/didexchange/1.1" {
		request := &DidExchangeRequestMessage{
			BaseMessage: messages.NewBaseMessage("https://didcomm.org/didexchange/1.1/request"),
			Label:       config.Label,
			Did:         connectionRecord.Did,
		}

		// Attach the DID document
		request.DidDocAttach = &messages.Attachment{
			Id:       common.GenerateUUID(),
			MimeType: "application/json",
			Data: messages.AttachmentData{
				Json: didDoc,
			},
		}

		// Set proper threading per OOB RFC 0434 + RFC 0160:
		// - thid MUST be the request message id
		// - pthid MUST reference the OOB invitation id
		request.SetThreadId(request.GetId())
		request.SetParentThreadId(invitation.GetId())

		// Request return route so responder can correlate over the same session
		if request.GetTransport() == nil {
			request.SetTransport(&messages.TransportDecorator{})
		}
		request.GetTransport().ReturnRoute = "all"

		// Store the request thread id on the record to correlate the response later
		if connectionRecord != nil {
			if connectionRecord.Tags == nil {
				connectionRecord.Tags = make(map[string]string)
			}
			connectionRecord.Tags["threadId"] = request.GetThreadId()
			// Best effort update (ignore error here, caller already saved the record)
			_ = cs.repository.Update(cs.context, connectionRecord)
		}

		return request
	}

	// Default to Connections 1.0 for backward compatibility
	request := conmsg.CreateConnectionRequestWithDidDoc(config.Label, didDoc)

	// Set proper threading per OOB RFC 0434 + RFC 0160:
	// - thid MUST be the request message id
	// - pthid MUST reference the OOB invitation id
	request.SetThreadId(request.GetId())
	request.SetParentThreadId(invitation.GetId())

	// Request return route so responder can correlate over the same session
	if request.GetTransport() == nil {
		request.SetTransport(&messages.TransportDecorator{})
	}
	request.GetTransport().ReturnRoute = "all"

	// Optionally include an image URL
	if config.ImageUrl != "" {
		request.SetImageUrl(config.ImageUrl)
	}

	// Do not request return-route inline; let responder POST to our inbound endpoint

	// Store the request thread id on the record to correlate the response later
	if connectionRecord != nil {
		if connectionRecord.Tags == nil {
			connectionRecord.Tags = make(map[string]string)
		}
		connectionRecord.Tags["threadId"] = request.GetThreadId()
		// Best effort update (ignore error here, caller already saved the record)
		_ = cs.repository.Update(cs.context, connectionRecord)
	}
	return request
}

// ProcessInvitationConfig contains configuration for processing invitations
type ProcessInvitationConfig struct {
	Label                string
	Alias                string
	AutoAcceptConnection bool
	ImageUrl             string
	ReuseConnection      bool
}

// FindById retrieves a connection record by ID
func (cs *ConnectionService) FindById(id string) (*ConnectionRecord, error) {
	return cs.repository.FindById(cs.context, id)
}

// FindByOutOfBandId retrieves connection records by out-of-band ID
func (cs *ConnectionService) FindByOutOfBandId(oobId string) ([]*ConnectionRecord, error) {
	return cs.repository.FindByOutOfBandId(cs.context, oobId)
}

// FindByDid retrieves a connection record by DID
func (cs *ConnectionService) FindByDid(did string) (*ConnectionRecord, error) {
	return cs.repository.FindByDid(cs.context, did)
}

// UpdateConnectionState updates the state of a connection
func (cs *ConnectionService) UpdateConnectionState(connectionId string, newState ConnectionState) error {
	record, err := cs.repository.FindById(cs.context, connectionId)
	if err != nil {
		return fmt.Errorf("failed to find connection record: %w", err)
	}

	record.State = newState
	record.Tags["state"] = string(newState)

	if err := cs.repository.Update(cs.context, record); err != nil {
		return fmt.Errorf("failed to update connection record: %w", err)
	}

	log.Printf("🔄 Updated connection %s state to %s", connectionId, newState)
	return nil
}

// UpdateConnection saves changes to the given connection record
func (cs *ConnectionService) UpdateConnection(record *ConnectionRecord) error {
	if record == nil {
		return fmt.Errorf("connection record cannot be nil")
	}

	if err := cs.repository.Update(cs.context, record); err != nil {
		return fmt.Errorf("failed to update connection record: %w", err)
	}
	return nil
}

// SaveConnection saves a new connection record
func (cs *ConnectionService) SaveConnection(record *ConnectionRecord) error {
	if record == nil {
		return fmt.Errorf("connection record cannot be nil")
	}

	if err := cs.repository.Save(cs.context, record); err != nil {
		return fmt.Errorf("failed to save connection record: %w", err)
	}
	return nil
}

// GetAllConnections returns all connection records
func (cs *ConnectionService) GetAllConnections() ([]*ConnectionRecord, error) {
	return cs.repository.GetAll(cs.context)
}

// NewConnectionRecord creates a new connection record
func NewConnectionRecord(id string) *ConnectionRecord {
	return &ConnectionRecord{
		BaseRecord: &storage.BaseRecord{
			ID:   id,
			Type: "ConnectionRecord",
			Tags: make(map[string]string),
		},
		State: ConnectionStateNull,
	}
}

// createDidDocumentForPeerDid creates a DID document for a peer DID
func (cs *ConnectionService) createDidDocumentForPeerDid(peerDid string, publicKey []byte, serviceEndpoint string) (*dids.DidDoc, error) {
	didDoc := dids.NewDidDoc(peerDid)

	// Aries 0160 style public key
	vmID := peerDid + "#key-1"
	pk := &dids.PublicKey{
		Id:              vmID,
		Type:            dids.VerificationMethodTypeEd25519VerificationKey2018,
		Controller:      peerDid,
		PublicKeyBase58: encoding.EncodeBase58(publicKey),
	}
	didDoc.AddPublicKey(pk)

	// Also include 2020 + multibase variant to help receivers index our key by z-fingerprint (Credo-TS parity)
	// Use a distinct verification method id, and reference remains backwards compatible via 2018 id
	pk2020 := &dids.PublicKey{
		Id:         peerDid + "#key-1-mb",
		Type:       dids.VerificationMethodTypeEd25519VerificationKey2020,
		Controller: peerDid,
		PublicKeyMultibase: func() string {
			fp, _ := peer.Ed25519Fingerprint(publicKey)
			return fp
		}(),
	}
	didDoc.AddPublicKey(pk2020)

	// Authentication referencing the above key
	didDoc.AddAuthentication(&dids.Authentication{Type: dids.AuthenticationTypeEd25519Signature2018, PublicKey: pk})

	// Add service if we have an endpoint (use did-communication as expected by Credo-TS)
	if serviceEndpoint != "" {
		service := &dids.Service{
			Id:              peerDid + "#service-1",
			Type:            "did-communication",
			ServiceEndpoint: serviceEndpoint,
			// Aries 0160/Credo-TS DIDDoc expects verification method ids in recipientKeys
			// Put the 2018 (base58 verkey) first for maximum interop; include 2020 multibase as secondary
			RecipientKeys: []string{vmID, pk2020.Id},
		}
		didDoc.AddService(service)
	}

	return didDoc, nil
}

// SendTrustPing sends a trust ping message to a connection
func (cs *ConnectionService) SendTrustPing(connectionId string, comment string) error {
	log.Printf("🏓 Sending trust ping to connection %s", connectionId)

	// Find the connection record
	connectionRecord, err := cs.repository.FindById(cs.context, connectionId)
	if err != nil {
		return fmt.Errorf("failed to find connection record: %w", err)
	}

	if connectionRecord == nil {
		return fmt.Errorf("connection record not found: %s", connectionId)
	}

	// Check connection state - can only ping active connections
	if connectionRecord.State != ConnectionStateComplete && connectionRecord.State != ConnectionStateResponded {
		return fmt.Errorf("connection must be in complete or responded state to send trust ping, current state: %s", connectionRecord.State)
	}

	// Check that we have their endpoint
	if connectionRecord.TheirEndpoint == "" {
		return fmt.Errorf("connection does not have an endpoint to send trust ping")
	}

	// Get message sender from DI
	var messageSender interface{}
	if cs.context != nil && cs.context.DependencyManager != nil {
		if dm, ok := cs.context.DependencyManager.(di.DependencyManager); ok {
			if senderAny, err := dm.Resolve(di.TokenMessageSender); err == nil {
				messageSender = senderAny
			}
		}
	}
	if messageSender == nil {
		return fmt.Errorf("message sender service not available")
	}

	// Use the new trust ping message type
	// We need to import and use the new trust ping message type
	// For now, create a simple trust ping structure
	trustPing := map[string]interface{}{
		"@type":              "https://didcomm.org/trust-ping/1.0/ping",
		"@id":                common.GenerateUUID(),
		"comment":            comment,
		"response_requested": true,
	}

	// Add threading information if we have it
	if connectionRecord.Tags != nil && connectionRecord.Tags["threadId"] != "" {
		trustPing["~thread"] = map[string]interface{}{
			"thid": connectionRecord.Tags["threadId"],
		}
	}

	log.Printf("✅ Trust ping created for connection %s with comment: %s", connectionId, comment)

	// Note: Actual sending would require integration with the outbound message service
	// This is a placeholder for the trust ping functionality
	// In a complete implementation, this would:
	// 1. Create a proper TrustPingMessage using the new message types
	// 2. Send it via the MessageSender service
	// 3. Handle the response when it comes back

	return nil
}

// ProcessTrustPingResponse processes a trust ping response and updates connection state
func (cs *ConnectionService) ProcessTrustPingResponse(connectionId string) error {
	log.Printf("🏓✅ Processing trust ping response for connection %s", connectionId)

	// Find the connection record
	connectionRecord, err := cs.repository.FindById(cs.context, connectionId)
	if err != nil {
		return fmt.Errorf("failed to find connection record: %w", err)
	}

	if connectionRecord == nil {
		return fmt.Errorf("connection record not found: %s", connectionId)
	}

	// Update connection state to complete if it wasn't already
	if connectionRecord.State != ConnectionStateComplete {
		connectionRecord.State = ConnectionStateComplete
		connectionRecord.Tags["state"] = string(ConnectionStateComplete)

		if err := cs.repository.Update(cs.context, connectionRecord); err != nil {
			log.Printf("⚠️ Failed to update connection state after trust ping response: %v", err)
			return err
		}

		log.Printf("✅ Connection %s marked as complete after trust ping response", connectionId)
	}

	return nil
}

// CreateTrustPing creates a trust ping message for a connection - following credo-ts pattern
func (cs *ConnectionService) CreateTrustPing(
	ctx *context.AgentContext,
	connection *ConnectionRecord,
	config *CreateTrustPingConfig,
) (TrustPingResult, error) {
	log.Printf("🏓 Creating trust ping for connection %s", connection.ID)

	comment := "ping"
	responseRequested := true

	if config != nil {
		if config.Comment != "" {
			comment = config.Comment
		}
		responseRequested = config.ResponseRequested
	}

	// Import the messages package properly
	ping := map[string]interface{}{
		"@type":              "https://didcomm.org/trust_ping/1.0/ping",
		"@id":                common.GenerateUUID(),
		"comment":            comment,
		"response_requested": responseRequested,
	}

	// Add threading if available
	if connection.Tags != nil && connection.Tags["threadId"] != "" {
		ping["~thread"] = map[string]interface{}{
			"thid": connection.Tags["threadId"],
		}
	}

	log.Printf("✅ Trust ping created for connection %s", connection.ID)

	return TrustPingResult{
		Message: ping,
	}, nil
}

// TrustPingResult contains the result of creating a trust ping
type TrustPingResult struct {
	Message interface{} // Simplified - would be actual TrustPingMessage in full implementation
}

// CreateTrustPingConfig contains configuration for trust ping creation - matches credo-ts
type CreateTrustPingConfig struct {
	ResponseRequested bool
	Comment           string
}
