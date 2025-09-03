package services

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/core/di"
	"github.com/ajna-inc/essi/pkg/core/logger"
	"github.com/ajna-inc/essi/pkg/core/storage"
	"github.com/ajna-inc/essi/pkg/core/common"
	"github.com/ajna-inc/essi/pkg/core/wallet"
	jws "github.com/ajna-inc/essi/pkg/didcomm/crypto/jws"
	"github.com/ajna-inc/essi/pkg/didcomm/messages"
	peer "github.com/ajna-inc/essi/pkg/dids/methods/peer"
)

// DidExchangeProtocol handles the DID Exchange Protocol as defined in RFC 0023
// This follows the same pattern as credo-ts DidExchangeProtocol
type DidExchangeProtocol struct {
	connectionService *ConnectionService
	walletService     *wallet.WalletService
}

// NewDidExchangeProtocol creates a new DID Exchange Protocol service
func NewDidExchangeProtocol(connectionService *ConnectionService, walletService *wallet.WalletService) *DidExchangeProtocol {
	return &DidExchangeProtocol{
		connectionService: connectionService,
		walletService:     walletService,
	}
}

// CreateRequest creates a DID Exchange request message from an out-of-band invitation
// This follows the same pattern as credo-ts
func (protocol *DidExchangeProtocol) CreateRequest(
	agentContext *context.AgentContext,
	outOfBandRecord interface{}, // OutOfBandRecord type - simplified for now
	config CreateRequestConfig,
) (*DidExchangeRequestMessage, *ConnectionRecord, error) {
	logger.GetDefaultLogger().Info("🔄 Creating DID Exchange request")

	// Generate our DID for this connection
	ourKey, err := protocol.walletService.CreateKey(wallet.KeyTypeEd25519)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create key for DID Exchange: %w", err)
	}

	// Create connection record
	connectionId := common.GenerateUUID()
	connectionRecord := &ConnectionRecord{
		BaseRecord: &storage.BaseRecord{
			ID:   connectionId,
			Type: "ConnectionRecord",
			Tags: make(map[string]string),
		},
		State:    ConnectionStateInvited,
		Role:     "requester", // DID Exchange requester role
		Protocol: "https://didcomm.org/didexchange/1.1",
		MyKeyId:  ourKey.Id,
	}

	// Create DID Exchange request message
	request := &DidExchangeRequestMessage{
		BaseMessage: messages.NewBaseMessage("https://didcomm.org/didexchange/1.1/request"),
		Label:       config.Label,
	}

	request.SetThreadId(request.GetId())

	logger.GetDefaultLogger().Infof("✅ Created DID Exchange request with ID: %s", request.GetId())

	return request, connectionRecord, nil
}

// CreateResponse creates a DID Exchange response message
func (protocol *DidExchangeProtocol) CreateResponse(
	agentContext *context.AgentContext,
	connectionRecord *ConnectionRecord,
	outOfBandRecord interface{},
	routing interface{}, // Routing config - simplified for now
) (*DidExchangeResponseMessage, error) {
	logger.GetDefaultLogger().Infof("🔄 Creating DID Exchange response for connection %s", connectionRecord.ID)

	connectionRecord.State = ConnectionStateResponded
	connectionRecord.Role = "responder" // DID Exchange responder role

	// Create DID Exchange response message
	response := &DidExchangeResponseMessage{
		BaseMessage: messages.NewBaseMessage("https://didcomm.org/didexchange/1.1/response"),
		Did:         connectionRecord.Did, // Set our DID in the response
	}

	// Thread to the request
	if connectionRecord.Tags != nil && connectionRecord.Tags["threadId"] != "" {
		response.SetThreadId(connectionRecord.Tags["threadId"])
	}

	// Build DIDDoc and attach as signed did_doc~attach (JWS)
	if connectionRecord.MyKeyId != "" {
		if key, err := protocol.walletService.GetKey(connectionRecord.MyKeyId); err == nil && key != nil {
			endpoint := ""
			if protocol.connectionService != nil {
				endpoint = protocol.connectionService.GetDefaultServiceEndpoint()
			}
			doc := peer.CreatePeerDidDocument(key.PublicKey, endpoint)
			// Ensure the DID matches our connection DID if already set
			if connectionRecord.Did != "" {
				doc.Id = connectionRecord.Did
			}
			// Create JWS over the DIDDoc
			fingerprint, _ := peer.Ed25519Fingerprint(key.PublicKey)
			kid := "did:key:" + fingerprint
			var att interface{}
			if agentContext != nil && agentContext.DependencyManager != nil {
				if dm, ok := agentContext.DependencyManager.(di.DependencyManager); ok {
					if any, rerr := dm.Resolve(di.TokenJwsService); rerr == nil {
						if jwsSvc, ok := any.(*jws.JwsService); ok && jwsSvc != nil {
							att, err = jwsSvc.CreateSignedAttachment(agentContext, doc, connectionRecord.MyKeyId, kid)
						}
					}
				}
			}
			if err == nil && att != nil {
				if response.BaseMessage.AdditionalFields == nil {
					response.BaseMessage.AdditionalFields = make(map[string]interface{})
				}
				response.BaseMessage.AdditionalFields["did_doc~attach"] = att
			} else {
				// Fallback to unsigned attach if signing fails
				if b, mErr := json.Marshal(doc); mErr == nil {
					b64 := base64.RawURLEncoding.EncodeToString(b)
					attach := map[string]interface{}{
						"@id":       common.GenerateUUID(),
						"mime-type": "application/json",
						"data": map[string]interface{}{
							"base64": b64,
						},
					}
					if response.BaseMessage.AdditionalFields == nil {
						response.BaseMessage.AdditionalFields = make(map[string]interface{})
					}
					response.BaseMessage.AdditionalFields["did_doc~attach"] = attach
				}
			}
		}
	}

	logger.GetDefaultLogger().Info("✅ Created DID Exchange response")

	return response, nil
}

// CreateComplete creates a DID Exchange complete message
func (protocol *DidExchangeProtocol) CreateComplete(
	agentContext *context.AgentContext,
	connectionRecord *ConnectionRecord,
	outOfBandRecord interface{},
) (*DidExchangeCompleteMessage, error) {
	logger.GetDefaultLogger().Infof("🔄 Creating DID Exchange complete for connection %s", connectionRecord.ID)

	connectionRecord.State = ConnectionStateComplete

	// Create DID Exchange complete message
	complete := &DidExchangeCompleteMessage{
		BaseMessage: messages.NewBaseMessage("https://didcomm.org/didexchange/1.1/complete"),
	}

	// Thread to the original request
	if connectionRecord.Tags != nil && connectionRecord.Tags["threadId"] != "" {
		complete.SetThreadId(connectionRecord.Tags["threadId"])
	}

	logger.GetDefaultLogger().Info("✅ Created DID Exchange complete")

	return complete, nil
}

// ProcessRequest processes an incoming DID Exchange request
func (protocol *DidExchangeProtocol) ProcessRequest(
	agentContext *context.AgentContext,
	request *DidExchangeRequestMessage,
	outOfBandRecord interface{},
) (*ConnectionRecord, error) {
	logger.GetDefaultLogger().Infof("🔄 Processing DID Exchange request from: %s", request.GetLabel())

	// Create connection record for this request
	connectionId := common.GenerateUUID()
	connectionRecord := &ConnectionRecord{
		BaseRecord: &storage.BaseRecord{
			ID:   connectionId,
			Type: "ConnectionRecord",
			Tags: map[string]string{
				"threadId": request.GetThreadId(),
			},
		},
		State:      ConnectionStateRequested,
		Role:       "responder",
		Protocol:   "https://didcomm.org/didexchange/1.1",
		TheirLabel: request.GetLabel(),
	}

	logger.GetDefaultLogger().Infof("✅ Processed DID Exchange request, created connection %s", connectionId)

	return connectionRecord, nil
}

// ProcessResponse processes an incoming DID Exchange response
func (protocol *DidExchangeProtocol) ProcessResponse(
	agentContext *context.AgentContext,
	response *DidExchangeResponseMessage,
	connectionRecord *ConnectionRecord,
) error {
	logger.GetDefaultLogger().Infof("🔄 Processing DID Exchange response for connection %s", connectionRecord.ID)

	connectionRecord.State = ConnectionStateResponded

	logger.GetDefaultLogger().Info("✅ Processed DID Exchange response")

	return nil
}

// ProcessComplete processes an incoming DID Exchange complete message
func (protocol *DidExchangeProtocol) ProcessComplete(
	agentContext *context.AgentContext,
	complete *DidExchangeCompleteMessage,
	connectionRecord *ConnectionRecord,
) error {
	logger.GetDefaultLogger().Infof("🔄 Processing DID Exchange complete for connection %s", connectionRecord.ID)

	connectionRecord.State = ConnectionStateComplete

	logger.GetDefaultLogger().Info("✅ Processed DID Exchange complete - connection established")

	return nil
}

// CreateRequestConfig contains configuration for creating DID Exchange requests
type CreateRequestConfig struct {
	Label                string
	Alias                string
	AutoAcceptConnection bool
	OurDid               string
	// Routing and other config simplified for now
}

// DidExchangeRequestMessage represents a DID Exchange request message
type DidExchangeRequestMessage struct {
	*messages.BaseMessage
	Label        string               `json:"label"`
	Did          string               `json:"did"`
	DidDocAttach *messages.Attachment `json:"did_doc~attach,omitempty"`
}

func (m *DidExchangeRequestMessage) GetLabel() string {
	return m.Label
}

type DidExchangeResponseMessage struct {
	*messages.BaseMessage
	Did string `json:"did"`
}

// MarshalJSON implements custom JSON marshaling to include AdditionalFields
func (m *DidExchangeResponseMessage) MarshalJSON() ([]byte, error) {
	// Create a map with all the base message fields
	result := make(map[string]interface{})

	// Add the standard fields
	result["@id"] = m.BaseMessage.Id
	result["@type"] = m.BaseMessage.Type

	// Add optional fields if present
	if !m.BaseMessage.CreatedTime.IsZero() {
		result["created_time"] = m.BaseMessage.CreatedTime
	}
	if !m.BaseMessage.ExpiresTime.IsZero() {
		result["expires_time"] = m.BaseMessage.ExpiresTime
	}
	if m.BaseMessage.Thread != nil {
		result["~thread"] = m.BaseMessage.Thread
	}
	if m.BaseMessage.Transport != nil {
		result["~transport"] = m.BaseMessage.Transport
	}

	// Add the Did field
	if m.Did != "" {
		result["did"] = m.Did
	}

	// Add all additional fields (including did_doc~attach)
	for key, value := range m.BaseMessage.AdditionalFields {
		result[key] = value
	}

	return json.Marshal(result)
}

type DidExchangeCompleteMessage struct {
	*messages.BaseMessage
}
