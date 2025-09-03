package services

import (
	"fmt"
	"log"
	
	"github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/core/common"
	"github.com/ajna-inc/essi/pkg/didcomm/messages"
)

// DidRotateService handles DID Rotation Protocol operations as defined in RFC 0794
// This follows the same pattern as credo-ts DidRotateService
type DidRotateService struct {
	connectionService *ConnectionService
}

// NewDidRotateService creates a new DID Rotate service
func NewDidRotateService(connectionService *ConnectionService) *DidRotateService {
	return &DidRotateService{
		connectionService: connectionService,
	}
}

// CreateRotate creates a DID rotation message
func (service *DidRotateService) CreateRotate(
	agentContext *context.AgentContext,
	config *CreateRotateConfig,
) (*DidRotateMessage, error) {
	log.Printf("🔄 Creating DID rotation for connection %s", config.Connection.ID)
	
	// Generate new DID if not provided
	toDid := config.ToDid
	if toDid == "" {
		// Generate new peer DID - simplified for now
		toDid = fmt.Sprintf("did:peer:0z%s", common.GenerateUUID()[:20])
	}
	
	// Create DID rotate message
	rotate := &DidRotateMessage{
		BaseMessage: messages.NewBaseMessage("https://didcomm.org/did-rotate/1.0/rotate"),
		ToDid:       toDid,
	}
	
	// Update connection record with new DID
	connection := config.Connection
	if connection.PreviousDids == nil {
		connection.PreviousDids = []string{}
	}
	if connection.Did != "" {
		connection.PreviousDids = append(connection.PreviousDids, connection.Did)
	}
	connection.Did = toDid
	
	if err := service.connectionService.UpdateConnection(connection); err != nil {
		return nil, fmt.Errorf("failed to update connection with new DID: %w", err)
	}
	
	log.Printf("✅ Created DID rotation message - rotating to DID: %s", toDid)
	
	return rotate, nil
}

// CreateRotateAck creates a DID rotation acknowledgment message
func (service *DidRotateService) CreateRotateAck(
	agentContext *context.AgentContext,
	rotate *DidRotateMessage,
	connection *ConnectionRecord,
) (*DidRotateAckMessage, error) {
	log.Printf("🔄 Creating DID rotation ACK for connection %s", connection.ID)
	
	ack := &DidRotateAckMessage{
		BaseMessage: messages.NewBaseMessage("https://didcomm.org/did-rotate/1.0/ack"),
	}
	
	// Thread to the rotate message
	ack.SetThreadId(rotate.GetThreadId())
	
	log.Printf("✅ Created DID rotation ACK")
	
	return ack, nil
}

// CreateHangup creates a hangup message to terminate a connection
func (service *DidRotateService) CreateHangup(
	agentContext *context.AgentContext,
	config *CreateHangupConfig,
) (*HangupMessage, error) {
	log.Printf("🔄 Creating hangup for connection %s", config.Connection.ID)
	
	hangup := &HangupMessage{
		BaseMessage: messages.NewBaseMessage("https://didcomm.org/did-rotate/1.0/hangup"),
	}
	
	// Update connection state to abandoned
	connection := config.Connection
	connection.State = ConnectionStateAbandoned
	
	if err := service.connectionService.UpdateConnection(connection); err != nil {
		log.Printf("⚠️ Failed to update connection state to abandoned: %v", err)
	}
	
	log.Printf("✅ Created hangup message - connection will be terminated")
	
	return hangup, nil
}

// ProcessRotate processes an incoming DID rotation message
func (service *DidRotateService) ProcessRotate(
	agentContext *context.AgentContext,
	rotate *DidRotateMessage,
	connection *ConnectionRecord,
) (*DidRotateAckMessage, error) {
	log.Printf("🔄 Processing DID rotation for connection %s", connection.ID)
	
	// Store their previous DID
	if connection.PreviousTheirDids == nil {
		connection.PreviousTheirDids = []string{}
	}
	if connection.TheirDid != "" {
		connection.PreviousTheirDids = append(connection.PreviousTheirDids, connection.TheirDid)
	}
	
	// Update their DID
	connection.TheirDid = rotate.GetToDid()
	
	if err := service.connectionService.UpdateConnection(connection); err != nil {
		return nil, fmt.Errorf("failed to update connection with their new DID: %w", err)
	}
	
	ack, err := service.CreateRotateAck(agentContext, rotate, connection)
	if err != nil {
		return nil, fmt.Errorf("failed to create rotate ACK: %w", err)
	}
	
	log.Printf("✅ Processed DID rotation - their new DID: %s", rotate.GetToDid())
	
	return ack, nil
}

// ProcessRotateAck processes an incoming DID rotation acknowledgment
func (service *DidRotateService) ProcessRotateAck(
	agentContext *context.AgentContext,
	ack *DidRotateAckMessage,
	connection *ConnectionRecord,
) error {
	log.Printf("✅ Processing DID rotation ACK for connection %s", connection.ID)
	
	// DID rotation is now complete
	log.Printf("✅ DID rotation completed successfully")
	
	return nil
}

// ProcessHangup processes an incoming hangup message
func (service *DidRotateService) ProcessHangup(
	agentContext *context.AgentContext,
	hangup *HangupMessage,
	connection *ConnectionRecord,
) error {
	log.Printf("📞 Processing hangup for connection %s", connection.ID)
	
	// Update connection state to abandoned
	connection.State = ConnectionStateAbandoned
	
	if err := service.connectionService.UpdateConnection(connection); err != nil {
		log.Printf("⚠️ Failed to update connection state: %v", err)
		return err
	}
	
	log.Printf("✅ Connection %s terminated via hangup", connection.ID)
	
	return nil
}

// Configuration types
type CreateRotateConfig struct {
	Connection *ConnectionRecord
	ToDid      string
	// Routing config simplified for now
}

type CreateHangupConfig struct {
	Connection *ConnectionRecord
}

// Placeholder message types - these will be implemented properly
type DidRotateMessage struct {
	*messages.BaseMessage
	ToDid string `json:"to_did"`
}

func (m *DidRotateMessage) GetToDid() string {
	return m.ToDid
}

type DidRotateAckMessage struct {
	*messages.BaseMessage
}

type HangupMessage struct {
	*messages.BaseMessage
}