package services

import (
	"fmt"
	"log"
	
	"github.com/ajna-inc/essi/pkg/core/context"
	connmessages "github.com/ajna-inc/essi/pkg/didcomm/modules/connections/messages"
)

// TrustPingService handles Trust Ping Protocol operations as defined in RFC 0048
// This follows the same pattern as credo-ts TrustPingService
type TrustPingService struct {
	connectionService *ConnectionService
}

// NewTrustPingService creates a new Trust Ping service
func NewTrustPingService(connectionService *ConnectionService) *TrustPingService {
	return &TrustPingService{
		connectionService: connectionService,
	}
}

// CreatePing creates a trust ping message for a connection
func (service *TrustPingService) CreatePing(
	agentContext *context.AgentContext,
	connection *ConnectionRecord,
	config *TrustPingConfig,
) (*connmessages.TrustPingMessage, error) {
	log.Printf("🏓 Creating trust ping for connection %s", connection.ID)
	
	comment := "ping"
	if config != nil && config.Comment != "" {
		comment = config.Comment
	}
	
	responseRequested := true
	if config != nil {
		responseRequested = config.ResponseRequested
	}
	
	// Create trust ping message
	ping := connmessages.NewTrustPingMessage(comment, responseRequested)
	
	// Set threading if we have a thread context
	if connection.Tags != nil && connection.Tags["threadId"] != "" {
		ping.SetThreadId(connection.Tags["threadId"])
	}
	
	log.Printf("✅ Created trust ping message with comment: %s", comment)
	
	return ping, nil
}

// CreatePingResponse creates a trust ping response message
func (service *TrustPingService) CreatePingResponse(
	agentContext *context.AgentContext,
	ping *connmessages.TrustPingMessage,
	connection *ConnectionRecord,
) (*connmessages.TrustPingResponseMessage, error) {
	log.Printf("🏓 Creating trust ping response for connection %s", connection.ID)
	
	// Create response using the factory method from the ping message
	response := connmessages.NewTrustPingResponseFromPing(ping)
	
	log.Printf("✅ Created trust ping response")
	
	return response, nil
}

// ProcessPing processes an incoming trust ping message
func (service *TrustPingService) ProcessPing(
	agentContext *context.AgentContext,
	ping *connmessages.TrustPingMessage,
	connection *ConnectionRecord,
) (*connmessages.TrustPingResponseMessage, error) {
	log.Printf("🏓 Processing trust ping from connection %s (response_requested=%v)", 
		connection.ID, ping.GetResponseRequested())
	
	// Update connection state if needed
	if connection.State != ConnectionStateComplete {
		connection.State = ConnectionStateComplete
		if err := service.connectionService.UpdateConnection(connection); err != nil {
			log.Printf("⚠️ Failed to update connection state: %v", err)
		} else {
			log.Printf("✅ Connection %s marked as complete after trust ping", connection.ID)
		}
	}
	
	// Create response if requested
	if ping.GetResponseRequested() {
		response, err := service.CreatePingResponse(agentContext, ping, connection)
		if err != nil {
			return nil, fmt.Errorf("failed to create ping response: %w", err)
		}
		return response, nil
	}
	
	return nil, nil
}

// ProcessPingResponse processes an incoming trust ping response
func (service *TrustPingService) ProcessPingResponse(
	agentContext *context.AgentContext,
	response *connmessages.TrustPingResponseMessage,
	connection *ConnectionRecord,
) error {
	log.Printf("🏓✅ Processing trust ping response from connection %s", connection.ID)
	
	// Update connection state to complete if not already
	if connection.State != ConnectionStateComplete {
		connection.State = ConnectionStateComplete
		if err := service.connectionService.UpdateConnection(connection); err != nil {
			log.Printf("⚠️ Failed to update connection state: %v", err)
			return err
		} else {
			log.Printf("✅ Connection %s marked as complete after ping response", connection.ID)
		}
	}
	
	return nil
}

// TrustPingConfig contains configuration for creating trust ping messages
type TrustPingConfig struct {
	Comment           string
	ResponseRequested bool
}