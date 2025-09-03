package handlers

import (
	"fmt"

	coreevents "github.com/ajna-inc/essi/pkg/core/events"
	"github.com/ajna-inc/essi/pkg/core/logger"
	"github.com/ajna-inc/essi/pkg/core/common"
	"github.com/ajna-inc/essi/pkg/core/wallet"
	"github.com/ajna-inc/essi/pkg/didcomm/decorators/signature"
	"github.com/ajna-inc/essi/pkg/didcomm/messages"
	"github.com/ajna-inc/essi/pkg/didcomm/models"
	connmessages "github.com/ajna-inc/essi/pkg/didcomm/modules/connections/messages"
	services "github.com/ajna-inc/essi/pkg/didcomm/modules/connections/services"
	outboundServices "github.com/ajna-inc/essi/pkg/didcomm/services"
	"github.com/ajna-inc/essi/pkg/didcomm/transport"
)

// Internal trust ping message type for connection handlers
type trustPingMessageInternal struct {
	*messages.BaseMessage
	Comment           string `json:"comment,omitempty"`
	ResponseRequested bool   `json:"response_requested,omitempty"`
}

// ConnectionRequestHandlerFunc handles `connections/1.0/request` messages.
func ConnectionRequestHandlerFunc(ctx *transport.InboundMessageContext) (*models.OutboundMessageContext, error) {
	logger.GetDefaultLogger().Info("🤝 (dispatcher) processing connection request")

	msg := &connmessages.ConnectionRequestMessage{}
	if err := msg.FromJSON(ctx.Raw); err != nil {
		return nil, err
	}

	connectionSvc := getConnectionService(ctx)
	if connectionSvc == nil {
		return nil, fmt.Errorf("connection service not configured")
	}

	walletService := getWalletService(ctx)
	if walletService == nil {
		return nil, fmt.Errorf("wallet service not configured")
	}

	messageSender := getMessageSender(ctx)
	if messageSender == nil {
		return nil, fmt.Errorf("message sender not configured")
	}

	// Create a new connection record for the incoming request
	connectionRecord := services.NewConnectionRecord(common.GenerateUUID())
	connectionRecord.State = services.ConnectionStateRequested
	connectionRecord.Role = "responder"
	connectionRecord.TheirDid = msg.GetDid()
	connectionRecord.TheirLabel = msg.GetLabel()
	connectionRecord.OutOfBandId = msg.GetThreadId()
	connectionRecord.Tags["threadId"] = msg.GetThreadId()

	// Extract endpoint from their DID document
	if msg.Connection != nil && msg.Connection.DidDoc != nil {
		logger.GetDefaultLogger().Debug("📋 Processing DID Document from request")
		for _, service := range msg.Connection.DidDoc.Service {
			if endpoint, ok := service.ServiceEndpoint.(string); ok {
				connectionRecord.TheirEndpoint = endpoint
				logger.GetDefaultLogger().Infof("✅ Found their endpoint: %s", endpoint)
				break
			}
		}
		// Also store their primary recipient key for routing/authcrypt
		if len(msg.Connection.DidDoc.PublicKey) > 0 && msg.Connection.DidDoc.PublicKey[0].PublicKeyBase58 != "" {
			connectionRecord.TheirRecipientKey = msg.Connection.DidDoc.PublicKey[0].PublicKeyBase58
			logger.GetDefaultLogger().Infof("✅ Found their recipient key: %s", connectionRecord.TheirRecipientKey)
		}
	}

	// Save the connection record
	if err := connectionSvc.SaveConnection(connectionRecord); err != nil {
		logger.GetDefaultLogger().Errorf("Failed to save connection record: %v", err)
		return nil, fmt.Errorf("failed to save connection record: %w", err)
	}

	logger.GetDefaultLogger().Infof("✅ Created connection record %s for %s", connectionRecord.ID, connectionRecord.TheirLabel)

	// Emit event: connection state changed to requested
	if bus := getEventBus(ctx); bus != nil {
		bus.Publish(coreevents.EventConnectionStateChanged, map[string]interface{}{
			"connectionId": connectionRecord.ID,
			"state":        string(services.ConnectionStateRequested),
		})
	}

	// Create our key for the connection
	ourKey, err := walletService.CreateKey(wallet.KeyTypeEd25519)
	if err != nil {
		logger.GetDefaultLogger().Errorf("Failed to create key: %v", err)
		return nil, fmt.Errorf("failed to create key: %w", err)
	}

	// Create our peer DID
	ourDid, err := createPeerDidFromKey(ourKey.PublicKey)
	if err != nil {
		logger.GetDefaultLogger().Errorf("Failed to create peer DID: %v", err)
		return nil, fmt.Errorf("failed to create peer DID: %w", err)
	}

	// Get service endpoint - prefer agent configured endpoint if available
	serviceEndpoint := ""
	if connectionSvc != nil {
		serviceEndpoint = connectionSvc.GetDefaultServiceEndpoint()
	}

	// Create our DID document (Aries-style DidDoc)
	ourDidDoc, err := createDidDocumentForPeerDid(ourDid, ourKey.PublicKey, serviceEndpoint)
	if err != nil {
		logger.GetDefaultLogger().Errorf("Failed to create DID document: %v", err)
		return nil, fmt.Errorf("failed to create DID document: %w", err)
	}

	// Update our connection record
	connectionRecord.Did = ourDid
	connectionRecord.MyKeyId = ourKey.Id
	connectionRecord.State = services.ConnectionStateResponded
	if err := connectionSvc.UpdateConnection(connectionRecord); err != nil {
		logger.GetDefaultLogger().Errorf("Failed to update connection record: %v", err)
		return nil, fmt.Errorf("failed to update connection record: %w", err)
	}

	// Create connection object for signing
	connectionData := &connmessages.ConnectionInfo{
		Did:    ourDid,
		DidDoc: ourDidDoc,
	}

	// Use our current key for signing (legacy invitationKeys cache removed)
	signingKey := ourKey

	// Create signature for the connection data
	connectionSig, err := signature.CreateSignature(connectionData, signingKey)
	if err != nil {
		logger.GetDefaultLogger().Errorf("Failed to create signature: %v", err)
		return nil, fmt.Errorf("failed to create signature: %w", err)
	}

	// Create connection response
	// Per RFC 0160 and Credo-TS, response must be threaded to the request (thid=request.id)
	response := connmessages.CreateConnectionResponseWithSignature(msg.GetThreadId(), connectionSig)

	logger.GetDefaultLogger().Infof("✅ Created connection response with DID: %s", ourDid)
	logger.GetDefaultLogger().Infof("📤 Preparing connection response for thread: %s", msg.GetThreadId())

	// Respect auto-accept configuration
	autoAccept := false
	if ctx != nil && ctx.AgentContext != nil && ctx.AgentContext.Config != nil {
		autoAccept = ctx.AgentContext.Config.AutoAcceptConnections || connectionRecord.AutoAcceptConnection
	}
	if !autoAccept {
		return nil, nil
	}

	// Create outbound context for the response
	if connectionRecord.TheirEndpoint != "" {
		outboundCtx, err := outboundServices.GetOutboundMessageContext(
			ctx.AgentContext,
			outboundServices.GetOutboundMessageContextParams{
				Message:             response,
				ConnectionRecord:    connectionRecord,
				AssociatedRecord:    connectionRecord,
				LastReceivedMessage: msg,
			},
		)
		if err != nil {
			logger.GetDefaultLogger().Errorf("Failed to create outbound context: %v", err)
			return nil, err
		}

		// Emit message sent event (will be sent by dispatcher)
		if bus := getEventBus(ctx); bus != nil {
			bus.Publish(coreevents.EventMessageSent, map[string]interface{}{
				"type": response.GetType(),
				"thid": response.GetThreadId(),
			})
		}

		return outboundCtx, nil
	}

	// No endpoint, return nil
	return nil, nil
}

// ConnectionResponseHandlerFunc handles `connections/1.0/response` messages.
func ConnectionResponseHandlerFunc(ctx *transport.InboundMessageContext) (*models.OutboundMessageContext, error) {
	logger.GetDefaultLogger().Info("🤝 (dispatcher) processing connection response")

	msg := &connmessages.ConnectionResponseMessage{}
	if err := msg.FromJSON(ctx.Raw); err != nil {
		return nil, err
	}

	connectionSvc := getConnectionService(ctx)
	if connectionSvc == nil {
		return nil, fmt.Errorf("connection service not configured")
	}

	// Verify and extract connection from signature
	connection, err := msg.GetConnectionFromSignature()
	if err != nil {
		logger.GetDefaultLogger().Errorf("Failed to verify connection signature: %v", err)
		return nil, fmt.Errorf("failed to verify connection signature: %w", err)
	}

	// Find the connection record by the request thread id (thid) we stored on the record tags
	threadID := msg.GetThreadId()
	if threadID == "" {
		return nil, fmt.Errorf("no thread ID in connection response")
	}

	var connectionRecord *services.ConnectionRecord
	all, err := connectionSvc.GetAllConnections()
	if err != nil {
		return nil, fmt.Errorf("failed to list connections: %w", err)
	}
	for _, rec := range all {
		if rec != nil && rec.Tags != nil && rec.Tags["threadId"] == threadID {
			connectionRecord = rec
			break
		}
	}
	if connectionRecord == nil {
		return nil, fmt.Errorf("connection record for thread %s not found", threadID)
	}

	// Update connection record with their DID
	connectionRecord.TheirDid = connection.Did
	connectionRecord.State = services.ConnectionStateResponded

	// Extract their endpoint from DIDDoc; keep InvitationKey from OOB service for routing parity with TS
	if connection.DidDoc != nil {
		for _, service := range connection.DidDoc.Service {
			if endpoint, ok := service.ServiceEndpoint.(string); ok && endpoint != "" {
				connectionRecord.TheirEndpoint = endpoint
				break
			}
		}
		// Persist peer DID doc primary public key for future routing/association
		if len(connection.DidDoc.PublicKey) > 0 && connection.DidDoc.PublicKey[0].PublicKeyBase58 != "" {
			connectionRecord.TheirRecipientKey = connection.DidDoc.PublicKey[0].PublicKeyBase58
		}
	}

	if err := connectionSvc.UpdateConnection(connectionRecord); err != nil {
		logger.GetDefaultLogger().Errorf("Failed to update connection record: %v", err)
		return nil, fmt.Errorf("failed to update connection record: %w", err)
	}

	// Emit event: connection state changed to responded
	if bus := getEventBus(ctx); bus != nil {
		bus.Publish(coreevents.EventConnectionStateChanged, map[string]interface{}{
			"connectionId": connectionRecord.ID,
			"state":        string(services.ConnectionStateResponded),
		})
	}

	// Conditional trust ping for auto-accept
	autoAccept := false
	if ctx != nil && ctx.AgentContext != nil && ctx.AgentContext.Config != nil {
		autoAccept = ctx.AgentContext.Config.AutoAcceptConnections || connectionRecord.AutoAcceptConnection
	}
	if !autoAccept {
		return nil, nil
	}

	// Create trust ping to move requester/responder to completed state on TS side
	ping := &trustPingMessageInternal{
		BaseMessage:       messages.NewBaseMessage("https://didcomm.org/trust_ping/1.0/ping"),
		Comment:           "ping",
		ResponseRequested: true,
	}
	// Thread ping to the same thread as the connection
	ping.SetThreadId(threadID)

	logger.GetDefaultLogger().Info("✅ Connection established successfully!")
	logger.GetDefaultLogger().Infof("   - Our DID: %s", connectionRecord.Did)
	logger.GetDefaultLogger().Infof("   - Their DID: %s", connectionRecord.TheirDid)
	logger.GetDefaultLogger().Infof("   - State: %s", connectionRecord.State)

	// Create outbound context for trust ping
	outboundCtx, err := outboundServices.GetOutboundMessageContext(
		ctx.AgentContext,
		outboundServices.GetOutboundMessageContextParams{
			Message:             ping,
			ConnectionRecord:    connectionRecord,
			AssociatedRecord:    nil,
			LastReceivedMessage: msg,
		},
	)
	if err != nil {
		logger.GetDefaultLogger().Warnf("Failed to create trust ping context: %v", err)
		// Don't fail the handler, just log
		return nil, nil
	}

	return outboundCtx, nil
}

// ConnectionAckHandlerFunc handles connection ACK messages
func ConnectionAckHandlerFunc(ctx *transport.InboundMessageContext) (*models.OutboundMessageContext, error) {
	logger.GetDefaultLogger().Info("🤝 Processing connection ACK")

	msg := &connmessages.ConnectionAckMessage{}
	if err := msg.FromJSON(ctx.Raw); err != nil {
		return nil, fmt.Errorf("failed to parse connection ACK: %w", err)
	}

	connectionSvc := getConnectionService(ctx)
	if connectionSvc == nil {
		return nil, fmt.Errorf("connection service not configured")
	}

	// Find the connection by thread ID
	threadID := msg.GetThreadId()
	if threadID == "" {
		return nil, fmt.Errorf("connection ACK must have a thread ID")
	}

	var connectionRecord *services.ConnectionRecord
	all, err := connectionSvc.GetAllConnections()
	if err != nil {
		return nil, fmt.Errorf("failed to list connections: %w", err)
	}

	for _, rec := range all {
		if rec != nil && rec.Tags != nil && rec.Tags["threadId"] == threadID {
			connectionRecord = rec
			break
		}
	}

	if connectionRecord == nil {
		return nil, fmt.Errorf("connection record for thread %s not found", threadID)
	}

	// Update connection state to complete
	connectionRecord.State = services.ConnectionStateComplete
	if err := connectionSvc.UpdateConnection(connectionRecord); err != nil {
		logger.GetDefaultLogger().Errorf("Failed to update connection record: %v", err)
		return nil, fmt.Errorf("failed to update connection record: %w", err)
	}

	// Emit event: connection state changed to complete
	if bus := getEventBus(ctx); bus != nil {
		bus.Publish(coreevents.EventConnectionStateChanged, map[string]interface{}{
			"connectionId": connectionRecord.ID,
			"state":        string(services.ConnectionStateComplete),
		})
	}

	logger.GetDefaultLogger().Infof("✅ Connection ACK processed - connection %s marked as complete", connectionRecord.ID)

	// No response needed for ACK
	return nil, nil
}

