package models

import (
	"fmt"
	
	"github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/didcomm/messages"
	"github.com/ajna-inc/essi/pkg/didcomm/modules/connections/services"
	"github.com/ajna-inc/essi/pkg/didcomm/modules/oob"
)

// ServiceMessageParams contains parameters for sending service messages
type ServiceMessageParams struct {
	SenderKey    string                // The sender's public key
	Service      *ResolvedDidCommService // The resolved DIDComm service
	ReturnRoute  bool                  // Whether to request return routing
}

// ResolvedDidCommService represents a resolved DIDComm service endpoint
type ResolvedDidCommService struct {
	ID              string   // Service ID
	ServiceEndpoint string   // The service endpoint URL
	RecipientKeys   []string // Recipient public keys
	RoutingKeys     []string // Routing keys for mediators
}

// OutboundMessageContextParams contains parameters for creating an outbound context
type OutboundMessageContextParams struct {
	AgentContext          *context.AgentContext
	InboundMessageContext *InboundMessageContext
	AssociatedRecord      interface{} // Any record associated with this message
	Connection            *services.ConnectionRecord
	ServiceParams         *ServiceMessageParams
	OutOfBand             *oob.OutOfBandRecord
	SessionID             string
}

// OutboundMessageContext represents the context for an outbound message
type OutboundMessageContext struct {
	Message               messages.AgentMessage
	Connection            *services.ConnectionRecord
	ServiceParams         *ServiceMessageParams
	OutOfBand             *oob.OutOfBandRecord
	AssociatedRecord      interface{}
	SessionID             string
	InboundMessageContext *InboundMessageContext
	AgentContext          *context.AgentContext
}

// NewOutboundMessageContext creates a new outbound message context
func NewOutboundMessageContext(message messages.AgentMessage, params OutboundMessageContextParams) *OutboundMessageContext {
	return &OutboundMessageContext{
		Message:               message,
		Connection:            params.Connection,
		SessionID:             params.SessionID,
		OutOfBand:             params.OutOfBand,
		ServiceParams:         params.ServiceParams,
		AssociatedRecord:      params.AssociatedRecord,
		InboundMessageContext: params.InboundMessageContext,
		AgentContext:          params.AgentContext,
	}
}

// AssertReadyConnection asserts the outbound message has a ready connection associated with it
func (ctx *OutboundMessageContext) AssertReadyConnection() (*services.ConnectionRecord, error) {
	if ctx.Connection == nil {
		return nil, fmt.Errorf("no connection associated with outgoing message %s", ctx.Message.GetType())
	}
	
	// Make sure connection is ready (at least responded state)
	if ctx.Connection.State != services.ConnectionStateResponded && 
	   ctx.Connection.State != services.ConnectionStateComplete {
		return nil, fmt.Errorf("connection %s is not ready (state: %s)", ctx.Connection.ID, ctx.Connection.State)
	}
	
	return ctx.Connection, nil
}

// IsOutboundServiceMessage checks if this is an outbound service message
func (ctx *OutboundMessageContext) IsOutboundServiceMessage() bool {
	return ctx.ServiceParams != nil && ctx.ServiceParams.Service != nil
}