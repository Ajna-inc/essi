package models

import (
	"time"
	
	"github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/core/di"
	"github.com/ajna-inc/essi/pkg/didcomm/messages"
	"github.com/ajna-inc/essi/pkg/didcomm/modules/connections/services"
)

// InboundMessageContext represents the context for processing an inbound message
type InboundMessageContext struct {
	Message      messages.AgentMessage      `json:"message"`
	Raw          []byte                     `json:"raw"`
	Connection   *services.ConnectionRecord `json:"connection,omitempty"`
	SessionID    string                     `json:"sessionId,omitempty"`
	ReceivedAt   time.Time                  `json:"receivedAt"`
	SenderKey    []byte                     `json:"senderKey,omitempty"`    // Public key of sender (for authcrypt)
	RecipientKey []byte                     `json:"recipientKey,omitempty"` // Public key used for decryption
	AgentContext *context.AgentContext      `json:"-"`
	TypedDI      di.DependencyManager       `json:"-"`
}