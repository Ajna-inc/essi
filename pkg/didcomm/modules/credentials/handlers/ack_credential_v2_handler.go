package handlers

import (
	"log"

	"github.com/ajna-inc/essi/pkg/core/context"
	credmsgs "github.com/ajna-inc/essi/pkg/didcomm/modules/credentials/messages"
	credsvc "github.com/ajna-inc/essi/pkg/didcomm/modules/credentials/services"
)

// AckCredentialV2Handler handles credential acknowledgment messages
type AckCredentialV2Handler struct {
	service *credsvc.CredentialService
}

// NewAckCredentialV2Handler creates a new ACK handler
func NewAckCredentialV2Handler(service *credsvc.CredentialService) *AckCredentialV2Handler {
	return &AckCredentialV2Handler{service: service}
}

// Handle processes incoming ACK messages
func (h *AckCredentialV2Handler) Handle(ctx *context.AgentContext, msg interface{}, connectionId string) (interface{}, error) {
	ack, ok := msg.(*credmsgs.AckCredentialV2)
	if !ok {
		log.Printf("Invalid message type for AckCredentialV2Handler")
		return nil, nil
	}

	// Get thread ID from the message
	thid := ack.GetThreadId()
	if thid == "" {
		thid = ack.GetId()
	}

	log.Printf("✅ Received ACK for credential exchange %s with status: %s", thid, ack.Status)

	// Mark the credential exchange as complete
	if err := h.service.MarkDone(thid); err != nil {
		log.Printf("Warning: Failed to mark credential exchange as done: %v", err)
		// Don't fail the handler - ACK is informational
	}

	// No response needed for ACK
	return nil, nil
}

// MessageType returns the message type this handler processes
func (h *AckCredentialV2Handler) MessageType() string {
	return credmsgs.AckCredentialV2Type
}