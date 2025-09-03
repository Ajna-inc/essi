package repository

import "github.com/ajna-inc/essi/pkg/didcomm/messages"

// DidCommMessageRole represents the role of a message
type DidCommMessageRole string

const (
	DidCommMessageRoleSender   DidCommMessageRole = "sender"
	DidCommMessageRoleReceiver DidCommMessageRole = "receiver"
)

// SaveMessageParams contains parameters for saving a message
type SaveMessageParams struct {
	AgentMessage       messages.AgentMessage
	Role               DidCommMessageRole
	AssociatedRecordId string
}

// GetMessageParams contains parameters for getting a message
type GetMessageParams struct {
	AssociatedRecordId string
	MessageClass       string
	Role               DidCommMessageRole
}

// DidCommMessageRepository handles storage of DIDComm messages
type DidCommMessageRepository struct {
	messages map[string]messages.AgentMessage
}

// NewDidCommMessageRepository creates a new repository
func NewDidCommMessageRepository() *DidCommMessageRepository {
	return &DidCommMessageRepository{
		messages: make(map[string]messages.AgentMessage),
	}
}

// SaveOrUpdateAgentMessage saves or updates a message
func (r *DidCommMessageRepository) SaveOrUpdateAgentMessage(params SaveMessageParams) error {
	// Simple implementation
	if params.AgentMessage != nil {
		r.messages[params.AssociatedRecordId] = params.AgentMessage
	}
	return nil
}

// GetAgentMessage gets a message
func (r *DidCommMessageRepository) GetAgentMessage(params GetMessageParams) messages.AgentMessage {
	// Simple implementation - in real code this would query storage
	return r.messages[params.AssociatedRecordId]
}