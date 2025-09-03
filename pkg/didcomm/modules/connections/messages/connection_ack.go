package messages

import (
	"encoding/json"
	"fmt"

	"github.com/ajna-inc/essi/pkg/didcomm/messages"
)

// ConnectionAckMessage represents a connection acknowledgment message
type ConnectionAckMessage struct {
	*messages.BaseMessage
	
	// Optional status field
	Status string `json:"status,omitempty"`
}

// Message type constants
const (
	ConnectionAckType     = "https://didcomm.org/connections/1.0/ack"
	ConnectionAckTypeV1_0 = "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/connections/1.0/ack"
)

// NewConnectionAckMessage creates a new connection ACK message
func NewConnectionAckMessage() *ConnectionAckMessage {
	baseMessage := messages.NewBaseMessage(ConnectionAckType)
	
	return &ConnectionAckMessage{
		BaseMessage: baseMessage,
		Status:      "OK",
	}
}

// NewConnectionAckMessageWithId creates a new connection ACK with specific ID
func NewConnectionAckMessageWithId(id string) *ConnectionAckMessage {
	baseMessage := messages.NewBaseMessageWithId(id, ConnectionAckType)
	
	return &ConnectionAckMessage{
		BaseMessage: baseMessage,
		Status:      "OK",
	}
}

// NewConnectionAckFromMessage creates an ACK message from another message
func NewConnectionAckFromMessage(originalMessage messages.MessageInterface) *ConnectionAckMessage {
	ack := NewConnectionAckMessage()
	
	// Set threading to reference the original message
	if originalMessage.GetThreadId() != "" {
		ack.SetThreadId(originalMessage.GetThreadId())
	} else {
		ack.SetThreadId(originalMessage.GetId())
	}
	
	return ack
}

// SetStatus sets the status of the ACK
func (m *ConnectionAckMessage) SetStatus(status string) {
	m.Status = status
}

// GetStatus returns the status of the ACK
func (m *ConnectionAckMessage) GetStatus() string {
	return m.Status
}

// Validate validates the connection ACK message
func (m *ConnectionAckMessage) Validate() error {
	if err := m.BaseMessage.Validate(); err != nil {
		return err
	}
	
	// ACK messages should have a thread ID
	if m.GetThreadId() == "" {
		return fmt.Errorf("connection ACK must reference a thread")
	}
	
	return nil
}

// ToJSON converts the ACK to JSON
func (m *ConnectionAckMessage) ToJSON() ([]byte, error) {
	return json.Marshal(m)
}

// FromJSON populates the ACK from JSON
func (m *ConnectionAckMessage) FromJSON(data []byte) error {
	return json.Unmarshal(data, m)
}

// Clone creates a deep copy of the message
func (m *ConnectionAckMessage) Clone() messages.MessageInterface {
	clone := &ConnectionAckMessage{
		BaseMessage: m.BaseMessage.Clone().(*messages.BaseMessage),
		Status:      m.Status,
	}
	
	return clone
}