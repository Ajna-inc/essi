package messages

import (
	"encoding/json"
	"fmt"

	"github.com/ajna-inc/essi/pkg/didcomm/messages"
)

// TrustPingMessage represents a trust ping message
type TrustPingMessage struct {
	*messages.BaseMessage
	
	// Comment - optional human-readable message
	Comment string `json:"comment,omitempty"`
	
	// ResponseRequested - whether a response is requested
	ResponseRequested bool `json:"response_requested,omitempty"`
}

// TrustPingResponseMessage represents a trust ping response
type TrustPingResponseMessage struct {
	*messages.BaseMessage
	
	// Comment - optional human-readable message
	Comment string `json:"comment,omitempty"`
}

// Message type constants
const (
	TrustPingType         = "https://didcomm.org/trust_ping/1.0/ping"
	TrustPingResponseType = "https://didcomm.org/trust_ping/1.0/ping_response"
	
	// Legacy types
	TrustPingTypeV1_0         = "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/trust_ping/1.0/ping"
	TrustPingResponseTypeV1_0 = "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/trust_ping/1.0/ping_response"
)

// NewTrustPingMessage creates a new trust ping message
func NewTrustPingMessage(comment string, responseRequested bool) *TrustPingMessage {
	baseMessage := messages.NewBaseMessage(TrustPingType)
	
	return &TrustPingMessage{
		BaseMessage:       baseMessage,
		Comment:           comment,
		ResponseRequested: responseRequested,
	}
}

// NewTrustPingMessageWithId creates a new trust ping with specific ID
func NewTrustPingMessageWithId(id string, comment string, responseRequested bool) *TrustPingMessage {
	baseMessage := messages.NewBaseMessageWithId(id, TrustPingType)
	
	return &TrustPingMessage{
		BaseMessage:       baseMessage,
		Comment:           comment,
		ResponseRequested: responseRequested,
	}
}

// NewTrustPingResponseMessage creates a new trust ping response
func NewTrustPingResponseMessage(comment string) *TrustPingResponseMessage {
	baseMessage := messages.NewBaseMessage(TrustPingResponseType)
	
	return &TrustPingResponseMessage{
		BaseMessage: baseMessage,
		Comment:     comment,
	}
}

// NewTrustPingResponseFromPing creates a response from a ping message
func NewTrustPingResponseFromPing(ping *TrustPingMessage) *TrustPingResponseMessage {
	response := NewTrustPingResponseMessage("pong")
	
	// Set threading to reference the ping
	if ping.GetThreadId() != "" {
		response.SetThreadId(ping.GetThreadId())
	} else {
		response.SetThreadId(ping.GetId())
	}
	
	return response
}

// Trust Ping Message Methods

// SetComment sets the comment
func (m *TrustPingMessage) SetComment(comment string) {
	m.Comment = comment
}

// GetComment returns the comment
func (m *TrustPingMessage) GetComment() string {
	return m.Comment
}

// SetResponseRequested sets whether a response is requested
func (m *TrustPingMessage) SetResponseRequested(requested bool) {
	m.ResponseRequested = requested
}

// GetResponseRequested returns whether a response is requested
func (m *TrustPingMessage) GetResponseRequested() bool {
	return m.ResponseRequested
}

// Validate validates the trust ping message
func (m *TrustPingMessage) Validate() error {
	return m.BaseMessage.Validate()
}

// ToJSON converts the ping to JSON
func (m *TrustPingMessage) ToJSON() ([]byte, error) {
	return json.Marshal(m)
}

// FromJSON populates the ping from JSON
func (m *TrustPingMessage) FromJSON(data []byte) error {
	return json.Unmarshal(data, m)
}

// Clone creates a deep copy of the message
func (m *TrustPingMessage) Clone() messages.MessageInterface {
	clone := &TrustPingMessage{
		BaseMessage:       m.BaseMessage.Clone().(*messages.BaseMessage),
		Comment:           m.Comment,
		ResponseRequested: m.ResponseRequested,
	}
	
	return clone
}

// Trust Ping Response Message Methods

// SetComment sets the comment on the response
func (m *TrustPingResponseMessage) SetComment(comment string) {
	m.Comment = comment
}

// GetComment returns the comment from the response
func (m *TrustPingResponseMessage) GetComment() string {
	return m.Comment
}

// Validate validates the trust ping response message
func (m *TrustPingResponseMessage) Validate() error {
	if err := m.BaseMessage.Validate(); err != nil {
		return err
	}
	
	// Response should have a thread ID
	if m.GetThreadId() == "" {
		return fmt.Errorf("trust ping response must reference a thread")
	}
	
	return nil
}

// ToJSON converts the response to JSON
func (m *TrustPingResponseMessage) ToJSON() ([]byte, error) {
	return json.Marshal(m)
}

// FromJSON populates the response from JSON
func (m *TrustPingResponseMessage) FromJSON(data []byte) error {
	return json.Unmarshal(data, m)
}

// Clone creates a deep copy of the message
func (m *TrustPingResponseMessage) Clone() messages.MessageInterface {
	clone := &TrustPingResponseMessage{
		BaseMessage: m.BaseMessage.Clone().(*messages.BaseMessage),
		Comment:     m.Comment,
	}
	
	return clone
}