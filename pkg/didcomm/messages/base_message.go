package messages

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// BaseMessage represents the base structure for all DIDComm messages
type BaseMessage struct {
	// Required fields according to DIDComm spec
	Id   string `json:"@id"`
	Type string `json:"@type"`

	// Optional fields
	From        string                 `json:"from,omitempty"`
	To          []string               `json:"to,omitempty"`
	CreatedTime time.Time              `json:"created_time,omitempty"`
	ExpiresTime time.Time              `json:"expires_time,omitempty"`
	Body        map[string]interface{} `json:"body,omitempty"`

	// DIDComm decorators
	Thread     *ThreadDecorator       `json:"~thread,omitempty"`
	Transport  *TransportDecorator    `json:"~transport,omitempty"`
	L10n       *L10nDecorator         `json:"~l10n,omitempty"`
	Timing     *TimingDecorator       `json:"~timing,omitempty"`
	Service    *ServiceDecorator      `json:"~service,omitempty"`
	Attachment []*AttachmentDecorator `json:"~attachment,omitempty"`

	// Additional fields for extensibility
	AdditionalFields map[string]interface{} `json:"-"`
}

// ThreadDecorator represents the thread decorator
type ThreadDecorator struct {
	Thid           string   `json:"thid,omitempty"`
	Pthid          string   `json:"pthid,omitempty"`
	SenderOrder    int      `json:"sender_order,omitempty"`
	ReceivedOrders []string `json:"received_orders,omitempty"`
	GoalCode       string   `json:"goal_code,omitempty"`
	Goal           string   `json:"goal,omitempty"`
	ParentThreadId string   `json:"parent_thread_id,omitempty"`
}

// TransportDecorator represents the transport decorator
type TransportDecorator struct {
	ReturnRoute             string `json:"return_route,omitempty"`
	ReturnRouteThread       string `json:"return_route_thread,omitempty"`
	QueuedTransportResponse string `json:"queued_transport_response,omitempty"`
}

// Return route constants
const (
	ReturnRouteNone   = "none"
	ReturnRouteAll    = "all"
	ReturnRouteThread = "thread"
)

// L10nDecorator represents the localization decorator
type L10nDecorator struct {
	Locale string `json:"locale,omitempty"`
}

// TimingDecorator represents the timing decorator
type TimingDecorator struct {
	InTime        *time.Time `json:"in_time,omitempty"`
	OutTime       *time.Time `json:"out_time,omitempty"`
	StaleTime     *time.Time `json:"stale_time,omitempty"`
	ExpiresTime   *time.Time `json:"expires_time,omitempty"`
	DelayMilli    int        `json:"delay_milli,omitempty"`
	WaitUntilTime *time.Time `json:"wait_until_time,omitempty"`
}

// ServiceDecorator represents the service decorator
type ServiceDecorator struct {
	RecipientKeys   []string `json:"recipient_keys"`
	RoutingKeys     []string `json:"routing_keys,omitempty"`
	ServiceEndpoint string   `json:"service_endpoint"`
}

// AttachmentDecorator represents an attachment
type AttachmentDecorator struct {
	Id          string          `json:"id"`
	Description string          `json:"description,omitempty"`
	Filename    string          `json:"filename,omitempty"`
	MimeType    string          `json:"mime-type,omitempty"`
	LastModTime time.Time       `json:"lastmod_time,omitempty"`
	ByteCount   int             `json:"byte_count,omitempty"`
	Data        *AttachmentData `json:"data"`
}

// AttachmentData represents the data in an attachment
type AttachmentData struct {
	Sha256 string      `json:"sha256,omitempty"`
	Links  []string    `json:"links,omitempty"`
	Base64 string      `json:"base64,omitempty"`
	Json   interface{} `json:"json,omitempty"`
	Jws    *JwsData    `json:"jws,omitempty"`
}

// Attachment represents a DIDComm attachment (without decorator prefix)
type Attachment struct {
	Id          string         `json:"@id"`
	Description string         `json:"description,omitempty"`
	Filename    string         `json:"filename,omitempty"`
	MimeType    string         `json:"mime-type,omitempty"`
	LastModTime string         `json:"lastmod_time,omitempty"`
	ByteCount   int            `json:"byte_count,omitempty"`
	Data        AttachmentData `json:"data"`
}

// JwsData represents JWS data in an attachment
type JwsData struct {
	Header    map[string]interface{} `json:"header"`
	Protected string                 `json:"protected"`
	Signature string                 `json:"signature"`
}

// MessageInterface defines the interface that all DIDComm messages must implement
type MessageInterface interface {
	GetId() string
	GetType() string
	SetId(id string)
	SetType(messageType string)
	GetFrom() string
	SetFrom(from string)
	GetTo() []string
	SetTo(to []string)
	GetThread() *ThreadDecorator
	SetThread(thread *ThreadDecorator)
	GetTransport() *TransportDecorator
	SetTransport(transport *TransportDecorator)
	GetThreadId() string
	SetThreadId(threadId string)
	HasReturnRoute() bool
	ToJSON() ([]byte, error)
	FromJSON(data []byte) error
	Clone() MessageInterface
	Validate() error
}

// AgentMessage is a type alias for MessageInterface for compatibility
type AgentMessage = MessageInterface

// NewBaseMessage creates a new base message with a generated ID
func NewBaseMessage(messageType string) *BaseMessage {
	return &BaseMessage{
		Id:               uuid.New().String(),
		Type:             messageType,
		AdditionalFields: make(map[string]interface{}),
	}
}

// NewBaseMessageWithId creates a new base message with a specific ID
func NewBaseMessageWithId(id, messageType string) *BaseMessage {
	return &BaseMessage{
		Id:               id,
		Type:             messageType,
		AdditionalFields: make(map[string]interface{}),
	}
}

// Implement MessageInterface methods

func (m *BaseMessage) GetId() string {
	return m.Id
}

func (m *BaseMessage) SetId(id string) {
	m.Id = id
}

func (m *BaseMessage) GetType() string {
	return m.Type
}

func (m *BaseMessage) SetType(messageType string) {
	m.Type = messageType
}

func (m *BaseMessage) GetFrom() string {
	return m.From
}

func (m *BaseMessage) SetFrom(from string) {
	m.From = from
}

func (m *BaseMessage) GetTo() []string {
	return m.To
}

func (m *BaseMessage) SetTo(to []string) {
	m.To = to
}

func (m *BaseMessage) GetThread() *ThreadDecorator {
	return m.Thread
}

func (m *BaseMessage) SetThread(thread *ThreadDecorator) {
	m.Thread = thread
}

func (m *BaseMessage) GetTransport() *TransportDecorator {
	return m.Transport
}

func (m *BaseMessage) SetTransport(transport *TransportDecorator) {
	m.Transport = transport
}

// ToJSON converts the message to JSON
func (m *BaseMessage) ToJSON() ([]byte, error) {
	// Create a map with all fields
	result := make(map[string]interface{})

	// Marshal to JSON first to get standard fields
	data, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}

	// Unmarshal to map
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}

	// Add additional fields
	for key, value := range m.AdditionalFields {
		result[key] = value
	}

	return json.Marshal(result)
}

// FromJSON populates the message from JSON
func (m *BaseMessage) FromJSON(data []byte) error {
	// First unmarshal to a map to extract additional fields
	var rawMap map[string]interface{}
	if err := json.Unmarshal(data, &rawMap); err != nil {
		return err
	}

	// Unmarshal to struct for known fields
	type Alias BaseMessage
	if err := json.Unmarshal(data, (*Alias)(m)); err != nil {
		return err
	}

	// Extract additional fields
	knownFields := map[string]bool{
		"@id": true, "@type": true, "from": true, "to": true,
		"created_time": true, "expires_time": true, "body": true,
		"~thread": true, "~transport": true, "~l10n": true,
		"~timing": true, "~service": true, "~attachment": true,
	}

	if m.AdditionalFields == nil {
		m.AdditionalFields = make(map[string]interface{})
	}

	for key, value := range rawMap {
		if !knownFields[key] {
			m.AdditionalFields[key] = value
		}
	}

	return nil
}

// Clone creates a deep copy of the message
func (m *BaseMessage) Clone() MessageInterface {
	clone := &BaseMessage{
		Id:               m.Id,
		Type:             m.Type,
		From:             m.From,
		To:               append([]string(nil), m.To...),
		CreatedTime:      m.CreatedTime,
		ExpiresTime:      m.ExpiresTime,
		AdditionalFields: make(map[string]interface{}),
	}

	// Clone body
	if m.Body != nil {
		clone.Body = make(map[string]interface{})
		for k, v := range m.Body {
			clone.Body[k] = v
		}
	}

	// Clone thread decorator
	if m.Thread != nil {
		clone.Thread = &ThreadDecorator{
			Thid:           m.Thread.Thid,
			Pthid:          m.Thread.Pthid,
			SenderOrder:    m.Thread.SenderOrder,
			ReceivedOrders: append([]string(nil), m.Thread.ReceivedOrders...),
			GoalCode:       m.Thread.GoalCode,
			Goal:           m.Thread.Goal,
			ParentThreadId: m.Thread.ParentThreadId,
		}
	}

	// Clone transport decorator
	if m.Transport != nil {
		clone.Transport = &TransportDecorator{
			ReturnRoute:             m.Transport.ReturnRoute,
			ReturnRouteThread:       m.Transport.ReturnRouteThread,
			QueuedTransportResponse: m.Transport.QueuedTransportResponse,
		}
	}

	// Clone additional fields
	for k, v := range m.AdditionalFields {
		clone.AdditionalFields[k] = v
	}

	return clone
}

// Validate performs basic validation on the message
func (m *BaseMessage) Validate() error {
	if m.Id == "" {
		return fmt.Errorf("message ID is required")
	}

	if m.Type == "" {
		return fmt.Errorf("message type is required")
	}

	// Validate thread decorator if present
	if m.Thread != nil {
		if err := m.validateThread(); err != nil {
			return fmt.Errorf("invalid thread decorator: %w", err)
		}
	}

	return nil
}

// validateThread validates the thread decorator
func (m *BaseMessage) validateThread() error {
	if m.Thread.Thid == "" && m.Thread.Pthid == "" {
		return fmt.Errorf("thread decorator must have either thid or pthid")
	}

	return nil
}

// Helper methods for working with thread decorators

// GetThreadId returns the thread ID, using message ID if no thread ID is set
func (m *BaseMessage) GetThreadId() string {
	if m.Thread != nil && m.Thread.Thid != "" {
		return m.Thread.Thid
	}
	return m.Id
}

// SetThreadId sets the thread ID
func (m *BaseMessage) SetThreadId(threadId string) {
	if m.Thread == nil {
		m.Thread = &ThreadDecorator{}
	}
	m.Thread.Thid = threadId
}

// GetParentThreadId returns the parent thread ID
func (m *BaseMessage) GetParentThreadId() string {
	if m.Thread != nil {
		if m.Thread.ParentThreadId != "" {
			return m.Thread.ParentThreadId
		}
		return m.Thread.Pthid
	}
	return ""
}

// SetParentThreadId sets the parent thread ID
func (m *BaseMessage) SetParentThreadId(parentThreadId string) {
	if m.Thread == nil {
		m.Thread = &ThreadDecorator{}
	}
	m.Thread.Pthid = parentThreadId
	m.Thread.ParentThreadId = parentThreadId
}

// HasReturnRoute checks if the message requests a response via return routing
func (m *BaseMessage) HasReturnRoute() bool {
	if m.Transport == nil {
		return false
	}
	return m.Transport.ReturnRoute == ReturnRouteAll || m.Transport.ReturnRoute == ReturnRouteThread
}

// SetReturnRoute sets the return route
func (m *BaseMessage) SetReturnRoute(returnRoute string) {
	if m.Transport == nil {
		m.Transport = &TransportDecorator{}
	}
	m.Transport.ReturnRoute = returnRoute
}

// Helper functions for creating messages with common patterns

// NewThreadedMessage creates a message that's part of a thread
func NewThreadedMessage(messageType, threadId string) *BaseMessage {
	msg := NewBaseMessage(messageType)
	msg.SetThreadId(threadId)
	return msg
}

// NewReplyMessage creates a reply to another message
func NewReplyMessage(messageType string, originalMessage MessageInterface) *BaseMessage {
	msg := NewBaseMessage(messageType)

	// Set thread ID to the original message's thread ID (or ID if no thread)
	msg.SetThreadId(originalMessage.GetThreadId())

	// Set reply-to information
	if originalMessage.GetFrom() != "" {
		msg.SetTo([]string{originalMessage.GetFrom()})
	}

	return msg
}

// CreateReplyMessage creates a reply message to this message
func (m *BaseMessage) CreateReplyMessage(messageType string) *BaseMessage {
	reply := NewBaseMessage(messageType)

	// Set thread ID to this message's thread ID (or ID if no thread)
	reply.SetThreadId(m.GetThreadId())

	// Set reply-to information
	if m.GetFrom() != "" {
		reply.SetTo([]string{m.GetFrom()})
	}

	return reply
}

// IsThreadedReplyTo checks if this message is a threaded reply to another message
func (m *BaseMessage) IsThreadedReplyTo(originalMessage MessageInterface) bool {
	// Check if both messages have thread information
	if m.Thread == nil || originalMessage.GetThreadId() == "" {
		return false
	}

	// Check if this message's thread ID matches the original message's thread ID
	return m.GetThreadId() == originalMessage.GetThreadId()
}
