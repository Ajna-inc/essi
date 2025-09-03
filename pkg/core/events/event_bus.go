package events

import "sync"

// EventMetadata carries context metadata for an event (parity with Credo TS)
type EventMetadata struct {
	ContextCorrelationId string
}

// Event represents a generic event with a name and payload data
type Event struct {
	Name     string
	Data     interface{}
	Metadata EventMetadata
}

// EventHandler processes an event
type EventHandler func(Event)

// Bus defines the event bus interface
// NOTE: existing callers using Publish still work; PublishWithMetadata is additive.
type Bus interface {
	Subscribe(eventName string, handler EventHandler) func()
	Publish(eventName string, data interface{})
	PublishWithMetadata(eventName string, data interface{}, md EventMetadata)
}

// subscription tracks a single handler subscription
type subscription struct {
	id      int64
	handler EventHandler
}

// SimpleBus is a thread-safe in-memory event bus
type SimpleBus struct {
	mu       sync.RWMutex
	handlers map[string][]subscription
	nextID   int64
}

// NewSimpleBus creates a new event bus
func NewSimpleBus() *SimpleBus {
	return &SimpleBus{handlers: make(map[string][]subscription)}
}

// Subscribe registers a handler for an event. Returns an unsubscribe function
func (b *SimpleBus) Subscribe(eventName string, handler EventHandler) func() {
	b.mu.Lock()
	id := b.nextID
	b.nextID++
	b.handlers[eventName] = append(b.handlers[eventName], subscription{id: id, handler: handler})
	b.mu.Unlock()

	return func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		subs := b.handlers[eventName]
		// Remove the subscription with matching id (stable order)
		out := subs[:0]
		for _, s := range subs {
			if s.id == id {
				continue
			}
			out = append(out, s)
		}
		b.handlers[eventName] = out
	}
}

// Publish emits an event to all subscribers (without metadata)
func (b *SimpleBus) Publish(eventName string, data interface{}) {
	b.PublishWithMetadata(eventName, data, EventMetadata{})
}

// PublishWithMetadata emits an event with metadata to all subscribers
func (b *SimpleBus) PublishWithMetadata(eventName string, data interface{}, md EventMetadata) {
	b.mu.RLock()
	subs := append([]subscription(nil), b.handlers[eventName]...)
	b.mu.RUnlock()
	ev := Event{Name: eventName, Data: data, Metadata: md}
	for _, s := range subs {
		// Fire handlers synchronously for simplicity
		s.handler(ev)
	}
}

// Common event names used across the agent
const (
	EventMessageReceived        = "message.received"
	EventMessageSent            = "message.sent"
	EventConnectionStateChanged = "connection.stateChanged"
	EventConnectionCompleted    = "connection.completed"
	EventConnectionRequest      = "connection.request"
	EventConnectionResponse     = "connection.response"
	EventCredentialStateChanged = "credentials.stateChanged"
	EventCredentialReceived     = "credentials.received"
	EventDidExchangeRequest     = "didexchange.request"
	EventDidExchangeResponse    = "didexchange.response"
	EventDidExchangeComplete    = "didexchange.complete"
	EventProblemReport          = "problem.report"
)

// AgentEventTypes - exact parity with Credo TS
const (
	AgentMessageReceived  = "AgentMessageReceived"
	AgentMessageProcessed = "AgentMessageProcessed"
	AgentMessageSent      = "AgentMessageSent"
)

// OOB Events - parity with Credo TS
const (
	OOBStateChanged    = "oob.stateChanged"
	OOBHandshakeReused = "oob.handshakeReused"
)

// Connection Events - parity with Credo TS
const (
	ConnectionStateChanged = "connection.stateChanged"
)

// Credential Events - parity with Credo TS
const (
	CredentialsStateChanged = "credentials.stateChanged"
	RevocationReceived      = "revocation.received"
)

// EmitterWithContext provides correlation-aware event emission
type EmitterWithContext interface {
	Emit(contextCorrelationId string, eventType string, payload interface{})
	EmitWithMetadata(eventType string, payload interface{}, metadata EventMetadata)
}

// ContextualEmitter wraps a Bus to provide correlation-aware emission
type ContextualEmitter struct {
	bus Bus
}

// NewContextualEmitter creates a new contextual emitter
func NewContextualEmitter(bus Bus) *ContextualEmitter {
	return &ContextualEmitter{bus: bus}
}

// Emit emits an event with context correlation ID attached
func (e *ContextualEmitter) Emit(contextCorrelationId string, eventType string, payload interface{}) {
	metadata := EventMetadata{ContextCorrelationId: contextCorrelationId}
	e.bus.PublishWithMetadata(eventType, payload, metadata)
}

// EmitWithMetadata emits an event with provided metadata
func (e *ContextualEmitter) EmitWithMetadata(eventType string, payload interface{}, metadata EventMetadata) {
	e.bus.PublishWithMetadata(eventType, payload, metadata)
}

// SubscribeWithFilter creates a filtered subscription that only receives events matching the predicate
func (b *SimpleBus) SubscribeWithFilter(eventName string, predicate func(Event) bool, handler EventHandler) func() {
	return b.Subscribe(eventName, func(event Event) {
		if predicate(event) {
			handler(event)
		}
	})
}

// FilterByCorrelationId creates a predicate function for correlation ID filtering
func FilterByCorrelationId(correlationId string) func(Event) bool {
	return func(event Event) bool {
		return event.Metadata.ContextCorrelationId == correlationId
	}
}
