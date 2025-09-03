package events

import (
	"testing"
)

func TestPhase0EventSystem(t *testing.T) {
	// Test unsubscribe fix
	bus := NewSimpleBus()
	called := false
	
	unsubscribe := bus.Subscribe("test", func(e Event) {
		called = true
	})
	
	bus.Publish("test", "data")
	if !called {
		t.Error("Handler should have been called")
	}
	
	// Test unsubscribe works
	called = false
	unsubscribe()
	bus.Publish("test", "data")
	if called {
		t.Error("Handler should not have been called after unsubscribe")
	}
}

func TestMetadataSupport(t *testing.T) {
	bus := NewSimpleBus()
	var receivedEvent Event
	
	bus.Subscribe("test", func(e Event) {
		receivedEvent = e
	})
	
	metadata := EventMetadata{ContextCorrelationId: "test-correlation-123"}
	bus.PublishWithMetadata("test", "payload", metadata)
	
	if receivedEvent.Metadata.ContextCorrelationId != "test-correlation-123" {
		t.Errorf("Expected correlation ID 'test-correlation-123', got '%s'", 
			receivedEvent.Metadata.ContextCorrelationId)
	}
}

func TestContextualEmitter(t *testing.T) {
	bus := NewSimpleBus()
	emitter := NewContextualEmitter(bus)
	
	var receivedEvent Event
	bus.Subscribe("test", func(e Event) {
		receivedEvent = e
	})
	
	emitter.Emit("correlation-456", "test", "payload")
	
	if receivedEvent.Metadata.ContextCorrelationId != "correlation-456" {
		t.Errorf("Expected correlation ID 'correlation-456', got '%s'", 
			receivedEvent.Metadata.ContextCorrelationId)
	}
}

func TestFilteredSubscription(t *testing.T) {
	bus := NewSimpleBus()
	called := false
	
	// Subscribe with correlation ID filter
	correlationFilter := FilterByCorrelationId("target-correlation")
	bus.SubscribeWithFilter("test", correlationFilter, func(e Event) {
		called = true
	})
	
	// Publish with wrong correlation ID - should not trigger
	metadata1 := EventMetadata{ContextCorrelationId: "wrong-correlation"}
	bus.PublishWithMetadata("test", "data", metadata1)
	if called {
		t.Error("Handler should not have been called for wrong correlation ID")
	}
	
	// Publish with correct correlation ID - should trigger
	metadata2 := EventMetadata{ContextCorrelationId: "target-correlation"}
	bus.PublishWithMetadata("test", "data", metadata2)
	if !called {
		t.Error("Handler should have been called for correct correlation ID")
	}
}