package agent

import (
    "testing"
    "time"

    corectx "github.com/ajna-inc/essi/pkg/core/context"
    "github.com/ajna-inc/essi/pkg/core/events"
)

func TestWaitForHandshakeReuseAccepted_Succeeds(t *testing.T) {
    // Arrange: minimal agent with context + event bus
    a := &Agent{
        context: corectx.NewAgentContext(corectx.AgentContextOptions{}),
        events:  events.NewSimpleBus(),
    }

    threadId := "thid-1"
    connId := "conn-1"

    // Publish matching event after a short delay
    go func() {
        time.Sleep(50 * time.Millisecond)
        a.events.Publish("oob.handshakeReused", map[string]interface{}{
            "reuseThreadId":       threadId,
            "connectionId":        connId,
            "contextCorrelationId": a.context.GetCorrelationId(),
        })
    }()

    // Act
    ok := a.waitForHandshakeReuseAccepted(threadId, connId, 500*time.Millisecond)

    // Assert
    if !ok {
        t.Fatalf("expected waitForHandshakeReuseAccepted to return true, got false")
    }
}

func TestWaitForHandshakeReuseAccepted_TimesOut(t *testing.T) {
    a := &Agent{
        context: corectx.NewAgentContext(corectx.AgentContextOptions{}),
        events:  events.NewSimpleBus(),
    }

    // Do not publish any event
    ok := a.waitForHandshakeReuseAccepted("thid-timeout", "conn-xyz", 50*time.Millisecond)
    if ok {
        t.Fatalf("expected waitForHandshakeReuseAccepted to timeout and return false, got true")
    }
}


