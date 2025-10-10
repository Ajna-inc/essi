package testutil

import (
    "testing"
    "time"

    "github.com/ajna-inc/essi/pkg/core/agent"
    "github.com/ajna-inc/essi/pkg/core/di"
    coreevents "github.com/ajna-inc/essi/pkg/core/events"
)

// ReturnWhenIsConnected waits using connection.stateChanged events for responded or complete.
func ReturnWhenIsConnected(t *testing.T, a *agent.Agent, connectionId string, timeout time.Duration) {
    t.Helper()
    // Quick check: already connected
    if conns, _ := a.GetConnections(); len(conns) > 0 {
        for _, c := range conns {
            if c == nil { continue }
            if connectionId != "" && c.ID != connectionId { continue }
            if c.State == "responded" || c.State == "complete" { return }
        }
    }
    // Resolve event bus
    var bus coreevents.Bus
    if any, err := a.GetDependencyManager().Resolve(di.TokenEventBusService); err == nil {
        bus, _ = any.(coreevents.Bus)
    }
    if bus == nil {
        t.Fatalf("event bus not available on agent for waiting")
    }
    // Prefer responded, then complete
    half := timeout / 2
    if _, err := WaitForConnResponded(bus, connectionId, half); err == nil { return }
    if _, err := WaitForConnComplete(bus, connectionId, timeout-half); err == nil { return }
    t.Fatalf("timeout waiting for connection %s to be connected", connectionId)
}

// ReturnWhenPartnerByTheirDidConnected waits via connection.stateChanged for theirDid + connected state.
func ReturnWhenPartnerByTheirDidConnected(t *testing.T, a *agent.Agent, partnerDid string, timeout time.Duration) {
    t.Helper()
    // Quick short-circuit
    if conns, _ := a.GetConnections(); len(conns) > 0 {
        for _, c := range conns {
            if c == nil { continue }
            if c.TheirDid != partnerDid { continue }
            if c.State == "responded" || c.State == "complete" { return }
        }
    }
    var bus coreevents.Bus
    if any, err := a.GetDependencyManager().Resolve(di.TokenEventBusService); err == nil {
        bus, _ = any.(coreevents.Bus)
    }
    if bus == nil { t.Fatalf("event bus not available on agent for waiting") }
    // Wait for stateChanged with theirDid match and responded/complete
    _, err := WaitForEvent(bus, coreevents.EventConnectionStateChanged, func(ev coreevents.Event) bool {
        if m, ok := ev.Data.(map[string]interface{}); ok {
            st, _ := m["state"].(string)
            td, _ := m["theirDid"].(string)
            if td != partnerDid { return false }
            return st == "responded" || st == "complete"
        }
        return false
    }, timeout)
    if err != nil { t.Fatalf("timeout waiting for partner (theirDid=%s) to be connected", partnerDid) }
}
