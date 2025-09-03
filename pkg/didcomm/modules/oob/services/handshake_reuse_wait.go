package services

import (
	"time"

	coreevents "github.com/ajna-inc/essi/pkg/core/events"
)

// WaitForHandshakeReused waits until an OutOfBand handshake reuse event matches the given criteria or timeout.
// Returns true when reuse is accepted, false on timeout or when bus is nil.
func WaitForHandshakeReused(bus coreevents.Bus, contextCorrelationId string, outOfBandRecordId string, reuseThreadId string, timeout time.Duration) bool {
	if bus == nil || reuseThreadId == "" {
		return false
	}
	ch := make(chan bool, 1)
	unsubscribe := bus.Subscribe("oob.handshakeReused", func(ev coreevents.Event) {
		// Optional metadata filter
		if contextCorrelationId != "" && ev.Metadata.ContextCorrelationId != contextCorrelationId {
			return
		}
		payload, ok := ev.Data.(map[string]interface{})
		if !ok || payload == nil {
			return
		}
		// Match by reuseThreadId
		if rt, ok := payload["reuseThreadId"].(string); !ok || rt != reuseThreadId {
			return
		}
		// If an OOB record id filter is provided, check for match if present
		if outOfBandRecordId != "" {
			if rec, ok := payload["outOfBandRecord"].(map[string]interface{}); ok && rec != nil {
				if id, ok := rec["id"].(string); ok && id != outOfBandRecordId {
					return
				}
			}
		}
		select {
		case ch <- true:
		default:
		}
	})
	defer unsubscribe()
	select {
	case <-time.After(timeout):
		return false
	case ok := <-ch:
		return ok
	}
}
