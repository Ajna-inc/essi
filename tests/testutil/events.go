package testutil

import (
	"errors"
	"time"

	coreevents "github.com/ajna-inc/essi/pkg/core/events"
)

// WaitForEvent subscribes to an event and resolves when predicate returns true or timeout elapses.
func WaitForEvent(bus coreevents.Bus, name string, predicate func(coreevents.Event) bool, timeout time.Duration) (coreevents.Event, error) {
	ch := make(chan coreevents.Event, 1)
	unsub := bus.Subscribe(name, func(ev coreevents.Event) {
		if predicate == nil || predicate(ev) {
			select {
			case ch <- ev:
			default:
			}
		}
	})
	defer unsub()
	select {
	case ev := <-ch:
		return ev, nil
	case <-time.After(timeout):
		return coreevents.Event{}, errors.New("timeout waiting for event")
	}
}

// WaitForMessageType waits for message.received with a specific DIDComm type.
func WaitForMessageType(bus coreevents.Bus, typeURI string, timeout time.Duration) (coreevents.Event, error) {
	return WaitForEvent(bus, coreevents.EventMessageReceived, func(ev coreevents.Event) bool {
		if m, ok := ev.Data.(map[string]interface{}); ok {
			if tp, _ := m["type"].(string); tp == typeURI {
				return true
			}
		}
		return false
	}, timeout)
}

// WaitForConnComplete waits for a connection.stateChanged event with state=="complete" (and optional id match).
func WaitForConnComplete(bus coreevents.Bus, id string, timeout time.Duration) (coreevents.Event, error) {
    return WaitForEvent(bus, coreevents.EventConnectionStateChanged, func(ev coreevents.Event) bool {
        if m, ok := ev.Data.(map[string]interface{}); ok {
            st, _ := m["state"].(string)
            if st != "complete" {
                return false
            }
            if id == "" {
                return true
            }
            cid, _ := m["id"].(string)
            return cid == id
        }
        return false
    }, timeout)
}

// WaitForConnResponded waits for a connection.stateChanged event with state=="responded" (and optional id match).
func WaitForConnResponded(bus coreevents.Bus, id string, timeout time.Duration) (coreevents.Event, error) {
    return WaitForEvent(bus, coreevents.EventConnectionStateChanged, func(ev coreevents.Event) bool {
        if m, ok := ev.Data.(map[string]interface{}); ok {
            st, _ := m["state"].(string)
            if st != "responded" { return false }
            if id == "" { return true }
            cid, _ := m["id"].(string)
            if cid == "" { cid, _ = m["connectionId"].(string) }
            return cid == id
        }
        return false
    }, timeout)
}

// WaitForConnState waits for a desired connection state
func WaitForConnState(bus coreevents.Bus, id string, desired string, timeout time.Duration) (coreevents.Event, error) {
    return WaitForEvent(bus, coreevents.EventConnectionStateChanged, func(ev coreevents.Event) bool {
        if m, ok := ev.Data.(map[string]interface{}); ok {
            st, _ := m["state"].(string)
            if st != desired { return false }
            if id == "" { return true }
            cid, _ := m["id"].(string)
            if cid == "" { cid, _ = m["connectionId"].(string) }
            return cid == id
        }
        return false
    }, timeout)
}
