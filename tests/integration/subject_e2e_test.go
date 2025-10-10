//go:build !subjectmem
// +build !subjectmem

// This test uses in-memory storage and subject transport; no external deps required.

package integration_test

import (
    "testing"
    "time"

    "github.com/ajna-inc/essi/pkg/core/agent"
    "github.com/ajna-inc/essi/pkg/core/di"
    coreevents "github.com/ajna-inc/essi/pkg/core/events"
    didcommmessages "github.com/ajna-inc/essi/pkg/didcomm/messages"
    didcommmodels "github.com/ajna-inc/essi/pkg/didcomm/models"
    oob "github.com/ajna-inc/essi/pkg/didcomm/modules/oob"
    oobmessages "github.com/ajna-inc/essi/pkg/didcomm/modules/oob/messages"
    "github.com/ajna-inc/essi/tests/testutil"
)

// buildTwoAgents creates two subject-transport agents and wires them via subject handlers
func buildTwoAgents(t *testing.T) (*agent.Agent, *agent.Agent) {
    // Use in-memory storage (no native deps) and subject transport
    a := testutil.NewMemoryAgent(t, "A", []string{"wss://subject/a"}, true)
    b := testutil.NewMemoryAgent(t, "B", []string{"wss://subject/b"}, true)
    testutil.SetupSubjectTransports(a.GetDependencyManager(), "wss://subject/a", b.GetDependencyManager(), "wss://subject/b")
    return a, b
}

func TestSubjectE2E_ConnectAndPing(t *testing.T) {
	a, b := buildTwoAgents(t)

	// Create OOB invitation on A and process on B
	dmA := a.GetDependencyManager()
	dep, err := dmA.Resolve(di.TokenOobApi)
	if err != nil {
		t.Fatalf("resolve OobApi: %v", err)
	}
	oobApi, ok := dep.(*oob.OutOfBandApi)
	if !ok || oobApi == nil {
		t.Fatalf("OobApi type unsupported")
	}
	rec, err := oobApi.CreateInvitation(oob.CreateOutOfBandInvitationConfig{Label: "test"})
	if err != nil {
		t.Fatalf("create invitation: %v", err)
	}
	// rec.OutOfBandInvitation is interface{}, cast to expected type
	inv, ok := rec.OutOfBandInvitation.(*oobmessages.OutOfBandInvitationMessage)
	if !ok || inv == nil {
		t.Fatalf("unexpected invitation type in record")
	}
	url, err := oobApi.InvitationToUrl(inv)
	if err != nil {
		t.Fatalf("InvitationToUrl: %v", err)
	}

	// Process on B
	if _, err := b.ProcessOOBInvitation(url); err != nil {
		t.Fatalf("process OOB: %v", err)
	}

    // Proceed without waiting for response; sender will fall back to OOB inline service for delivery if needed.

	// Send a trust-ping from A to B via MessageSender using first connection on A
	conns, _ := a.GetConnections()
	if len(conns) == 0 {
		t.Fatalf("no connections on A")
	}
	connA := conns[0]
	msg := didcommmessages.NewBaseMessage("https://didcomm.org/trust-ping/1.0/ping")
	if any, err := a.GetDependencyManager().Resolve(di.TokenMessageSender); err == nil {
		if ms, ok := any.(interface {
			SendMessage(*didcommmodels.OutboundMessageContext) error
		}); ok {
			out := didcommmodels.NewOutboundMessageContext(msg, didcommmodels.OutboundMessageContextParams{AgentContext: a.GetContext(), Connection: connA})
			if err := ms.SendMessage(out); err != nil {
				t.Fatalf("send ping: %v", err)
			}
		} else {
			t.Fatalf("MessageSender not available")
		}
	} else {
		t.Fatalf("resolve MessageSender: %v", err)
	}

	// Assert B receives the ping via event bus (proves subject wiring + sender/receiver)
    // Resolve bus on B to assert message receipt
    var busB coreevents.Bus
    if any, err := b.GetDependencyManager().Resolve(di.TokenEventBusService); err == nil { busB, _ = any.(coreevents.Bus) }
    if busB == nil { t.Fatalf("event bus B not available") }
    if _, err := testutil.WaitForMessageType(busB, "https://didcomm.org/trust-ping/1.0/ping", 5*time.Second); err != nil {
        t.Fatalf("did not receive trust-ping on B: %v", err)
    }
}
