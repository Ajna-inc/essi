//go:build integration
// +build integration

package integration_test

import (
	"net"
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

func pickPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen :0: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func buildHTTPAgents(t *testing.T) (*agent.Agent, *agent.Agent, int, int) {
	pa := pickPort(t)
	pb := pickPort(t)
	a := testutil.NewTestAgent(t, testutil.TestAgentOptions{Label: "HTTP-A", InboundHost: "127.0.0.1", InboundPort: pa})
	b := testutil.NewTestAgent(t, testutil.TestAgentOptions{Label: "HTTP-B", InboundHost: "127.0.0.1", InboundPort: pb})
	return a, b, pa, pb
}

func TestHTTP_DidExchange_And_Ping(t *testing.T) {
	a, b, _, _ := buildHTTPAgents(t)

	// Event buses
	var busA, busB coreevents.Bus
	if any, err := a.GetDependencyManager().Resolve(di.TokenEventBusService); err == nil {
		busA, _ = any.(coreevents.Bus)
	}
	if any, err := b.GetDependencyManager().Resolve(di.TokenEventBusService); err == nil {
		busB, _ = any.(coreevents.Bus)
	}
	if busA == nil || busB == nil {
		t.Fatalf("event buses not available")
	}

	// Create OOB on A and process on B
	dep, err := a.GetDependencyManager().Resolve(di.TokenOobApi)
	if err != nil {
		t.Fatalf("resolve OobApi: %v", err)
	}
	oobApi, ok := dep.(*oob.OutOfBandApi)
	if !ok || oobApi == nil {
		t.Fatalf("OobApi not available")
	}
	rec, err := oobApi.CreateInvitation(oob.CreateOutOfBandInvitationConfig{Label: "http-e2e"})
	if err != nil {
		t.Fatalf("create invitation: %v", err)
	}
	inv, ok := rec.OutOfBandInvitation.(*oobmessages.OutOfBandInvitationMessage)
	if !ok || inv == nil {
		t.Fatalf("invalid invitation payload")
	}
	url, err := oobApi.InvitationToUrl(inv)
	if err != nil {
		t.Fatalf("InvitationToUrl: %v", err)
	}

	if _, err := b.ProcessOOBInvitation(url); err != nil {
		t.Fatalf("process OOB: %v", err)
	}

	// Wait for both sides to complete
	if _, err := testutil.WaitForConnComplete(busA, "", 20*time.Second); err != nil {
		t.Fatalf("A complete: %v", err)
	}
	if _, err := testutil.WaitForConnComplete(busB, "", 20*time.Second); err != nil {
		t.Fatalf("B complete: %v", err)
	}

	// Send trust-ping from A to B
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

	// Wait for ping_response on A or ping on B
	if _, err := testutil.WaitForMessageType(busA, "https://didcomm.org/trust-ping/1.0/ping_response", 5*time.Second); err != nil {
		t.Fatalf("did not receive ping_response on A: %v", err)
	}
}
