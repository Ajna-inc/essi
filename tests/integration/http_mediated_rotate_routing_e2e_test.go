//go:build integration
// +build integration

package integration_test

import (
    "encoding/json"
    "fmt"
    "net"
    "testing"
    "time"

	"github.com/ajna-inc/essi/pkg/core/agent"
	"github.com/ajna-inc/essi/pkg/core/di"
	coreevents "github.com/ajna-inc/essi/pkg/core/events"
	didcommmessages "github.com/ajna-inc/essi/pkg/didcomm/messages"
    didcommodels "github.com/ajna-inc/essi/pkg/didcomm/models"
    connservices "github.com/ajna-inc/essi/pkg/didcomm/modules/connections/services"
	pickupHandlers "github.com/ajna-inc/essi/pkg/didcomm/modules/messagepickup/handlers"
	mpv2 "github.com/ajna-inc/essi/pkg/didcomm/modules/messagepickup/v2"
	oob "github.com/ajna-inc/essi/pkg/didcomm/modules/oob"
	oobmessages "github.com/ajna-inc/essi/pkg/didcomm/modules/oob/messages"
	transport "github.com/ajna-inc/essi/pkg/didcomm/transport"
	"github.com/ajna-inc/essi/tests/testutil"
)

// pickFreePort returns a free TCP port by binding to :0 temporarily
func pickFreePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen :0: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func buildHTTPAgent(t *testing.T, label string) *agent.Agent {
	port := pickFreePort(t)
	return testutil.NewTestAgent(t, testutil.TestAgentOptions{
		Label:       label,
		InboundHost: "127.0.0.1",
		InboundPort: port,
		Endpoints:   []string{fmt.Sprintf("http://127.0.0.1:%d", port)},
	})
}

func oobConnectHTTP(t *testing.T, inviter *agent.Agent, invitee *agent.Agent) *connservices.ConnectionRecord {
	dep, err := inviter.GetDependencyManager().Resolve(di.TokenOobApi)
	if err != nil {
		t.Fatalf("resolve OobApi: %v", err)
	}
	oobApi, ok := dep.(*oob.OutOfBandApi)
	if !ok || oobApi == nil {
		t.Fatalf("OobApi type unsupported")
	}
	rec, err := oobApi.CreateInvitation(oob.CreateOutOfBandInvitationConfig{Label: "http-test"})
	if err != nil {
		t.Fatalf("create invitation: %v", err)
	}
	inv, ok := rec.OutOfBandInvitation.(*oobmessages.OutOfBandInvitationMessage)
	if !ok || inv == nil {
		t.Fatalf("unexpected invitation type in record")
	}
	url, err := oobApi.InvitationToUrl(inv)
	if err != nil {
		t.Fatalf("InvitationToUrl: %v", err)
	}
	conn, err := invitee.ProcessOOBInvitation(url)
	if err != nil {
		t.Fatalf("process OOB: %v", err)
	}
    testutil.ReturnWhenIsConnected(t, invitee, conn.ID, 40*time.Second)
	return conn
}

func TestHTTP_MediatedRotate_RoutesViaMediator(t *testing.T) {
	holder := buildHTTPAgent(t, "HTTP-Holder")
	partner := buildHTTPAgent(t, "HTTP-Partner")
	mediator := buildHTTPAgent(t, "HTTP-Mediator")

	// Connect Holder <-> Partner (HTTP)
	_ = oobConnectHTTP(t, holder, partner)
	// Connect Mediator <-> Holder
	connHM := oobConnectHTTP(t, mediator, holder)

	// Request mediation and await grant
	testutil.RequestAndAwaitGrant(t, holder, connHM.ID, 15*time.Second)

	// Partner sends a trust-ping to Holder
	connsP, _ := partner.GetConnections()
	if len(connsP) == 0 {
		t.Fatalf("partner has no connections")
	}
	ping := didcommmessages.NewBaseMessage("https://didcomm.org/trust-ping/1.0/ping")
	out := didcommodels.NewOutboundMessageContext(ping, didcommodels.OutboundMessageContextParams{AgentContext: partner.GetContext(), Connection: connsP[0]})
	if any, err := partner.GetDependencyManager().Resolve(di.TokenMessageSender); err == nil {
		if ms, ok := any.(interface {
			SendMessage(*didcommodels.OutboundMessageContext) error
		}); ok {
			if err := ms.SendMessage(out); err != nil {
				t.Fatalf("send ping: %v", err)
			}
		} else {
			t.Fatalf("MessageSender not available")
		}
	} else {
		t.Fatalf("resolve MessageSender: %v", err)
	}

	// Assert mediator receives a forward (routing/1.0/forward) over HTTP inbound
	var busM coreevents.Bus
	if any, err := mediator.GetDependencyManager().Resolve(di.TokenEventBusService); err == nil {
		busM, _ = any.(coreevents.Bus)
	}
	if busM == nil {
		t.Fatalf("event bus mediator not available")
	}
	if _, err := testutil.WaitForMessageType(busM, "https://didcomm.org/routing/1.0/forward", 10*time.Second); err != nil {
		t.Fatalf("mediator did not receive forward after rotate: %v", err)
	}

	// Query pickup v2 status handler and check Credo fields
	connsM, _ := mediator.GetConnections()
	if len(connsM) == 0 {
		t.Fatalf("mediator has no connections")
	}
	stReq := mpv2.NewV2StatusRequest()
	raw, _ := json.Marshal(stReq)
	inbound := &transport.InboundMessageContext{Raw: raw, AgentContext: mediator.GetContext(), TypedDI: mediator.GetDependencyManager(), Connection: connsM[0]}
	outStatus, err := pickupHandlers.V2StatusRequestHandlerFunc(inbound)
	if err != nil || outStatus == nil || outStatus.Message == nil {
		t.Fatalf("status-request failed: %v", err)
	}
	b, _ := json.Marshal(outStatus.Message)
	var payload map[string]interface{}
	_ = json.Unmarshal(b, &payload)
	if _, ok := payload["message_count"]; !ok {
		t.Fatalf("status missing message_count")
	}
	if _, ok := payload["live_delivery"]; !ok {
		t.Fatalf("status missing live_delivery")
	}
}
