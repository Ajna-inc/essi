//go:build integration
// +build integration

package integration_test

import (
    "encoding/json"
    "testing"
    "time"
	"github.com/ajna-inc/essi/pkg/core/agent"
	"github.com/ajna-inc/essi/pkg/core/di"
	coreencoding "github.com/ajna-inc/essi/pkg/core/encoding"
    coreevents "github.com/ajna-inc/essi/pkg/core/events"
    
	"github.com/ajna-inc/essi/pkg/didcomm/messages"
    didcommodels "github.com/ajna-inc/essi/pkg/didcomm/models"
    connservices "github.com/ajna-inc/essi/pkg/didcomm/modules/connections/services"
	pickupHandlers "github.com/ajna-inc/essi/pkg/didcomm/modules/messagepickup/handlers"
	mpv2 "github.com/ajna-inc/essi/pkg/didcomm/modules/messagepickup/v2"
	oob "github.com/ajna-inc/essi/pkg/didcomm/modules/oob"
	oobmessages "github.com/ajna-inc/essi/pkg/didcomm/modules/oob/messages"
	routingmessages "github.com/ajna-inc/essi/pkg/didcomm/modules/routing/messages"
	transport "github.com/ajna-inc/essi/pkg/didcomm/transport"
	"github.com/ajna-inc/essi/tests/testutil"
)

// buildAgent is a helper to construct an agent with subject transport and a single subject endpoint
func buildAgent(t *testing.T, label, endpoint string) *agent.Agent {
	a := testutil.NewTestAgent(t, testutil.TestAgentOptions{Label: label, UseSubjectTransport: true, Endpoints: []string{endpoint}})
	return a
}

// oobConnect creates an OOB invitation on inviter and processes it on invitee. Returns invitee's connection record.
func oobConnect(t *testing.T, inviter *agent.Agent, invitee *agent.Agent) *connservices.ConnectionRecord {
	t.Helper()
	// Create invitation on inviter
	dep, err := inviter.GetDependencyManager().Resolve(di.TokenOobApi)
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
	inv, ok := rec.OutOfBandInvitation.(*oobmessages.OutOfBandInvitationMessage)
	if !ok || inv == nil {
		t.Fatalf("unexpected invitation type in record")
	}
	url, err := oobApi.InvitationToUrl(inv)
	if err != nil {
		t.Fatalf("InvitationToUrl: %v", err)
	}
	// Process on invitee
	conn, err := invitee.ProcessOOBInvitation(url)
	if err != nil {
		t.Fatalf("process OOB: %v", err)
	}
    // Wait for invitee completion; inviter usually reaches complete soon after
    testutil.ReturnWhenIsConnected(t, invitee, conn.ID, 40*time.Second)
	return conn
}

func TestMediatedRotateRoutesViaMediator(t *testing.T) {
	// Build three agents
	holder := buildAgent(t, "Holder", "wss://subject/holder")
	partner := buildAgent(t, "Partner", "wss://subject/partner")
	mediator := buildAgent(t, "Mediator", "wss://subject/mediator")

	// Wire subject endpoints for all three
	testutil.SetupSubjectTransports(holder.GetDependencyManager(), "wss://subject/holder", mediator.GetDependencyManager(), "wss://subject/mediator")
	testutil.SetupSubjectTransports(partner.GetDependencyManager(), "wss://subject/partner", holder.GetDependencyManager(), "")

	// Connect Holder <-> Partner
	_ = oobConnect(t, holder, partner)
	// Connect Mediator <-> Holder
	connHM := oobConnect(t, mediator, holder)

	// Request mediation on Holder→Mediator connection and await grant
	testutil.RequestAndAwaitGrant(t, holder, connHM.ID, 15*time.Second)

	// Choose a recent holder wallet key to register at mediator (base58)
	keys, err := holder.GetWalletService().ListKeys()
	if err != nil || len(keys) == 0 {
		t.Fatalf("holder wallet has no keys: %v", err)
	}
	recipKeyB58 := coreencoding.EncodeBase58(keys[len(keys)-1].PublicKey)
	if err := holder.SendKeylistUpdate(connHM.ID, recipKeyB58, routingmessages.KeylistUpdateAdd); err != nil {
		t.Fatalf("SendKeylistUpdate failed: %v", err)
	}

	// Clear queue before sending to ensure deterministic assertion
	transport.GetGlobalQueueRepository().Clear()

	// Partner sends a trust-ping to Holder
	connsP, _ := partner.GetConnections()
	if len(connsP) == 0 {
		t.Fatalf("partner has no connections")
	}
	ping := messages.NewBaseMessage("https://didcomm.org/trust-ping/1.0/ping")
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

    // Wait for forward to be received on mediator (routing/1.0/forward), then check queue
    var bus coreevents.Bus
    if any, err := mediator.GetDependencyManager().Resolve(di.TokenEventBusService); err == nil {
        bus, _ = any.(coreevents.Bus)
    }
    if bus == nil { t.Fatalf("mediator event bus not available") }
    if _, err := testutil.WaitForMessageType(bus, "https://didcomm.org/routing/1.0/forward", 10*time.Second); err != nil {
        t.Fatalf("mediator did not receive forward after rotate: %v", err)
    }
    queued := transport.GetGlobalQueueRepository().GetAll()
    if len(queued) == 0 { t.Fatalf("expected at least one message queued at mediator after rotate routing") }

	// Verify pickup v2 status fields are Credo-compatible
	// Use mediator side connection to holder for status
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
	// Marshal to JSON and check keys
	sj, _ := json.Marshal(outStatus.Message)
	var m map[string]interface{}
	_ = json.Unmarshal(sj, &m)
	if _, ok := m["message_count"]; !ok {
		t.Fatalf("status missing message_count field")
	}
	if _, ok := m["live_delivery"]; !ok {
		t.Fatalf("status missing live_delivery field")
	}
	if _, ok := m["oldest_received_time"]; !ok {
		t.Fatalf("status missing oldest_received_time field")
	}
	if _, ok := m["newest_received_time"]; !ok {
		t.Fatalf("status missing newest_received_time field")
	}
}
