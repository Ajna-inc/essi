//go:build integration
// +build integration

package integration_test

import (
	"fmt"
	"testing"
	"time"

	askarmodule "github.com/ajna-inc/essi/pkg/askar"
	"github.com/ajna-inc/essi/pkg/core/agent"
	corectx "github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/core/di"
	coreencoding "github.com/ajna-inc/essi/pkg/core/encoding"
	coreevents "github.com/ajna-inc/essi/pkg/core/events"
	corewallet "github.com/ajna-inc/essi/pkg/core/wallet"
	didcommmodule "github.com/ajna-inc/essi/pkg/didcomm"
	didcommmessages "github.com/ajna-inc/essi/pkg/didcomm/messages"
	didcommmodels "github.com/ajna-inc/essi/pkg/didcomm/models"
	oob "github.com/ajna-inc/essi/pkg/didcomm/modules/oob"
	oobmsgs "github.com/ajna-inc/essi/pkg/didcomm/modules/oob/messages"
	didcommtransport "github.com/ajna-inc/essi/pkg/didcomm/transport"
	didsmodule "github.com/ajna-inc/essi/pkg/dids/module"
	"github.com/ajna-inc/essi/tests/testutil"
)

// newTestAgent creates a minimal agent with Askar + DIDs + DIDComm
func newTestAgent(t *testing.T, label string, host string, port int, dbPath string) *agent.Agent {
	t.Helper()

	cfg := &corectx.AgentConfig{
		Label:       label,
		InboundHost: host,
		InboundPort: port,
	}
	if port > 0 {
		cfg.Endpoints = []string{fmt.Sprintf("http://%s:%d", host, port)}
	}

	modules := []di.Module{
		askarmodule.NewAskarModuleBuilder().WithSQLiteDatabase(dbPath).WithStoreID(label).WithStoreKey("test-key-123").Build(),
		didsmodule.NewDidsModule(&didsmodule.DidsModuleConfig{EnableDidPeer: true, EnableDidKey: true}),
		didcommmodule.NewDidCommModule(nil),
	}

	a, err := agent.NewAgent(&agent.AgentOptions{Config: cfg, Modules: modules})
	if err != nil {
		t.Fatalf("new agent: %v", err)
	}
	if err := a.Initialize(); err != nil {
		t.Fatalf("init agent: %v", err)
	}
	t.Cleanup(func() { _ = a.Shutdown() })
	return a
}

// waitForConnectionComplete polls GetConnections until a connection reaches complete
func waitForConnectionComplete(t *testing.T, a *agent.Agent, id string, timeout time.Duration) {
    t.Helper()
    // quick short-circuit if already connected
    if conns, _ := a.GetConnections(); len(conns) > 0 {
        for _, c := range conns {
            if id == "" || c.ID == id {
                if c.State == "complete" || c.State == "responded" { return }
            }
        }
    }
    var bus coreevents.Bus
    if any, err := a.GetDependencyManager().Resolve(di.TokenEventBusService); err == nil {
        bus, _ = any.(coreevents.Bus)
    }
    if bus == nil { t.Fatalf("event bus not available for agent") }
    half := timeout / 2
    if _, err := testutil.WaitForConnResponded(bus, id, half); err == nil { return }
    if _, err := testutil.WaitForConnComplete(bus, id, timeout-half); err == nil { return }
    t.Fatalf("timeout waiting for connection %s to complete", id)
}

func TestSelfConnectionE2E(t *testing.T) {
	t.Parallel()

	// Pick fixed ports unlikely to collide in CI; tests run serial by default
	portA := 39101
	portB := 39102

	dir := t.TempDir()
	agentA := newTestAgent(t, "test-agent-A", "127.0.0.1", portA, dir+"/a.db")
	agentB := newTestAgent(t, "test-agent-B", "127.0.0.1", portB, dir+"/b.db")

	// Subscribe to connection state change events on both agents and collect completions
	completeA := make(chan struct{}, 1)
	completeB := make(chan struct{}, 1)
	subA := agentA.GetDependencyManager()
	if any, err := subA.Resolve(di.TokenEventBusService); err == nil {
		if bus, ok := any.(coreevents.Bus); ok {
			_ = bus.Subscribe(coreevents.EventConnectionStateChanged, func(ev coreevents.Event) {
				if m, ok := ev.Data.(map[string]interface{}); ok {
					if st, _ := m["state"].(string); st == "complete" {
						select {
						case completeA <- struct{}{}:
						default:
						}
					}
				}
			})
		}
	}
	subB := agentB.GetDependencyManager()
	if any, err := subB.Resolve(di.TokenEventBusService); err == nil {
		if bus, ok := any.(coreevents.Bus); ok {
			_ = bus.Subscribe(coreevents.EventConnectionStateChanged, func(ev coreevents.Event) {
				if m, ok := ev.Data.(map[string]interface{}); ok {
					if st, _ := m["state"].(string); st == "complete" {
						select {
						case completeB <- struct{}{}:
						default:
						}
					}
				}
			})
		}
	}

	// Resolve OOB API on agent A
	dm := agentA.GetDependencyManager()
	dep, err := dm.Resolve(di.TokenOobApi)
	if err != nil {
		t.Fatalf("resolve OobApi: %v", err)
	}
	oobApi, ok := dep.(*oob.OutOfBandApi)
	if !ok || oobApi == nil {
		t.Fatalf("OobApi not available")
	}

	// Create invitation
	rec, err := oobApi.CreateInvitation(oob.CreateOutOfBandInvitationConfig{Label: "SelfTest"})
	if err != nil {
		t.Fatalf("create invitation: %v", err)
	}
	inv, ok := rec.OutOfBandInvitation.(*oobmsgs.OutOfBandInvitationMessage)
	if !ok || inv == nil {
		t.Fatalf("invalid invitation payload in record")
	}
	url, err := oobApi.InvitationToUrl(inv)
	if err != nil {
		t.Fatalf("build invitation url: %v", err)
	}

	// Process invitation with agent B
	connB, err := agentB.ProcessOOBInvitation(url)
	if err != nil {
		t.Fatalf("agentB process oob: %v", err)
	}

	// Wait for both sides to complete connection
	waitForConnectionComplete(t, agentB, connB.ID, 20*time.Second)
	waitForConnectionComplete(t, agentA, "", 20*time.Second)

	// Print operation breakdown (optional, omitted)

	select {
	case <-completeA:
	case <-time.After(2 * time.Second):
		t.Fatalf("no complete event on agentA")
	}
	select {
	case <-completeB:
	case <-time.After(2 * time.Second):
		t.Fatalf("no complete event on agentB")
	}
}

func TestReturnRouteHandshake(t *testing.T) {
	t.Parallel()

	// Responder with inbound; requester without inbound
	portA := 39201
	dir := t.TempDir()
	responder := newTestAgent(t, "responder", "127.0.0.1", portA, dir+"/responder.db")
	requester := newTestAgent(t, "requester", "", 0, dir+"/requester.db")

	// Create OOB on responder
	dm := responder.GetDependencyManager()
	dep, err := dm.Resolve(di.TokenOobApi)
	if err != nil {
		t.Fatalf("resolve OobApi: %v", err)
	}
	oobApi, ok := dep.(*oob.OutOfBandApi)
	if !ok || oobApi == nil {
		t.Fatalf("OobApi not available")
	}
	rec, err := oobApi.CreateInvitation(oob.CreateOutOfBandInvitationConfig{Label: "RR test"})
	if err != nil {
		t.Fatalf("create invitation: %v", err)
	}
	inv, ok := rec.OutOfBandInvitation.(*oobmsgs.OutOfBandInvitationMessage)
	if !ok || inv == nil {
		t.Fatalf("invalid invitation payload in record")
	}
	url, err := oobApi.InvitationToUrl(inv)
	if err != nil {
		t.Fatalf("build invitation url: %v", err)
	}

	// Process on requester (no inbound). Requester should set return-route; responder replies inline.
	connReq, err := requester.ProcessOOBInvitation(url)
	if err != nil {
		t.Fatalf("requester process oob: %v", err)
	}

	// Wait for both to complete
	waitForConnectionComplete(t, requester, connReq.ID, 20*time.Second)
	waitForConnectionComplete(t, responder, "", 20*time.Second)
}

// TestMessageEventAfterConnection ensures that after connection, sending a message
// from agent A triggers a message.received event on agent B
func TestMessageEventAfterConnection(t *testing.T) {
	t.Parallel()

	portA := 39501
	portB := 39502
	dir := t.TempDir()
	a := newTestAgent(t, "agentA-msg", "127.0.0.1", portA, dir+"/a-msg.db")
	b := newTestAgent(t, "agentB-msg", "127.0.0.1", portB, dir+"/b-msg.db")

	// Subscribe to message.received on B
	msgReceived := make(chan string, 1)
	if any, err := b.GetDependencyManager().Resolve(di.TokenEventBusService); err == nil {
		if bus, ok := any.(coreevents.Bus); ok {
			_ = bus.Subscribe(coreevents.EventMessageReceived, func(ev coreevents.Event) {
				if m, ok := ev.Data.(map[string]interface{}); ok {
					if tp, _ := m["type"].(string); tp == "https://didcomm.org/trust-ping/1.0/ping" {
						select {
						case msgReceived <- tp:
						default:
						}
					}
				}
			})
		}
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
	rec, err := oobApi.CreateInvitation(oob.CreateOutOfBandInvitationConfig{Label: "msgtest"})
	if err != nil {
		t.Fatalf("create invitation: %v", err)
	}
	inv, ok := rec.OutOfBandInvitation.(*oobmsgs.OutOfBandInvitationMessage)
	if !ok || inv == nil {
		t.Fatalf("invalid invitation payload in record")
	}
	url, err := oobApi.InvitationToUrl(inv)
	if err != nil {
		t.Fatalf("build invitation url: %v", err)
	}
	connB, err := b.ProcessOOBInvitation(url)
	if err != nil {
		t.Fatalf("agentB process oob: %v", err)
	}

	// Wait for complete on both agents
	waitForConnectionComplete(t, b, connB.ID, 20*time.Second)
	waitForConnectionComplete(t, a, "", 20*time.Second)

	// Send a base message (trust-ping) from A -> B on the established connection
	connsA, _ := a.GetConnections()
	if len(connsA) == 0 || connsA[0] == nil {
		t.Fatalf("no connection on A")
	}
	connA := connsA[0]

	// Build and send
	msg := didcommmessages.NewBaseMessage("https://didcomm.org/trust-ping/1.0/ping")
	// Resolve MessageSender
	if any, err := a.GetDependencyManager().Resolve(di.TokenMessageSender); err == nil {
		if ms, ok := any.(interface {
			SendMessage(*didcommmodels.OutboundMessageContext) error
		}); ok {
			// Provide explicit service with known responder endpoint and recipient key
			// Resolve recipient key from B's connection MyKeyId
			connsB, _ := b.GetConnections()
			if len(connsB) == 0 || connsB[0] == nil {
				t.Fatalf("no connection on B")
			}
			connB := connsB[0]
			var recipB string
			if any2, err2 := b.GetDependencyManager().Resolve(di.TokenWalletService); err2 == nil {
				if ws, ok2 := any2.(*corewallet.WalletService); ok2 && ws != nil {
					if key, kerr := ws.GetKey(connB.MyKeyId); kerr == nil && key != nil {
						recipB = coreencoding.EncodeBase58(key.PublicKey)
					}
				}
			}
			if recipB == "" {
				t.Fatalf("could not resolve recipient key on B")
			}
			svc := &didcommmodels.ResolvedDidCommService{ID: "svc", ServiceEndpoint: fmt.Sprintf("http://%s:%d", "127.0.0.1", portB), RecipientKeys: []string{recipB}}
			out := didcommmodels.NewOutboundMessageContext(msg, didcommmodels.OutboundMessageContextParams{AgentContext: a.GetContext(), Connection: connA, ServiceParams: &didcommmodels.ServiceMessageParams{Service: svc}})
			if err := ms.SendMessage(out); err != nil {
				t.Fatalf("send message: %v", err)
			}
		} else {
			t.Fatalf("MessageSender not available")
		}
	} else {
		t.Fatalf("resolve MessageSender: %v", err)
	}

	select {
	case <-msgReceived:
		// ok
	case <-time.After(3 * time.Second):
		t.Fatalf("message.received event not observed on agent B")
	}
}

// TestQueueFallback enqueues a message when direct transport is unavailable and queue is advertised
func TestQueueFallback(t *testing.T) {
	t.Parallel()
	portA := 39301
	dir := t.TempDir()
	// Responder with inbound
	responder := newTestAgent(t, "responderQ", "127.0.0.1", portA, dir+"/responderQ.db")
	requester := newTestAgent(t, "requesterQ", "127.0.0.1", 0, dir+"/requesterQ.db")

	// Create OOB on responder
	dm := responder.GetDependencyManager()
	dep, err := dm.Resolve(di.TokenOobApi)
	if err != nil {
		t.Fatalf("resolve OobApi: %v", err)
	}
	oobApi, ok := dep.(*oob.OutOfBandApi)
	if !ok || oobApi == nil {
		t.Fatalf("OobApi not available")
	}
	rec, err := oobApi.CreateInvitation(oob.CreateOutOfBandInvitationConfig{Label: "Q test"})
	if err != nil {
		t.Fatalf("create invitation: %v", err)
	}
	inv, ok := rec.OutOfBandInvitation.(*oobmsgs.OutOfBandInvitationMessage)
	if !ok || inv == nil {
		t.Fatalf("invalid invitation payload in record")
	}
	url, err := oobApi.InvitationToUrl(inv)
	if err != nil {
		t.Fatalf("build invitation url: %v", err)
	}
	connReq, err := requester.ProcessOOBInvitation(url)
	if err != nil {
		t.Fatalf("requester process oob: %v", err)
	}
	waitForConnectionComplete(t, requester, connReq.ID, 20*time.Second)
	waitForConnectionComplete(t, responder, "", 20*time.Second)

	// Make the responder endpoint unreachable to force queue fallback
	// Build a synthetic service to a closed port and send via MessageSender
	conns, _ := requester.GetConnections()
	if len(conns) == 0 || conns[0] == nil {
		t.Fatalf("no connection on requester")
	}
	conn := conns[0]
	dmReq := requester.GetDependencyManager()
	// Instead, send a message via MessageSender with overridden service params
	if any, err := dmReq.Resolve(di.TokenMessageSender); err == nil {
		if ms, ok := any.(interface {
			SendMessage(*didcommmodels.OutboundMessageContext) error
		}); ok {
			// Build a minimal DIDComm message (BaseMessage) to use as payload
			msg := didcommmessages.NewBaseMessage("https://didcomm.org/trust-ping/1.0/ping")
			// Pick an unreachable endpoint and advertise Accept queue in the DIDDoc created earlier
			// Construct a synthetic service for direct call to sendToService by populating ServiceParams
			svc := &didcommmodels.ResolvedDidCommService{ID: "q1", ServiceEndpoint: "http://127.0.0.1:9", RecipientKeys: []string{conn.TheirRecipientKey}}
			out := didcommmodels.NewOutboundMessageContext(msg, didcommmodels.OutboundMessageContextParams{AgentContext: requester.GetContext(), Connection: conn, ServiceParams: &didcommmodels.ServiceMessageParams{Service: svc}})
			_ = ms.SendMessage(out)
		}
	}
	// Inspect queue repo has 1 message
	q := didcommtransport.GetGlobalQueueRepository()
	msgs := q.GetAll()
	if len(msgs) == 0 {
		t.Fatalf("expected queued message, found none")
	}
}
