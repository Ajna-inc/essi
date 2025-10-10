package messagepickup_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/ajna-inc/essi/pkg/core/di"
	coreencoding "github.com/ajna-inc/essi/pkg/core/encoding"
	"github.com/ajna-inc/essi/pkg/core/wallet"
	"github.com/ajna-inc/essi/pkg/didcomm/messages"
	connservices "github.com/ajna-inc/essi/pkg/didcomm/modules/connections/services"
	"github.com/ajna-inc/essi/pkg/didcomm/modules/messagepickup/handlers"
	mpv2 "github.com/ajna-inc/essi/pkg/didcomm/modules/messagepickup/v2"
	envelopeServices "github.com/ajna-inc/essi/pkg/didcomm/services"
	transport "github.com/ajna-inc/essi/pkg/didcomm/transport"
)

// Verifies v2 status fields include message_count, longest_waited_seconds, oldest/newest times and total_bytes
func TestPickupV2_Status_Fields_Computed(t *testing.T) {
	dm := di.NewDependencyManager()
	provider := di.DefaultAgentContextProvider{}
	agentCtx, _ := provider.NewRootContext(dm, "pickup-v2-status")
	ws := wallet.NewWalletService(agentCtx, wallet.NewSimpleKeyRepository())
	dm.RegisterInstance(di.TokenAgentContext, agentCtx)
	dm.RegisterInstance(di.TokenWalletService, ws)

	es := envelopeServices.NewEnvelopeService(agentCtx)
	es.SetTypedDI(dm)
	dm.RegisterInstance(di.TokenEnvelopeService, es)

	conn := connservices.NewConnectionRecord("c-v2-status")

	recip, _ := ws.CreateKey(wallet.KeyTypeEd25519)
	// Build two messages and queue them with controlled timestamps
	msg1 := messages.NewBaseMessage("https://example.org/test/1.0/one")
	enc1, _ := es.PackMessage(msg1, []string{coreencoding.EncodeBase58(recip.PublicKey)}, envelopeServices.PackageTypeAnoncrypt)
	qm1 := &transport.QueuedMessage{ConnectionId: conn.ID, Payload: enc1, CreatedAt: time.Now().Add(-10 * time.Second)}
	transport.GetGlobalQueueRepository().Add(qm1)

	msg2 := messages.NewBaseMessage("https://example.org/test/1.0/two")
	enc2, _ := es.PackMessage(msg2, []string{coreencoding.EncodeBase58(recip.PublicKey)}, envelopeServices.PackageTypeAnoncrypt)
	qm2 := &transport.QueuedMessage{ConnectionId: conn.ID, Payload: enc2, CreatedAt: time.Now().Add(-2 * time.Second)}
	transport.GetGlobalQueueRepository().Add(qm2)

	// Build inbound ctx
	inbound := func(m messages.AgentMessage) *transport.InboundMessageContext {
		raw, _ := json.Marshal(m)
		return &transport.InboundMessageContext{Raw: raw, AgentContext: agentCtx, TypedDI: dm, Connection: conn}
	}

	stReq := mpv2.NewV2StatusRequest()
	out, err := handlers.V2StatusRequestHandlerFunc(inbound(stReq))
	if err != nil || out == nil || out.Message == nil {
		t.Fatalf("status-request failed: %v", err)
	}

	// Decode to generic map to inspect fields
	b, _ := json.Marshal(out.Message)
	var payload map[string]interface{}
	_ = json.Unmarshal(b, &payload)

	if _, ok := payload["message_count"]; !ok {
		t.Fatalf("missing message_count")
	}
	if _, ok := payload["longest_waited_seconds"]; !ok {
		t.Fatalf("missing longest_waited_seconds")
	}
	if _, ok := payload["oldest_received_time"]; !ok {
		t.Fatalf("missing oldest_received_time")
	}
	if _, ok := payload["newest_received_time"]; !ok {
		t.Fatalf("missing newest_received_time")
	}
	if tb, ok := payload["total_bytes"].(float64); !ok || tb <= 0 {
		t.Fatalf("total_bytes not computed: %#v", payload["total_bytes"])
	}
}
