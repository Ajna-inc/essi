package messagepickup_test

import (
	"encoding/json"
	"testing"

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

// Verifies that delivered (not acked) messages are not re-delivered until acked
func TestPickupV2_NoRedeliveryWithoutAck(t *testing.T) {
	dm := di.NewDependencyManager()
	provider := di.DefaultAgentContextProvider{}
	agentCtx, _ := provider.NewRootContext(dm, "pickup-v2-redelivery")
	ws := wallet.NewWalletService(agentCtx, wallet.NewSimpleKeyRepository())
	dm.RegisterInstance(di.TokenAgentContext, agentCtx)
	dm.RegisterInstance(di.TokenWalletService, ws)

	es := envelopeServices.NewEnvelopeService(agentCtx)
	es.SetTypedDI(dm)
	dm.RegisterInstance(di.TokenEnvelopeService, es)

	conn := connservices.NewConnectionRecord("c-v2-redelivery")

	recip, _ := ws.CreateKey(wallet.KeyTypeEd25519)
	// Queue two encrypted messages
	for i := 0; i < 2; i++ {
		msg := messages.NewBaseMessage("https://example.org/test/1.0/msg")
		enc, _ := es.PackMessage(msg, []string{coreencoding.EncodeBase58(recip.PublicKey)}, envelopeServices.PackageTypeAnoncrypt)
		transport.GetGlobalQueueRepository().Add(&transport.QueuedMessage{ConnectionId: conn.ID, Payload: enc})
	}

	inbound := func(m messages.AgentMessage) *transport.InboundMessageContext {
		raw, _ := json.Marshal(m)
		return &transport.InboundMessageContext{Raw: raw, AgentContext: agentCtx, TypedDI: dm, Connection: conn}
	}

	// First delivery request (limit=2) should return two attachments and mark them delivered
	del1 := mpv2.NewV2DeliveryRequest(2)
	out1, err := handlers.V2DeliveryRequestHandlerFunc(inbound(del1))
	if err != nil || out1 == nil || out1.Message == nil {
		t.Fatalf("delivery-request #1 failed: %v", err)
	}

	// Second delivery request (limit=2) without ack should return 0 attachments (no redelivery)
	del2 := mpv2.NewV2DeliveryRequest(2)
	out2, err := handlers.V2DeliveryRequestHandlerFunc(inbound(del2))
	if err != nil || out2 == nil || out2.Message == nil {
		t.Fatalf("delivery-request #2 failed: %v", err)
	}
	b2, _ := json.Marshal(out2.Message)
	var payload2 struct {
		Attachments []mpv2.Attachment `json:"attachments"`
	}
	_ = json.Unmarshal(b2, &payload2)
	if len(payload2.Attachments) != 0 {
		t.Fatalf("expected 0 attachments on second delivery without ack, got %d", len(payload2.Attachments))
	}

	// Ack nothing → still non-redeliverable
	ack := mpv2.NewV2MessagesReceived([]string{})
	if _, err := handlers.V2MessagesReceivedHandlerFunc(inbound(ack)); err != nil {
		t.Fatalf("messages-received: %v", err)
	}
}
