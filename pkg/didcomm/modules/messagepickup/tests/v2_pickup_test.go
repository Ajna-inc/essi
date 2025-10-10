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

func TestPickupV2_Status_Delivery_Ack(t *testing.T) {
	dm := di.NewDependencyManager()
	provider := di.DefaultAgentContextProvider{}
	agentCtx, _ := provider.NewRootContext(dm, "pickup-v2")
	ws := wallet.NewWalletService(agentCtx, wallet.NewSimpleKeyRepository())
	dm.RegisterInstance(di.TokenAgentContext, agentCtx)
	dm.RegisterInstance(di.TokenWalletService, ws)

	// Envelope service to create encrypted messages
	es := envelopeServices.NewEnvelopeService(agentCtx)
	es.SetTypedDI(dm)
	dm.RegisterInstance(di.TokenEnvelopeService, es)

	// Connection context
	conn := connservices.NewConnectionRecord("c-v2")

	// Queue two encrypted messages
	recip, _ := ws.CreateKey(wallet.KeyTypeEd25519)
	msg1 := messages.NewBaseMessage("https://example.org/test/1.0/one")
	enc1, _ := es.PackMessage(msg1, []string{coreencoding.EncodeBase58(recip.PublicKey)}, envelopeServices.PackageTypeAnoncrypt)
	transport.GetGlobalQueueRepository().Add(&transport.QueuedMessage{ConnectionId: conn.ID, Payload: enc1})
	msg2 := messages.NewBaseMessage("https://example.org/test/1.0/two")
	enc2, _ := es.PackMessage(msg2, []string{coreencoding.EncodeBase58(recip.PublicKey)}, envelopeServices.PackageTypeAnoncrypt)
	transport.GetGlobalQueueRepository().Add(&transport.QueuedMessage{ConnectionId: conn.ID, Payload: enc2})

	// Build inbound ctx helper
	inbound := func(m messages.AgentMessage) *transport.InboundMessageContext {
		raw, _ := json.Marshal(m)
		return &transport.InboundMessageContext{Raw: raw, AgentContext: agentCtx, TypedDI: dm, Connection: conn}
	}

	// Status request → returns status with count 2
	stReq := mpv2.NewV2StatusRequest()
	if out, err := handlers.V2StatusRequestHandlerFunc(inbound(stReq)); err != nil {
		t.Fatalf("status-request handler: %v", err)
	} else if out == nil {
		t.Fatalf("expected status response")
	}

	// Delivery request limit 1 → returns 1 attachment
	delReq := mpv2.NewV2DeliveryRequest(1)
	if out, err := handlers.V2DeliveryRequestHandlerFunc(inbound(delReq)); err != nil {
		t.Fatalf("delivery-request handler: %v", err)
	} else if out == nil {
		t.Fatalf("expected delivery response")
	}

	// Messages received ack → should not error
	ack := mpv2.NewV2MessagesReceived([]string{"id1"})
	if _, err := handlers.V2MessagesReceivedHandlerFunc(inbound(ack)); err != nil {
		t.Fatalf("messages-received handler: %v", err)
	}
}
