package routing_test

import (
	"encoding/json"
	"testing"

	base "github.com/ajna-inc/essi/pkg/didcomm/messages"
	routinghandlers "github.com/ajna-inc/essi/pkg/didcomm/modules/routing/handlers"
	routingmessages "github.com/ajna-inc/essi/pkg/didcomm/modules/routing/messages"
	envelopeServices "github.com/ajna-inc/essi/pkg/didcomm/services"
	transport "github.com/ajna-inc/essi/pkg/didcomm/transport"
)

func TestForwardHandler_ParsesMessage(t *testing.T) {
	inner := &envelopeServices.EncryptedMessage{Protected: "hdr", IV: "iv", Ciphertext: "ct", Tag: "tag"}
	fwd := routingmessages.NewForward("did:key:z6Mkabc", inner)
	raw, _ := json.Marshal(fwd)

	ctx := &transport.InboundMessageContext{Raw: raw, Message: base.NewBaseMessage(routingmessages.ForwardMessageType)}
	out, err := routinghandlers.ForwardHandlerFunc(ctx)
	if err != nil {
		t.Fatalf("forward handler error: %v", err)
	}
	if out != nil {
		t.Fatalf("expected no outbound from forward handler")
	}
}
