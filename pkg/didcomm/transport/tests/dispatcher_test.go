package transport_test

import (
	"testing"
	"time"

	"github.com/ajna-inc/essi/pkg/didcomm/messages"
	"github.com/ajna-inc/essi/pkg/didcomm/models"
	transport "github.com/ajna-inc/essi/pkg/didcomm/transport"
	"github.com/ajna-inc/essi/tests/testutil"
)

// dummySender captures outbound messages passed by Dispatcher
func TestDispatcher_Dispatch_InvokesSender(t *testing.T) {
	d := transport.NewDispatcher()
	spy := testutil.NewSenderSpy()
	d.SetMessageSender(spy)

	const inType = "https://example.org/test/1.0/ping"
	// Register handler that returns minimal response
	d.Register(inType, func(in *transport.InboundMessageContext) (*models.OutboundMessageContext, error) {
		resp := messages.NewBaseMessage("https://example.org/test/1.0/ping_response")
		out := models.NewOutboundMessageContext(resp, models.OutboundMessageContextParams{})
		return out, nil
	})

	inbound := &transport.InboundMessageContext{Message: messages.NewBaseMessage(inType)}
	if err := d.Dispatch(inbound); err != nil {
		t.Fatalf("dispatch returned error: %v", err)
	}

	select {
	case out := <-spy.Ch:
		if out == nil || out.Message == nil || out.Message.GetType() != "https://example.org/test/1.0/ping_response" {
			t.Fatalf("unexpected outbound: %#v", out)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for sender")
	}
}

func TestDispatcher_DispatchSync_UnknownType(t *testing.T) {
	d := transport.NewDispatcher()
	inbound := &transport.InboundMessageContext{Message: messages.NewBaseMessage("https://example.org/unknown/1.0/msg")}
	if _, err := d.DispatchSync(inbound); err == nil {
		t.Fatalf("expected error for unknown message type")
	}
}
