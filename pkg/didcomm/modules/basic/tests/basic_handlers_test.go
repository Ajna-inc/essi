package basic_test

import (
	"encoding/json"
	"testing"

	"github.com/ajna-inc/essi/pkg/didcomm/messages"
	basicHandlers "github.com/ajna-inc/essi/pkg/didcomm/modules/basic/handlers"
	transport "github.com/ajna-inc/essi/pkg/didcomm/transport"
)

func TestBasicMessageHandler_ParsesMessage(t *testing.T) {
	m := &basicHandlers.BasicMessage{BaseMessage: messages.NewBaseMessage(basicHandlers.BasicMessageType)}
	m.SentTime = "2021-01-01T00:00:00Z"
	m.Content = "hello"
	raw, _ := json.Marshal(m)

	ctx := &transport.InboundMessageContext{Raw: raw}
	out, err := basicHandlers.BasicMessageHandlerFunc(ctx)
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if out != nil {
		t.Fatalf("expected no outbound context, got %#v", out)
	}
}

func TestProblemReportHandler_ParsesMessage(t *testing.T) {
	pr := &basicHandlers.ProblemReport{BaseMessage: messages.NewBaseMessage(basicHandlers.ProblemReportType)}
	pr.Description.En = "oops"
	pr.Description.Code = "E001"
	raw, _ := json.Marshal(pr)

	ctx := &transport.InboundMessageContext{Raw: raw}
	out, err := basicHandlers.ProblemReportHandlerFunc(ctx)
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if out != nil {
		t.Fatalf("expected no outbound context, got %#v", out)
	}
}
