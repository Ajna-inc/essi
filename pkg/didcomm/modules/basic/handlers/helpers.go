package handlers

import (
	"github.com/ajna-inc/essi/pkg/core/di"
	coreevents "github.com/ajna-inc/essi/pkg/core/events"
	"github.com/ajna-inc/essi/pkg/didcomm/messages"
	"github.com/ajna-inc/essi/pkg/didcomm/transport"
)

// BasicMessage represents a basic message
type BasicMessage struct {
	*messages.BaseMessage
	SentTime string `json:"sent_time"`
	Content  string `json:"content"`
}

// ProblemReport represents a problem report message
type ProblemReport struct {
	*messages.BaseMessage
	Description struct {
		En   string `json:"en"`
		Code string `json:"code"`
	} `json:"description"`
}

// GetEventBus resolves the event bus from the inbound context (DI)
func GetEventBus(ctx *transport.InboundMessageContext) coreevents.Bus {
	if ctx != nil && ctx.TypedDI != nil {
		if dep, err := ctx.TypedDI.Resolve(di.TokenEventBusService); err == nil {
			if bus, ok := dep.(coreevents.Bus); ok {
				return bus
			}
		}
	}
	return nil
}