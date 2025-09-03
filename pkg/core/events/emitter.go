package events

import (
	corectx "github.com/ajna-inc/essi/pkg/core/context"
)

// Emitter is a thin helper over Bus to attach correlation id metadata.
type Emitter struct {
	bus Bus
}

func NewEmitter(bus Bus) *Emitter { return &Emitter{bus: bus} }

// Emit attaches context correlation id metadata to the event.
func (e *Emitter) Emit(ctx *corectx.AgentContext, name string, payload interface{}) {
	if e == nil || e.bus == nil {
		return
	}
	md := EventMetadata{}
	if ctx != nil {
		md.ContextCorrelationId = ctx.GetCorrelationId()
	}
	e.bus.PublishWithMetadata(name, payload, md)
}
