package handlers

import (
	corectx "github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/core/di"
	coreevents "github.com/ajna-inc/essi/pkg/core/events"
	oob "github.com/ajna-inc/essi/pkg/didcomm/modules/oob"
	"github.com/ajna-inc/essi/pkg/didcomm/transport"
)

// getEventBus extracts the event bus from the inbound message context
func getEventBus(ctx *transport.InboundMessageContext) coreevents.Bus {
	if ctx != nil && ctx.TypedDI != nil {
		if dep, err := ctx.TypedDI.Resolve(di.TokenEventBusService); err == nil {
			if bus, ok := dep.(coreevents.Bus); ok {
				return bus
			}
		}
	}
	return nil
}

// getOobRepository extracts the OOB repository from the agent context
func getOobRepository(agentCtx *corectx.AgentContext) *oob.OutOfBandRepository {
	if agentCtx != nil && agentCtx.DependencyManager != nil {
		if dm, ok := agentCtx.DependencyManager.(di.DependencyManager); ok {
			if dep, err := dm.Resolve(di.TokenOutOfBandRepository); err == nil {
				if repo, ok := dep.(*oob.OutOfBandRepository); ok {
					return repo
				}
			}
		}
	}
	return nil
}
