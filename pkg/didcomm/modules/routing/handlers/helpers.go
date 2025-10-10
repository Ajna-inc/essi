package handlers

import (
	"github.com/ajna-inc/essi/pkg/core/di"
	routesvc "github.com/ajna-inc/essi/pkg/didcomm/modules/routing/services"
	"github.com/ajna-inc/essi/pkg/didcomm/transport"
)

// GetMediatorService resolves the mediator service from the inbound context (DI)
func GetMediatorService(ctx *transport.InboundMessageContext) *routesvc.MediatorService {
	if ctx != nil && ctx.TypedDI != nil {
		if dep, err := ctx.TypedDI.Resolve(di.TokenMediatorService); err == nil {
			if s, ok := dep.(*routesvc.MediatorService); ok {
				return s
			}
		}
	}
	return nil
}
