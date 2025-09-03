package handlers

import (
	"github.com/ajna-inc/essi/pkg/core/di"
	services "github.com/ajna-inc/essi/pkg/didcomm/modules/connections/services"
	credsvc "github.com/ajna-inc/essi/pkg/didcomm/modules/credentials/services"
	"github.com/ajna-inc/essi/pkg/didcomm/transport"
)

// getCredentialService resolves the credential service from the inbound context (DI)
func getCredentialService(ctx *transport.InboundMessageContext) *credsvc.CredentialService {
	if ctx != nil && ctx.TypedDI != nil {
		if dep, err := ctx.TypedDI.Resolve(di.TokenCredentialsService); err == nil {
			if s, ok := dep.(*credsvc.CredentialService); ok {
				return s
			}
		}
	}
	return nil
}

// getConnectionService resolves the connection service from the inbound context (DI)
func getConnectionService(ctx *transport.InboundMessageContext) *services.ConnectionService {
	if ctx != nil && ctx.TypedDI != nil {
		if dep, err := ctx.TypedDI.Resolve(di.TokenConnectionService); err == nil {
			if svc, ok := dep.(*services.ConnectionService); ok {
				return svc
			}
		}
	}
	return nil
}