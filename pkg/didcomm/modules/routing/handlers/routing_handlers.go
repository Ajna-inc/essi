package handlers

import (
	"encoding/json"
	"fmt"

	"github.com/ajna-inc/essi/pkg/core/logger"
	"github.com/ajna-inc/essi/pkg/didcomm/models"
	routingmessages "github.com/ajna-inc/essi/pkg/didcomm/modules/routing/messages"
	"github.com/ajna-inc/essi/pkg/didcomm/transport"
)

// ForwardHandlerFunc handles routing forward messages
func ForwardHandlerFunc(ctx *transport.InboundMessageContext) (*models.OutboundMessageContext, error) {
	var fwd routingmessages.Forward
	if err := json.Unmarshal(ctx.Raw, &fwd); err != nil {
		return nil, fmt.Errorf("failed to parse forward message: %w", err)
	}
	return nil, nil
}

// MediationRequestHandlerFunc handles mediation requests
func MediationRequestHandlerFunc(ctx *transport.InboundMessageContext) (*models.OutboundMessageContext, error) {
	var req routingmessages.MediationRequest
	if err := json.Unmarshal(ctx.Raw, &req); err != nil {
		return nil, fmt.Errorf("failed to parse mediation request: %w", err)
	}
	return nil, nil
}

// MediationGrantHandlerFunc handles mediation grant messages
func MediationGrantHandlerFunc(ctx *transport.InboundMessageContext) (*models.OutboundMessageContext, error) {
	var grant routingmessages.MediationGrant
	if err := json.Unmarshal(ctx.Raw, &grant); err != nil {
		return nil, fmt.Errorf("failed to parse mediation grant: %w", err)
	}
	logger.GetDefaultLogger().Infof("🤝 Mediation granted. endpoint=%s routing_keys=%v", grant.Endpoint, grant.RoutingKeys)
	return nil, nil
}

// MediationDenyHandlerFunc handles mediation deny messages
func MediationDenyHandlerFunc(ctx *transport.InboundMessageContext) (*models.OutboundMessageContext, error) {
	var deny routingmessages.MediationDeny
	if err := json.Unmarshal(ctx.Raw, &deny); err != nil {
		return nil, fmt.Errorf("failed to parse mediation deny: %w", err)
	}
	logger.GetDefaultLogger().Warnf("❌ Mediation denied (thid=%s)", deny.GetThreadId())
	return nil, nil
}

// KeylistUpdateHandlerFunc handles keylist updates
func KeylistUpdateHandlerFunc(ctx *transport.InboundMessageContext) (*models.OutboundMessageContext, error) {
	var resp routingmessages.KeylistUpdateResponse
	if err := json.Unmarshal(ctx.Raw, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse keylist update response: %w", err)
	}
	logger.GetDefaultLogger().Infof("🗝️ Keylist updated: %v", resp.Updated)
	return nil, nil
}
