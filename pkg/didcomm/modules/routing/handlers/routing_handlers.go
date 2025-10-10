package handlers

import (
	"encoding/json"
	"fmt"

	"github.com/ajna-inc/essi/pkg/core/di"
	coreevents "github.com/ajna-inc/essi/pkg/core/events"
	"github.com/ajna-inc/essi/pkg/core/logger"
	"github.com/ajna-inc/essi/pkg/didcomm/models"
	connservices "github.com/ajna-inc/essi/pkg/didcomm/modules/connections/services"
	routingmessages "github.com/ajna-inc/essi/pkg/didcomm/modules/routing/messages"
	routeRecs "github.com/ajna-inc/essi/pkg/didcomm/modules/routing/records"
	"github.com/ajna-inc/essi/pkg/didcomm/transport"
)

// ForwardHandlerFunc handles routing forward messages
func ForwardHandlerFunc(ctx *transport.InboundMessageContext) (*models.OutboundMessageContext, error) {
	var fwd routingmessages.Forward
	if err := json.Unmarshal(ctx.Raw, &fwd); err != nil {
		return nil, fmt.Errorf("failed to parse forward message: %w", err)
	}
	// Delegate to MediatorService to deliver or queue
	if svc := GetMediatorService(ctx); svc != nil {
		_, _ = svc.ProcessForward(&fwd, ctx.Connection)
	}
	return nil, nil
}

// MediationRequestHandlerFunc handles mediation requests
func MediationRequestHandlerFunc(ctx *transport.InboundMessageContext) (*models.OutboundMessageContext, error) {
	var req routingmessages.MediationRequest
	if err := json.Unmarshal(ctx.Raw, &req); err != nil {
		return nil, fmt.Errorf("failed to parse mediation request: %w", err)
	}
	// Resolve ConnectionService to determine mediator endpoint
	var endpoint string
	if ctx != nil && ctx.TypedDI != nil {
		if dep, err := ctx.TypedDI.Resolve(di.TokenConnectionService); err == nil {
			if cs, ok := dep.(*connservices.ConnectionService); ok && cs != nil {
				endpoint = cs.GetDefaultServiceEndpoint()
			}
		}
	}
	if endpoint == "" {
		endpoint = "http://localhost:3001"
	}
	grant := routingmessages.NewMediationGrant(req.GetThreadId(), endpoint, []string{})
	// Reply to the requester connection (ctx.Connection) if present
	out := models.NewOutboundMessageContext(grant, models.OutboundMessageContextParams{
		AgentContext: ctx.AgentContext,
		Connection:   ctx.Connection,
	})
	return out, nil
}

// MediationGrantHandlerFunc handles mediation grant messages
func MediationGrantHandlerFunc(ctx *transport.InboundMessageContext) (*models.OutboundMessageContext, error) {
	var grant routingmessages.MediationGrant
	if err := json.Unmarshal(ctx.Raw, &grant); err != nil {
		return nil, fmt.Errorf("failed to parse mediation grant: %w", err)
	}
	logger.GetDefaultLogger().Infof("🤝 Mediation granted. endpoint=%s routing_keys=%v", grant.Endpoint, grant.RoutingKeys)
	// Persist recipient-side mediation record and set as default
	if ctx != nil && ctx.TypedDI != nil {
		if dep, err := ctx.TypedDI.Resolve(di.TokenMediationRepository); err == nil {
			if repo, ok := dep.(routeRecs.Repository); ok && repo != nil {
				rec := &routeRecs.MediationRecord{
					ID:           ctx.Connection.ID,
					Role:         routeRecs.MediationRoleRecipient,
					State:        routeRecs.MediationStateGranted,
					ConnectionId: ctx.Connection.ID,
					ThreadId:     grant.GetThreadId(),
					Endpoint:     grant.Endpoint,
					RoutingKeys:  grant.RoutingKeys,
					Default:      true,
				}
				_ = repo.Save(ctx.AgentContext, rec)
				// Emit mediation.stateChanged event
				if eb, err := ctx.TypedDI.Resolve(di.TokenEventBusService); err == nil {
					if bus, ok := eb.(coreevents.Bus); ok {
						bus.Publish(coreevents.MediationStateChanged, map[string]interface{}{"id": rec.ID, "state": rec.State, "connectionId": rec.ConnectionId})
					}
				}
				// Trigger did-rotate for existing peer connections (best-effort)
				go func() {
					depCS, _ := ctx.TypedDI.Resolve(di.TokenConnectionService)
					cs, _ := depCS.(*connservices.ConnectionService)
					depMS, _ := ctx.TypedDI.Resolve(di.TokenMessageSender)
					ms, _ := depMS.(interface {
						SendMessage(*models.OutboundMessageContext) error
					})
					if cs == nil || ms == nil {
						return
					}
					rot := connservices.NewDidRotateService(cs)
					conns, err := cs.GetAllConnections()
					if err != nil {
						return
					}
					for _, c := range conns {
						if c == nil || c.ID == rec.ConnectionId {
							continue
						}
						if c.State != connservices.ConnectionStateComplete && c.State != connservices.ConnectionStateResponded {
							continue
						}
						rotateMsg, err := rot.CreateRotate(ctx.AgentContext, &connservices.CreateRotateConfig{Connection: c})
						if err != nil {
							continue
						}
						out := models.NewOutboundMessageContext(rotateMsg, models.OutboundMessageContextParams{AgentContext: ctx.AgentContext, Connection: c})
						_ = ms.SendMessage(out)
					}
				}()
			}
		}
	}
	return nil, nil
}

// MediationDenyHandlerFunc handles mediation deny messages
func MediationDenyHandlerFunc(ctx *transport.InboundMessageContext) (*models.OutboundMessageContext, error) {
	var deny routingmessages.MediationDeny
	if err := json.Unmarshal(ctx.Raw, &deny); err != nil {
		return nil, fmt.Errorf("failed to parse mediation deny: %w", err)
	}
	logger.GetDefaultLogger().Warnf("❌ Mediation denied (thid=%s)", deny.GetThreadId())
	if ctx != nil && ctx.TypedDI != nil {
		if eb, err := ctx.TypedDI.Resolve(di.TokenEventBusService); err == nil {
			if bus, ok := eb.(coreevents.Bus); ok {
				bus.Publish(coreevents.MediationStateChanged, map[string]interface{}{"connectionId": func() string {
					if ctx.Connection != nil {
						return ctx.Connection.ID
					}
					return ""
				}(), "state": "denied"})
			}
		}
	}
	return nil, nil
}

// KeylistUpdateHandlerFunc handles keylist updates
func KeylistUpdateHandlerFunc(ctx *transport.InboundMessageContext) (*models.OutboundMessageContext, error) {
	var upd routingmessages.KeylistUpdate
	if err := json.Unmarshal(ctx.Raw, &upd); err != nil {
		return nil, fmt.Errorf("failed to parse keylist update: %w", err)
	}
	// Acknowledge each update as success (minimal mediator behavior)
	updated := make([]routingmessages.KeylistUpdateResponseItem, 0, len(upd.Updates))
	for _, u := range upd.Updates {
		updated = append(updated, routingmessages.KeylistUpdateResponseItem{RecipientKey: u.RecipientKey, Action: u.Action, Result: routingmessages.KeylistUpdateResultSuccess})
	}
	resp := routingmessages.NewKeylistUpdateResponse(upd.GetThreadId(), updated)
	out := models.NewOutboundMessageContext(resp, models.OutboundMessageContextParams{AgentContext: ctx.AgentContext, Connection: ctx.Connection})
	logger.GetDefaultLogger().Infof("🗝️ Keylist update ack for %d items", len(updated))
	return out, nil
}
