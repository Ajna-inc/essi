package routingservices

import (
	"fmt"
	"time"

	corectx "github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/core/di"
	coreevents "github.com/ajna-inc/essi/pkg/core/events"
	"github.com/ajna-inc/essi/pkg/didcomm/models"
	connsvc "github.com/ajna-inc/essi/pkg/didcomm/modules/connections/services"
	routeMsgs "github.com/ajna-inc/essi/pkg/didcomm/modules/routing/messages"
	routeRecs "github.com/ajna-inc/essi/pkg/didcomm/modules/routing/records"
)

// MediationRecipientApi provides recipient-side mediation operations (Credo-TS parity)
type MediationRecipientApi struct {
	ctx *corectx.AgentContext
	dm  di.DependencyManager
}

func NewMediationRecipientApi(ctx *corectx.AgentContext, dm di.DependencyManager) *MediationRecipientApi {
	return &MediationRecipientApi{ctx: ctx, dm: dm}
}

// RequestAndAwaitGrant sends mediate-request to the given connection and waits for grant
func (a *MediationRecipientApi) RequestAndAwaitGrant(connection *connsvc.ConnectionRecord, timeout time.Duration) error {
	if connection == nil {
		return fmt.Errorf("connection required")
	}
	// emit requested event
	if eb, err := a.dm.Resolve(di.TokenEventBusService); err == nil {
		if bus, ok := eb.(coreevents.Bus); ok {
			bus.Publish(coreevents.MediationStateChanged, map[string]interface{}{"connectionId": connection.ID, "state": "requested"})
		}
	}
	// build request
	req := routeMsgs.NewMediationRequest()
	if thid, ok := connection.Tags["threadId"]; ok && thid != "" {
		req.SetThreadId(thid)
	}
	out := models.NewOutboundMessageContext(req, models.OutboundMessageContextParams{AgentContext: a.ctx, Connection: connection})
	// send via message sender
	if dep, err := a.dm.Resolve(di.TokenMessageSender); err == nil {
		if ms, ok := dep.(interface {
			SendMessage(*models.OutboundMessageContext) error
		}); ok {
			_ = ms.SendMessage(out)
		}
	}
	// wait for grant via event bus
	var bus coreevents.Bus
	if eb, err := a.dm.Resolve(di.TokenEventBusService); err == nil {
		bus, _ = eb.(coreevents.Bus)
	}
	if bus == nil {
		return fmt.Errorf("event bus not available")
	}
	ch := make(chan struct{}, 1)
	unsub := bus.Subscribe(coreevents.EventMessageReceived, func(ev coreevents.Event) {
		if m, ok := ev.Data.(map[string]interface{}); ok {
			if tp, _ := m["type"].(string); tp == routeMsgs.MediationGrantType {
				select {
				case ch <- struct{}{}:
				default:
				}
			}
		}
	})
	defer unsub()
	select {
	case <-ch:
		return nil
	case <-time.After(timeout):
		return fmt.Errorf("timeout awaiting grant")
	}
}

// SetDefaultMediator marks the mediation record for connection as default, unsetting previous default
func (a *MediationRecipientApi) SetDefaultMediator(connectionId string) error {
	dep, err := a.dm.Resolve(di.TokenMediationRepository)
	if err != nil {
		return err
	}
	repo, ok := dep.(routeRecs.Repository)
	if !ok || repo == nil {
		return fmt.Errorf("mediation repository unavailable")
	}
	// unset existing default
	if def, err := repo.FindDefault(a.ctx); err == nil && def != nil {
		def.Default = false
		_ = repo.Update(a.ctx, def)
	}
	// set for given connection
	rec, err := repo.FindByConnectionId(a.ctx, connectionId)
	if err != nil {
		return err
	}
	rec.Default = true
	if err := repo.Update(a.ctx, rec); err != nil {
		return err
	}
	// emit stateChanged
	if eb, err := a.dm.Resolve(di.TokenEventBusService); err == nil {
		if bus, ok := eb.(coreevents.Bus); ok {
			bus.Publish(coreevents.MediationStateChanged, map[string]interface{}{"id": rec.ID, "state": rec.State, "connectionId": rec.ConnectionId})
		}
	}
	return nil
}

// GetDefaultMediator returns the default mediation record
func (a *MediationRecipientApi) GetDefaultMediator() (*routeRecs.MediationRecord, error) {
	dep, err := a.dm.Resolve(di.TokenMediationRepository)
	if err != nil {
		return nil, err
	}
	repo, _ := dep.(routeRecs.Repository)
	if repo == nil {
		return nil, fmt.Errorf("mediation repo unavailable")
	}
	return repo.FindDefault(a.ctx)
}

// AddKey adds a recipient key via keylist-update to the default mediator
func (a *MediationRecipientApi) AddKey(key string) error {
	return a.keylistUpdate(key, routeMsgs.KeylistUpdateAdd)
}

// RemoveKey removes a recipient key via keylist-update from the default mediator
func (a *MediationRecipientApi) RemoveKey(key string) error {
	return a.keylistUpdate(key, routeMsgs.KeylistUpdateRemove)
}

func (a *MediationRecipientApi) keylistUpdate(key string, action routeMsgs.KeylistUpdateAction) error {
	dep, err := a.dm.Resolve(di.TokenMediationRepository)
	if err != nil {
		return err
	}
	repo, _ := dep.(routeRecs.Repository)
	if repo == nil {
		return fmt.Errorf("mediation repo unavailable")
	}
	rec, err := repo.FindDefault(a.ctx)
	if err != nil {
		return fmt.Errorf("no default mediator: %w", err)
	}
	upd := routeMsgs.NewKeylistUpdate([]routeMsgs.KeylistUpdateItem{{RecipientKey: key, Action: action}})
	if thid := rec.ThreadId; thid != "" {
		upd.SetThreadId(thid)
	}
	// Resolve actual connection record by id
	var conn *connsvc.ConnectionRecord
	if depCS, err := a.dm.Resolve(di.TokenConnectionService); err == nil {
		if cs, ok := depCS.(*connsvc.ConnectionService); ok && cs != nil {
			if c, err := cs.FindById(rec.ConnectionId); err == nil {
				conn = c
			}
		}
	}
	if conn == nil {
		return fmt.Errorf("connection not found for mediator")
	}
	out := models.NewOutboundMessageContext(upd, models.OutboundMessageContextParams{AgentContext: a.ctx, Connection: conn})
	if dep2, err := a.dm.Resolve(di.TokenMessageSender); err == nil {
		if ms, ok := dep2.(interface {
			SendMessage(*models.OutboundMessageContext) error
		}); ok {
			return ms.SendMessage(out)
		}
	}
	return fmt.Errorf("message sender unavailable")
}

// ListMediators returns all mediation records
func (a *MediationRecipientApi) ListMediators() ([]*routeRecs.MediationRecord, error) {
	dep, err := a.dm.Resolve(di.TokenMediationRepository)
	if err != nil {
		return nil, err
	}
	repo, _ := dep.(routeRecs.Repository)
	if repo == nil {
		return nil, fmt.Errorf("mediation repo unavailable")
	}
	return repo.GetAll(a.ctx)
}

// UnsetDefaultMediator clears the default flag on all mediators
func (a *MediationRecipientApi) UnsetDefaultMediator() error {
	dep, err := a.dm.Resolve(di.TokenMediationRepository)
	if err != nil {
		return err
	}
	repo, _ := dep.(routeRecs.Repository)
	if repo == nil {
		return fmt.Errorf("mediation repo unavailable")
	}
	list, err := repo.GetAll(a.ctx)
	if err != nil {
		return err
	}
	for _, r := range list {
		if r.Default {
			r.Default = false
			_ = repo.Update(a.ctx, r)
		}
	}
	return nil
}
