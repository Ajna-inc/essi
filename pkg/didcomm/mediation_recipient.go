package didcomm

import (
	"time"

	"fmt"
	"github.com/ajna-inc/essi/pkg/core/di"
	connservices "github.com/ajna-inc/essi/pkg/didcomm/modules/connections/services"
	routeRecs "github.com/ajna-inc/essi/pkg/didcomm/modules/routing/records"
	routesvc "github.com/ajna-inc/essi/pkg/didcomm/modules/routing/services"
)

// DidCommMediationRecipientApi is a small facade to mirror Credo-TS mediation recipient API one-to-one
type DidCommMediationRecipientApi struct {
	inner *routesvc.MediationRecipientApi
	dm    di.DependencyManager
}

// NewDidCommMediationRecipientApi resolves the underlying recipient API from DI
func NewDidCommMediationRecipientApi(dm di.DependencyManager) *DidCommMediationRecipientApi {
	if any, err := dm.Resolve(di.TokenMediationRecipientApi); err == nil {
		if api, ok := any.(*routesvc.MediationRecipientApi); ok && api != nil {
			return &DidCommMediationRecipientApi{inner: api, dm: dm}
		}
	}
	return &DidCommMediationRecipientApi{inner: nil, dm: dm}
}

func (a *DidCommMediationRecipientApi) RequestAndAwaitGrant(connectionId string, timeout time.Duration) error {
	if a.inner == nil {
		return nil
	}
	// Resolve via connections service
	if any, err := a.dm.Resolve(di.TokenConnectionService); err == nil {
		if cs, ok := any.(*connservices.ConnectionService); ok && cs != nil {
			if conn, err := cs.FindById(connectionId); err == nil && conn != nil {
				return a.inner.RequestAndAwaitGrant(conn, timeout)
			}
			return fmt.Errorf("connection %s not found", connectionId)
		}
	}
	return fmt.Errorf("connection service unavailable")
}

// The facade methods delegate to the inner API. For completeness, we expose
// SetDefaultMediator, GetDefaultMediator, ListMediators, UnsetDefaultMediator, AddKey, RemoveKey
func (a *DidCommMediationRecipientApi) SetDefaultMediator(connectionId string) error {
	if a.inner == nil {
		return nil
	}
	return a.inner.SetDefaultMediator(connectionId)
}
func (a *DidCommMediationRecipientApi) GetDefaultMediator() (*routeRecs.MediationRecord, error) {
	if a.inner == nil {
		return nil, nil
	}
	return a.inner.GetDefaultMediator()
}
func (a *DidCommMediationRecipientApi) ListMediators() ([]*routeRecs.MediationRecord, error) {
	if a.inner == nil {
		return nil, nil
	}
	return a.inner.ListMediators()
}
func (a *DidCommMediationRecipientApi) UnsetDefaultMediator() error {
	if a.inner == nil {
		return nil
	}
	return a.inner.UnsetDefaultMediator()
}
func (a *DidCommMediationRecipientApi) AddKey(key string) error {
	if a.inner == nil {
		return nil
	}
	return a.inner.AddKey(key)
}
func (a *DidCommMediationRecipientApi) RemoveKey(key string) error {
	if a.inner == nil {
		return nil
	}
	return a.inner.RemoveKey(key)
}
