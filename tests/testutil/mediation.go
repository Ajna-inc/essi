package testutil

import (
	"testing"
	"time"

	"github.com/ajna-inc/essi/pkg/core/agent"
	"github.com/ajna-inc/essi/pkg/core/di"
	coreevents "github.com/ajna-inc/essi/pkg/core/events"
	routingmessages "github.com/ajna-inc/essi/pkg/didcomm/modules/routing/messages"
)

// RequestAndAwaitGrant sends a mediate-request via Agent and waits for mediate-grant.
func RequestAndAwaitGrant(t *testing.T, a *agent.Agent, connectionId string, timeout time.Duration) {
	t.Helper()
	var bus coreevents.Bus
	if any, err := a.GetDependencyManager().Resolve(di.TokenEventBusService); err == nil {
		bus, _ = any.(coreevents.Bus)
	}
	if bus == nil {
		t.Fatalf("event bus not available")
	}
	if err := a.RequestMediation(connectionId); err != nil {
		t.Fatalf("request mediation: %v", err)
	}
	if _, err := WaitForMessageType(bus, routingmessages.MediationGrantType, timeout); err != nil {
		t.Fatalf("did not receive mediation grant: %v", err)
	}
}
