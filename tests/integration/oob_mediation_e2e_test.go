//go:build integration
// +build integration

package integration_test

import (
	"testing"
	"time"

	"github.com/ajna-inc/essi/pkg/core/di"
	coreevents "github.com/ajna-inc/essi/pkg/core/events"
	oob "github.com/ajna-inc/essi/pkg/didcomm/modules/oob"
	oobmessages "github.com/ajna-inc/essi/pkg/didcomm/modules/oob/messages"
	routingmessages "github.com/ajna-inc/essi/pkg/didcomm/modules/routing/messages"
	"github.com/ajna-inc/essi/tests/testutil"
)

// Provisions mediation via Agent.ProvisionMediatorIfConfigured using OOB URL from mediator.
func Test_OOB_Mediation_AutoProvision(t *testing.T) {
	// Setup mediator agent first and create OOB URL
	mediator := testutil.NewTestAgent(t, testutil.TestAgentOptions{Label: "Mediator-AP", UseSubjectTransport: true, Endpoints: []string{"wss://subject/mediator-ap"}})
	dep, err := mediator.GetDependencyManager().Resolve(di.TokenOobApi)
	if err != nil {
		t.Fatalf("resolve OobApi: %v", err)
	}
	oobApi, ok := dep.(*oob.OutOfBandApi)
	if !ok || oobApi == nil {
		t.Fatalf("OobApi not available")
	}
	rec, err := oobApi.CreateInvitation(oob.CreateOutOfBandInvitationConfig{Label: "mediator-ap"})
	if err != nil {
		t.Fatalf("create invitation: %v", err)
	}
	inv, ok := rec.OutOfBandInvitation.(*oobmessages.OutOfBandInvitationMessage)
	if !ok || inv == nil {
		t.Fatalf("invalid invitation payload")
	}
	url, err := oobApi.InvitationToUrl(inv)
	if err != nil {
		t.Fatalf("InvitationToUrl: %v", err)
	}

	// Now create holder/recipient agent with mediator URL in config and subject transport
	holder := testutil.NewTestAgent(t, testutil.TestAgentOptions{Label: "Holder-AP", UseSubjectTransport: true, Endpoints: []string{"wss://subject/holder-ap"}, MediatorInvitationUrl: url})
	testutil.SetupSubjectTransports(holder.GetDependencyManager(), "wss://subject/holder-ap", mediator.GetDependencyManager(), "wss://subject/mediator-ap")

	// Manually trigger auto-provision based on config
	holder.ProvisionMediatorIfConfigured()

	// Wait for mediation grant on holder
	var bus coreevents.Bus
	if any, err := holder.GetDependencyManager().Resolve(di.TokenEventBusService); err == nil {
		bus, _ = any.(coreevents.Bus)
	}
	if bus == nil {
		t.Fatalf("holder event bus unavailable")
	}
	if _, err := testutil.WaitForMessageType(bus, routingmessages.MediationGrantType, 20*time.Second); err != nil {
		t.Fatalf("did not receive mediation grant: %v", err)
	}
}
