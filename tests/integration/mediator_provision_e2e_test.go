//go:build integration
// +build integration

package integration_test

import (
	"testing"
	"time"

	"github.com/ajna-inc/essi/pkg/core/agent"
	"github.com/ajna-inc/essi/pkg/core/di"
	coreevents "github.com/ajna-inc/essi/pkg/core/events"
	oob "github.com/ajna-inc/essi/pkg/didcomm/modules/oob"
	oobmessages "github.com/ajna-inc/essi/pkg/didcomm/modules/oob/messages"
	routingmessages "github.com/ajna-inc/essi/pkg/didcomm/modules/routing/messages"
	"github.com/ajna-inc/essi/tests/testutil"
)

// Build two subject-transport agents and wire them together.
func buildSubjectAgents(t *testing.T) (*agent.Agent, *agent.Agent) {
	a := testutil.NewTestAgent(t, testutil.TestAgentOptions{Label: "Alice", UseSubjectTransport: true, Endpoints: []string{"wss://subject/alice"}})
	m := testutil.NewTestAgent(t, testutil.TestAgentOptions{Label: "Mediator", UseSubjectTransport: true, Endpoints: []string{"wss://subject/mediator"}})
	testutil.SetupSubjectTransports(a.GetDependencyManager(), "wss://subject/alice", m.GetDependencyManager(), "wss://subject/mediator")
	return a, m
}

func Test_OOB_Mediation_Provision_And_Keylist(t *testing.T) {
	alice, mediator := buildSubjectAgents(t)

	// Event buses
	var busA, busM coreevents.Bus
	if any, err := alice.GetDependencyManager().Resolve(di.TokenEventBusService); err == nil {
		busA, _ = any.(coreevents.Bus)
	}
	if any, err := mediator.GetDependencyManager().Resolve(di.TokenEventBusService); err == nil {
		busM, _ = any.(coreevents.Bus)
	}
	if busA == nil || busM == nil {
		t.Fatalf("event buses unavailable")
	}

	// Mediator creates an OOB invitation
	dep, err := mediator.GetDependencyManager().Resolve(di.TokenOobApi)
	if err != nil {
		t.Fatalf("resolve OobApi: %v", err)
	}
	oobApi, ok := dep.(*oob.OutOfBandApi)
	if !ok || oobApi == nil {
		t.Fatalf("OobApi not available")
	}
	rec, err := oobApi.CreateInvitation(oob.CreateOutOfBandInvitationConfig{Label: "mediation"})
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

	// Alice processes invitation and connects
	if _, err := alice.ProcessOOBInvitation(url); err != nil {
		t.Fatalf("process OOB: %v", err)
	}
	if _, err := testutil.WaitForConnComplete(busA, "", 20*time.Second); err != nil {
		t.Fatalf("alice complete: %v", err)
	}
	if _, err := testutil.WaitForConnComplete(busM, "", 20*time.Second); err != nil {
		t.Fatalf("mediator complete: %v", err)
	}

	// Alice requests mediation to mediator connection
	conns, _ := alice.GetConnections()
	if len(conns) == 0 {
		t.Fatalf("no connections on alice")
	}
	if err := alice.RequestMediation(conns[0].ID); err != nil {
		t.Fatalf("request mediation: %v", err)
	}

	// Expect mediate-grant received on Alice (bus message-received)
	if _, err := testutil.WaitForMessageType(busA, routingmessages.MediationGrantType, 10*time.Second); err != nil {
		t.Fatalf("did not receive mediation grant: %v", err)
	}

	// Send a keylist-update add for Alice's key
	recs, _ := alice.GetConnections()
	if len(recs) == 0 {
		t.Fatalf("no connections on alice after grant")
	}
	my := recs[0].MyKeyId
	if my == "" {
		t.Fatalf("missing MyKeyId on connection")
	}
	// Alice wallet lookup for public key requires DI; skip and send any placeholder key if missing
	// For now, just assert we receive keylist-update-response when we trigger SendKeylistUpdate
	_ = alice.SendKeylistUpdate(recs[0].ID, "z6MkkPlaceholderKeyForTest", routingmessages.KeylistUpdateAdd)
	if _, err := testutil.WaitForMessageType(busA, routingmessages.KeylistUpdateResponseType, 10*time.Second); err != nil {
		t.Fatalf("did not receive keylist-update-response: %v", err)
	}
}
