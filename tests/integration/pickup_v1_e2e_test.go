//go:build integration
// +build integration

package integration_test

import (
	"testing"
	"time"

	"github.com/ajna-inc/essi/pkg/core/agent"
	"github.com/ajna-inc/essi/pkg/core/di"
	coreevents "github.com/ajna-inc/essi/pkg/core/events"
	mpv1 "github.com/ajna-inc/essi/pkg/didcomm/modules/messagepickup/v1"
	oob "github.com/ajna-inc/essi/pkg/didcomm/modules/oob"
	oobmessages "github.com/ajna-inc/essi/pkg/didcomm/modules/oob/messages"
	"github.com/ajna-inc/essi/tests/testutil"
)

// Similar wiring as the mediation test but focuses on pickup loop triggering a batch response.
func buildPickupAgents(t *testing.T) (*agent.Agent, *agent.Agent) {
	a := testutil.NewTestAgent(t, testutil.TestAgentOptions{Label: "Holder", UseSubjectTransport: true, Endpoints: []string{"wss://subject/holder"}})
	m := testutil.NewTestAgent(t, testutil.TestAgentOptions{Label: "Mediator", UseSubjectTransport: true, Endpoints: []string{"wss://subject/mediator2"}})
	testutil.SetupSubjectTransports(a.GetDependencyManager(), "wss://subject/holder", m.GetDependencyManager(), "wss://subject/mediator2")
	return a, m
}

func Test_PickupV1_Loop_ReceivesBatch(t *testing.T) {
	holder, mediator := buildPickupAgents(t)

	// Connect holder and mediator via OOB
	var busH coreevents.Bus
	if any, err := holder.GetDependencyManager().Resolve(di.TokenEventBusService); err == nil {
		busH, _ = any.(coreevents.Bus)
	}
	if busH == nil {
		t.Fatalf("holder event bus unavailable")
	}
	dep, err := mediator.GetDependencyManager().Resolve(di.TokenOobApi)
	if err != nil {
		t.Fatalf("resolve OobApi: %v", err)
	}
	oobApi, ok := dep.(*oob.OutOfBandApi)
	if !ok || oobApi == nil {
		t.Fatalf("OobApi not available")
	}
	rec, err := oobApi.CreateInvitation(oob.CreateOutOfBandInvitationConfig{Label: "pickup"})
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

	if _, err := holder.ProcessOOBInvitation(url); err != nil {
		t.Fatalf("process OOB: %v", err)
	}
	if _, err := testutil.WaitForConnComplete(busH, "", 20*time.Second); err != nil {
		t.Fatalf("holder complete: %v", err)
	}

	// Start pickup loop manually against this mediator connection
	conns, _ := holder.GetConnections()
	if len(conns) == 0 {
		t.Fatalf("no holder connections")
	}
	// kickoff a single pickup iteration by calling the internal method via exported API? Not available.
	// Instead, send one explicit batch-pickup message and expect a batch response event.
	if any, err := holder.GetDependencyManager().Resolve(di.TokenMessageSender); err == nil {
		if ms, ok := any.(interface{ SendMessage(*interface{}) error }); ok {
			_ = ms
		}
	}
	// Build a one-off batch-pickup and send via agent SendMessage (uses MessageSender under the hood)
	msg := mpv1.NewV1BatchPickup(10)
	if err := holder.SendMessage(msg, conns[0].ID); err != nil {
		t.Fatalf("send batch-pickup: %v", err)
	}

	// Expect a batch message reception on holder
	if _, err := testutil.WaitForMessageType(busH, mpv1.V1BatchType, 10*time.Second); err != nil {
		t.Fatalf("did not receive v1 batch response: %v", err)
	}
}
