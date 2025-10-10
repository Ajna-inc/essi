//go:build subjectmem
// +build subjectmem

package integration_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/ajna-inc/essi/pkg/core/di"
	coreevents "github.com/ajna-inc/essi/pkg/core/events"
	connservices "github.com/ajna-inc/essi/pkg/didcomm/modules/connections/services"
	"github.com/ajna-inc/essi/pkg/didcomm/modules/oob"
	oobmessages "github.com/ajna-inc/essi/pkg/didcomm/modules/oob/messages"
	"github.com/ajna-inc/essi/tests/testutil"
)

func registerRotateSvcMem(t *testing.T, dm di.DependencyManager) {
	t.Helper()
	dep, err := dm.Resolve(di.TokenConnectionService)
	if err != nil {
		t.Fatalf("resolve ConnectionService: %v", err)
	}
	cs, _ := dep.(*connservices.ConnectionService)
	dm.RegisterInstance(di.TokenDidRotateService, connservices.NewDidRotateService(cs))
}

func TestDidRotate_SubjectMemory_E2E(t *testing.T) {
	// Two memory agents with subject endpoints
	a := testutil.NewMemoryAgent(t, "A", []string{"wss://subject/a"}, true)
	b := testutil.NewMemoryAgent(t, "B", []string{"wss://subject/b"}, true)
	testutil.SetupSubjectTransports(a.GetDependencyManager(), "wss://subject/a", b.GetDependencyManager(), "wss://subject/b")

	registerRotateSvcMem(t, a.GetDependencyManager())
	registerRotateSvcMem(t, b.GetDependencyManager())

	// Create OOB invitation on A and process on B
	dep, err := a.GetDependencyManager().Resolve(di.TokenOobApi)
	if err != nil {
		t.Fatalf("resolve OobApi: %v", err)
	}
	oobApi, ok := dep.(*oob.OutOfBandApi)
	if !ok || oobApi == nil {
		t.Fatalf("OobApi type unsupported")
	}
	rec, err := oobApi.CreateInvitation(oob.CreateOutOfBandInvitationConfig{Label: "rotate-mem"})
	if err != nil {
		t.Fatalf("create invitation: %v", err)
	}
	inv, ok := rec.OutOfBandInvitation.(*oobmessages.OutOfBandInvitationMessage)
	if !ok || inv == nil {
		t.Fatalf("invalid invitation payload in record")
	}
	url, err := oobApi.InvitationToUrl(inv)
	if err != nil {
		t.Fatalf("InvitationToUrl: %v", err)
	}

	if _, err := b.ProcessOOBInvitation(url); err != nil {
		t.Fatalf("process OOB: %v", err)
	}

    // Wait for complete on both via events
    var busA coreevents.Bus
    if any, err := a.GetDependencyManager().Resolve(di.TokenEventBusService); err == nil { busA, _ = any.(coreevents.Bus) }
    var busB coreevents.Bus
    if any, err := b.GetDependencyManager().Resolve(di.TokenEventBusService); err == nil { busB, _ = any.(coreevents.Bus) }
    if busA == nil || busB == nil { t.Fatalf("event buses not available") }
    if _, err := testutil.WaitForConnComplete(busA, "", 20*time.Second); err != nil { t.Fatalf("A complete: %v", err) }
    if _, err := testutil.WaitForConnComplete(busB, "", 20*time.Second); err != nil { t.Fatalf("B complete: %v", err) }

	// Create rotate on A and send
	connsA, _ := a.GetConnections()
	if len(connsA) == 0 || connsA[0] == nil {
		t.Fatalf("no connection on A")
	}
	cA := connsA[0]
	depCS, err := a.GetDependencyManager().Resolve(di.TokenConnectionService)
	if err != nil {
		t.Fatalf("resolve CS: %v", err)
	}
	csA, _ := depCS.(*connservices.ConnectionService)
	rotSvc := connservices.NewDidRotateService(csA)
	rotate, err := rotSvc.CreateRotate(a.GetContext(), &connservices.CreateRotateConfig{Connection: cA})
	if err != nil {
		t.Fatalf("CreateRotate: %v", err)
	}
	if err := a.SendMessage(rotate, cA.ID); err != nil {
		t.Fatalf("send rotate: %v", err)
	}

	// Expect ack back on A
	if _, err := testutil.WaitForMessageType(busA, "https://didcomm.org/did-rotate/1.0/ack", 5*time.Second); err != nil {
		t.Fatalf("did-rotate ack not observed: %v", err)
	}
}
