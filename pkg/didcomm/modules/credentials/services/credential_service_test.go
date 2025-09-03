package services

import (
	"testing"

	corectx "github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/core/di"
	coreevents "github.com/ajna-inc/essi/pkg/core/events"
	credmsgs "github.com/ajna-inc/essi/pkg/didcomm/modules/credentials/messages"
	credrecs "github.com/ajna-inc/essi/pkg/didcomm/modules/credentials/records"
)

type stubHolder struct{}

func (h *stubHolder) EnsureLinkSecret() (string, error) { return "default", nil }
func (h *stubHolder) CreateCredentialRequest(offer map[string]interface{}) (map[string]interface{}, map[string]interface{}, error) {
	return map[string]interface{}{"req": true}, map[string]interface{}{"meta": true}, nil
}
func (h *stubHolder) ProcessIssuedCredential(credential map[string]interface{}, requestMetadata map[string]interface{}) error {
	return nil
}

func TestProcessOffer_BuildsRequestAndStoresMetadata(t *testing.T) {
	t.Skip("TODO: Update test to use real storage via Askar")
	ctx := corectx.NewAgentContext(corectx.AgentContextOptions{})
	var repo credrecs.Repository // TODO: Initialize with real storage
	dm := di.NewDependencyManager()
	dm.RegisterInstance(di.TokenEventBusService, coreevents.NewSimpleBus())
	svc := NewCredentialService(ctx, dm, repo)
	ctx.DependencyManager = dm
	svc.SetAnoncredsHolder(&stubHolder{})

	offer := credmsgs.NewOfferCredentialV2()
	offer.SetThreadId("thid-1")
	offer.Formats = append(offer.Formats, credmsgs.FormatEntry{AttachID: "att-1", Format: "anoncreds/credential-offer@v1"})
	offer.OffersAttach = append(offer.OffersAttach, credmsgs.Attachment("att-1", map[string]interface{}{"nonce": "123"}))

	req, rec, err := svc.ProcessOffer("thid-1", "conn-1", offer)
	if err != nil {
		t.Fatalf("ProcessOffer error: %v", err)
	}
	if req == nil {
		t.Fatalf("expected request to be built")
	}
	if rec == nil {
		t.Fatalf("expected record to be returned")
	}
	if rec.RequestMetadata == nil {
		t.Fatalf("expected RequestMetadata to be stored on record")
	}
}

func TestProcessIssue_UsesStoredRequestMetadata(t *testing.T) {
	t.Skip("TODO: Update test to use real storage via Askar")
	ctx := corectx.NewAgentContext(corectx.AgentContextOptions{})
	var repo credrecs.Repository // TODO: Initialize with real storage
	dm := di.NewDependencyManager()
	dm.RegisterInstance(di.TokenEventBusService, coreevents.NewSimpleBus())
	svc := NewCredentialService(ctx, dm, repo)
	ctx.DependencyManager = dm
	svc.SetAnoncredsHolder(&stubHolder{})

	// Seed a record with metadata
	rec := credrecs.NewCredentialRecord("rec-1")
	rec.ThreadId = "thid-2"
	rec.ConnectionId = "conn-2"
	rec.RequestMetadata = map[string]interface{}{"meta": true}
	if err := repo.Save(ctx, rec); err != nil {
		t.Fatalf("save: %v", err)
	}

	cred := credmsgs.NewIssueCredentialV2Credential()
	cred.SetThreadId("thid-2")
	cred.Formats = append(cred.Formats, credmsgs.FormatEntry{AttachID: "cred-1", Format: "anoncreds/credential@v1"})
	cred.CredentialsAttach = append(cred.CredentialsAttach, credmsgs.Attachment("cred-1", map[string]interface{}{"cred": true}))

	ack, err := svc.ProcessIssue("thid-2", "conn-2", cred)
	if err != nil {
		t.Fatalf("ProcessIssue error: %v", err)
	}
	if ack == nil {
		t.Fatalf("expected ack to be built")
	}
}
