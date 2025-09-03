package oob_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	ctxpkg "github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/core/di"
	corestorage "github.com/ajna-inc/essi/pkg/core/storage"
	didmsgs "github.com/ajna-inc/essi/pkg/didcomm/messages"
	oobpkg "github.com/ajna-inc/essi/pkg/didcomm/modules/oob"
	oobmsgs "github.com/ajna-inc/essi/pkg/didcomm/modules/oob/messages"
	outboundctx "github.com/ajna-inc/essi/pkg/didcomm/services"
)

// minimal in-memory storage for testing
type memStorage struct {
	data map[string]map[string]corestorage.Record
}

func newMemStorage() *memStorage {
	return &memStorage{data: map[string]map[string]corestorage.Record{}}
}

func (m *memStorage) Save(ctx context.Context, record corestorage.Record) error {
	cls := record.GetType()
	if m.data[cls] == nil {
		m.data[cls] = map[string]corestorage.Record{}
	}
	m.data[cls][record.GetId()] = record
	return nil
}
func (m *memStorage) Update(ctx context.Context, record corestorage.Record) error {
	return m.Save(ctx, record)
}
func (m *memStorage) Delete(ctx context.Context, record corestorage.Record) error {
	cls := record.GetType()
	if m.data[cls] != nil {
		delete(m.data[cls], record.GetId())
	}
	return nil
}
func (m *memStorage) DeleteById(ctx context.Context, recordClass string, id string) error {
	if m.data[recordClass] != nil {
		delete(m.data[recordClass], id)
	}
	return nil
}
func (m *memStorage) GetById(ctx context.Context, recordClass string, id string) (corestorage.Record, error) {
	if recs := m.data[recordClass]; recs != nil {
		if r, ok := recs[id]; ok {
			return r, nil
		}
	}
	return nil, fmt.Errorf("not found")
}
func (m *memStorage) GetAll(ctx context.Context, recordClass string) ([]corestorage.Record, error) {
	out := []corestorage.Record{}
	for _, r := range m.data[recordClass] {
		out = append(out, r)
	}
	return out, nil
}
func (m *memStorage) FindByQuery(ctx context.Context, recordClass string, query corestorage.Query) ([]corestorage.Record, error) {
	out := []corestorage.Record{}
	for _, r := range m.data[recordClass] {
		ok := true
		// only support tag equality used in tests
		for k, v := range query.Equal {
			// tag query is in the form _tags.<key>
			if len(k) > 7 && k[:7] == "_tags." {
				tagKey := k[7:]
				if rv, okTag := r.GetTags()[tagKey]; !okTag || rv != v {
					ok = false
					break
				}
			}
		}
		if ok {
			out = append(out, r)
		}
	}
	return out, nil
}
func (m *memStorage) FindSingleByQuery(ctx context.Context, recordClass string, query corestorage.Query) (corestorage.Record, error) {
	list, _ := m.FindByQuery(ctx, recordClass, query)
	if len(list) == 0 {
		return nil, fmt.Errorf("not found")
	}
	return list[0], nil
}

// Test indexing and lookup by invitationRequestsThreadIds parity
func TestOobRecord_IndexAndLookupByRequestThreadId(t *testing.T) {
	// Build an OOB invitation with a single attached request having @id = req-123
	inv := oobmsgs.NewOutOfBandInvitationMessage("label")
	reqPlain := map[string]interface{}{
		"@id":   "req-123",
		"@type": "https://didcomm.org/test/1.0/request",
	}
	buf, _ := json.Marshal(reqPlain)
	att := oobpkg.Attachment{Id: "att-1", MimeType: "application/json", Data: map[string]interface{}{"base64": base64.StdEncoding.EncodeToString(buf)}}
	inv.Requests = append(inv.Requests, att)

	rec := &oobpkg.OutOfBandRecord{
		BaseRecord:          corestorage.NewBaseRecord("OutOfBandRecord"),
		Role:                oobpkg.OutOfBandRoleReceiver,
		State:               oobpkg.OutOfBandStateInitial,
		OutOfBandInvitation: inv,
		Tags:                map[string]string{},
	}
	rec.ID = rec.BaseRecord.GetId()

	// Manually add request index tag (what setOobRecordTags does internally)
	rec.Tags["invreq:req-123"] = "1"

	// Create repository backed by mem storage
	repo := oobpkg.NewOutOfBandRepository(newMemStorage(), nil)
	if err := repo.Save(nil, rec); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	// Should be found by request thread id
	got := repo.FindByRequestThreadId(nil, "req-123")
	if got == nil || got.ID != rec.ID {
		t.Fatalf("expected record %s via FindByRequestThreadId, got %#v", rec.ID, got)
	}

	// Also validate GetOutOfBandRecordForMessage uses this path
	// Build a minimal AgentContext with DI resolving our repository
	dm := di.NewDependencyManager()
	dm.RegisterInstance(di.TokenOutOfBandRepository, repo)
	agentCtx := ctxpkg.NewAgentContext(ctxpkg.AgentContextOptions{Config: &ctxpkg.AgentConfig{}})
	agentCtx.SetDependencyManager(dm)

	// Build a dummy message having thid=req-123 and no pthid
	msg := didmsgs.NewThreadedMessage("https://didcomm.org/test/1.0/response", "req-123")

	found := outboundctx.GetOutOfBandRecordForMessage(agentCtx, msg)
	if found == nil || found.ID != rec.ID {
		t.Fatalf("expected GetOutOfBandRecordForMessage to find record %s, got %#v", rec.ID, found)
	}
}
