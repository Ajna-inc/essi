package handlers_test

import (
	"encoding/json"
	"testing"

	corectx "github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/core/di"
	corewallet "github.com/ajna-inc/essi/pkg/core/wallet"
	"github.com/ajna-inc/essi/pkg/didcomm/messages"
	handlers "github.com/ajna-inc/essi/pkg/didcomm/modules/connections/handlers"
	connservices "github.com/ajna-inc/essi/pkg/didcomm/modules/connections/services"
	transport "github.com/ajna-inc/essi/pkg/didcomm/transport"
)

type memRepo struct {
	list []*connservices.ConnectionRecord
}

func (r *memRepo) Save(ctx *corectx.AgentContext, record *connservices.ConnectionRecord) error {
	r.list = append(r.list, record)
	return nil
}
func (r *memRepo) FindById(ctx *corectx.AgentContext, id string) (*connservices.ConnectionRecord, error) {
	for _, c := range r.list {
		if c.ID == id {
			return c, nil
		}
	}
	return nil, nil
}
func (r *memRepo) FindByOutOfBandId(ctx *corectx.AgentContext, o string) ([]*connservices.ConnectionRecord, error) {
	return r.list, nil
}
func (r *memRepo) FindByDid(ctx *corectx.AgentContext, d string) (*connservices.ConnectionRecord, error) {
	return nil, nil
}
func (r *memRepo) FindByInvitationKey(ctx *corectx.AgentContext, k string) (*connservices.ConnectionRecord, error) {
	return nil, nil
}
func (r *memRepo) GetAll(ctx *corectx.AgentContext) ([]*connservices.ConnectionRecord, error) {
	return r.list, nil
}
func (r *memRepo) Update(ctx *corectx.AgentContext, record *connservices.ConnectionRecord) error {
	for i, c := range r.list {
		if c.ID == record.ID {
			r.list[i] = record
			break
		}
	}
	return nil
}
func (r *memRepo) Delete(ctx *corectx.AgentContext, id string) error { return nil }

func setupRotateDI(t *testing.T) (di.DependencyManager, *corectx.AgentContext, *connservices.ConnectionService, *memRepo) {
	dm := di.NewDependencyManager()
	provider := di.DefaultAgentContextProvider{}
	ac, _ := provider.NewRootContext(dm, "rotate-di")
	ws := corewallet.NewWalletService(ac, corewallet.NewSimpleKeyRepository())
	dm.RegisterInstance(di.TokenAgentContext, ac)
	dm.RegisterInstance(di.TokenWalletService, ws)
	repo := &memRepo{}
	cs := connservices.NewConnectionService(ac, repo, ws)
	dm.RegisterInstance(di.TokenConnectionService, cs)
	dm.RegisterInstance(di.TokenDidRotateService, connservices.NewDidRotateService(cs))
	return dm, ac, cs, repo
}

func TestDidRotateHandler_ProducesAckOutbound(t *testing.T) {
	dm, ac, _, repo := setupRotateDI(t)
	// Seed connection with thread id
	rec := connservices.NewConnectionRecord("c1")
	rec.Tags["threadId"] = "th-rot"
	repo.Save(ac, rec)

	// Build rotate with thread id
	rot := connservices.DidRotateMessage{BaseMessage: messages.NewBaseMessage("https://didcomm.org/did-rotate/1.0/rotate")}
	rot.SetThreadId("th-rot")
	raw, _ := json.Marshal(rot)
	in := &transport.InboundMessageContext{Raw: raw, AgentContext: ac, TypedDI: dm}
	out, err := handlers.DidRotateHandlerFunc(in)
	if err != nil {
		t.Fatalf("rotate handler: %v", err)
	}
	if out == nil || out.Message == nil || out.Message.GetType() != "https://didcomm.org/did-rotate/1.0/ack" {
		t.Fatalf("expected ack outbound, got %#v", out)
	}
}

func TestDidRotateAckHandler_NoOutbound(t *testing.T) {
	dm, ac, _, repo := setupRotateDI(t)
	rec := connservices.NewConnectionRecord("c2")
	rec.Tags["threadId"] = "th-ack"
	repo.Save(ac, rec)
	ack := connservices.DidRotateAckMessage{BaseMessage: messages.NewBaseMessage("https://didcomm.org/did-rotate/1.0/ack")}
	ack.SetThreadId("th-ack")
	raw, _ := json.Marshal(ack)
	in := &transport.InboundMessageContext{Raw: raw, AgentContext: ac, TypedDI: dm}
	out, err := handlers.DidRotateAckHandlerFunc(in)
	if err != nil {
		t.Fatalf("ack handler: %v", err)
	}
	if out != nil {
		t.Fatalf("expected no outbound for ack")
	}
}

func TestDidRotateHangupHandler_AbandonsConnection(t *testing.T) {
	dm, ac, cs, repo := setupRotateDI(t)
	rec := connservices.NewConnectionRecord("c3")
	rec.Tags["threadId"] = "th-hang"
	repo.Save(ac, rec)
	hang := connservices.HangupMessage{BaseMessage: messages.NewBaseMessage("https://didcomm.org/did-rotate/1.0/hangup")}
	hang.SetThreadId("th-hang")
	raw, _ := json.Marshal(hang)
	in := &transport.InboundMessageContext{Raw: raw, AgentContext: ac, TypedDI: dm}
	out, err := handlers.DidRotateHangupHandlerFunc(in)
	if err != nil {
		t.Fatalf("hangup handler: %v", err)
	}
	if out != nil {
		t.Fatalf("expected no outbound for hangup")
	}
	// verify state
	got, _ := cs.FindById("c3")
	if got.State != connservices.ConnectionStateAbandoned {
		t.Fatalf("expected abandoned, got %s", got.State)
	}
}
