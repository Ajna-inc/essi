package messagepickup_test

import (
	"encoding/json"
	"testing"
	"time"

	corectx "github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/core/di"
	"github.com/ajna-inc/essi/pkg/core/encoding"
	"github.com/ajna-inc/essi/pkg/core/wallet"
	didcommmessages "github.com/ajna-inc/essi/pkg/didcomm/messages"
	didcommmodels "github.com/ajna-inc/essi/pkg/didcomm/models"
	connservices "github.com/ajna-inc/essi/pkg/didcomm/modules/connections/services"
	"github.com/ajna-inc/essi/pkg/didcomm/modules/messagepickup/handlers"
	envelopeServices "github.com/ajna-inc/essi/pkg/didcomm/services"
	transport "github.com/ajna-inc/essi/pkg/didcomm/transport"
)

// Test V1 batch handler unpacks attachments and dispatches inner messages via global dispatcher
func TestV1BatchHandler_DispatchesInnerMessages(t *testing.T) {
	// Build DI with wallet + envelope service
	dm := di.NewDependencyManager()
	provider := di.DefaultAgentContextProvider{}
	agentCtx, _ := provider.NewRootContext(dm, "pickup-v1")
	ws := wallet.NewWalletService(agentCtx, wallet.NewSimpleKeyRepository())
	dm.RegisterInstance(di.TokenAgentContext, agentCtx)
	dm.RegisterInstance(di.TokenWalletService, ws)
	es := envelopeServices.NewEnvelopeService(agentCtx)
	es.SetTypedDI(dm)
	es.SetKidFormatForTesting("didkey")
	dm.RegisterInstance(di.TokenEnvelopeService, es)
	// Minimal connection service required by handler
	cs := connservices.NewConnectionService(agentCtx, &fakeConnRepo{}, ws)
	dm.RegisterInstance(di.TokenConnectionService, cs)

	// Create recipient key for unpacking
	key, _ := ws.CreateKey(wallet.KeyTypeEd25519)

	// Create an inner plaintext message and pack anoncrypt to recipient
	innerType := "https://example.org/pickup/1.0/inner"
	inner := didcommmessages.NewBaseMessage(innerType)
	inner.Body = map[string]interface{}{"n": 1}
	enc, err := es.PackMessage(inner, []string{encoding.EncodeBase58(key.PublicKey)}, envelopeServices.PackageTypeAnoncrypt)
	if err != nil {
		t.Fatalf("pack inner: %v", err)
	}
	// Convert to map[string]interface{} for embedding in batch attach
	var encMap map[string]interface{}
	b, _ := json.Marshal(enc)
	_ = json.Unmarshal(b, &encMap)

	// Build V1Batch payload
	batch := struct {
		*didcommmessages.BaseMessage
		Messages []struct {
			Id      string                 `json:"id"`
			Message map[string]interface{} `json:"message"`
		} `json:"messages~attach"`
	}{BaseMessage: didcommmessages.NewBaseMessage("https://didcomm.org/messagepickup/1.0/batch")}
	batch.Messages = append(batch.Messages, struct {
		Id      string                 `json:"id"`
		Message map[string]interface{} `json:"message"`
	}{Id: "att-1", Message: encMap})
	raw, _ := json.Marshal(batch)

	// Prepare a dispatcher and register handler for the inner type to capture dispatch
	d := transport.NewDispatcher()
	dispatched := make(chan struct{}, 1)
	d.Register(innerType, func(in *transport.InboundMessageContext) (*didcommmodels.OutboundMessageContext, error) {
		dispatched <- struct{}{}
		return nil, nil
	})
	transport.SetDispatcher(d)
	t.Cleanup(func() { transport.SetDispatcher(nil) })

	// Build inbound context for the batch
	in := &transport.InboundMessageContext{Raw: raw, AgentContext: agentCtx, TypedDI: dm}
	if _, err := handlers.V1BatchHandlerFunc(in); err != nil {
		t.Fatalf("V1BatchHandlerFunc: %v", err)
	}

	select {
	case <-dispatched:
		// ok
	case <-time.After(2 * time.Second):
		t.Fatalf("inner message was not dispatched")
	}
}

// fakeConnRepo mirrors minimal test repository used elsewhere
type fakeConnRepo struct{}

func (f *fakeConnRepo) Save(ctx *corectx.AgentContext, record *connservices.ConnectionRecord) error {
	return nil
}
func (f *fakeConnRepo) FindById(ctx *corectx.AgentContext, id string) (*connservices.ConnectionRecord, error) {
	return nil, nil
}
func (f *fakeConnRepo) FindByOutOfBandId(ctx *corectx.AgentContext, oobId string) ([]*connservices.ConnectionRecord, error) {
	return []*connservices.ConnectionRecord{}, nil
}
func (f *fakeConnRepo) FindByDid(ctx *corectx.AgentContext, did string) (*connservices.ConnectionRecord, error) {
	return nil, nil
}
func (f *fakeConnRepo) FindByInvitationKey(ctx *corectx.AgentContext, key string) (*connservices.ConnectionRecord, error) {
	return nil, nil
}
func (f *fakeConnRepo) GetAll(ctx *corectx.AgentContext) ([]*connservices.ConnectionRecord, error) {
	return []*connservices.ConnectionRecord{}, nil
}
func (f *fakeConnRepo) Update(ctx *corectx.AgentContext, record *connservices.ConnectionRecord) error {
	return nil
}
func (f *fakeConnRepo) Delete(ctx *corectx.AgentContext, id string) error { return nil }
