package services_test

import (
	"sync"
	"testing"

	corectx "github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/core/di"
	coreencoding "github.com/ajna-inc/essi/pkg/core/encoding"
	corewallet "github.com/ajna-inc/essi/pkg/core/wallet"
	connmsg "github.com/ajna-inc/essi/pkg/didcomm/modules/connections/messages"
	services "github.com/ajna-inc/essi/pkg/didcomm/modules/connections/services"
	oobmsgs "github.com/ajna-inc/essi/pkg/didcomm/modules/oob/messages"
	dids "github.com/ajna-inc/essi/pkg/dids"
	didsapi "github.com/ajna-inc/essi/pkg/dids/api"
	peerreg "github.com/ajna-inc/essi/pkg/dids/methods/peer"
	didrepo "github.com/ajna-inc/essi/pkg/dids/repository"
	testutil "github.com/ajna-inc/essi/tests/testutil"
)

// inMemoryConnRepo is a minimal in-memory ConnectionRepository for tests
type inMemoryConnRepo struct {
	mu   sync.RWMutex
	list []*services.ConnectionRecord
}

func (r *inMemoryConnRepo) Save(ctx *corectx.AgentContext, record *services.ConnectionRecord) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.list = append(r.list, record)
	return nil
}
func (r *inMemoryConnRepo) FindById(ctx *corectx.AgentContext, id string) (*services.ConnectionRecord, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, it := range r.list {
		if it.ID == id {
			return it, nil
		}
	}
	return nil, nil
}
func (r *inMemoryConnRepo) FindByOutOfBandId(ctx *corectx.AgentContext, oobId string) ([]*services.ConnectionRecord, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*services.ConnectionRecord
	for _, it := range r.list {
		if it.Tags != nil && it.Tags["outOfBandId"] == oobId {
			out = append(out, it)
		}
	}
	return out, nil
}
func (r *inMemoryConnRepo) FindByDid(ctx *corectx.AgentContext, did string) (*services.ConnectionRecord, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, it := range r.list {
		if it.Did == did || it.TheirDid == did {
			return it, nil
		}
	}
	return nil, nil
}
func (r *inMemoryConnRepo) FindByInvitationKey(ctx *corectx.AgentContext, key string) (*services.ConnectionRecord, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, it := range r.list {
		if it.InvitationKey == key {
			return it, nil
		}
	}
	return nil, nil
}
func (r *inMemoryConnRepo) GetAll(ctx *corectx.AgentContext) ([]*services.ConnectionRecord, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*services.ConnectionRecord, len(r.list))
	copy(out, r.list)
	return out, nil
}
func (r *inMemoryConnRepo) Update(ctx *corectx.AgentContext, record *services.ConnectionRecord) error {
	return nil
}
func (r *inMemoryConnRepo) Delete(ctx *corectx.AgentContext, id string) error { return nil }

type suiteEnv struct {
	dm       di.DependencyManager
	ctx      *corectx.AgentContext
	wallet   *corewallet.WalletService
	connRepo *inMemoryConnRepo
	connSvc  *services.ConnectionService
}

func newConnEnv(t *testing.T, label string, endpoints []string) *suiteEnv {
	t.Helper()
	dm := di.NewDependencyManager()
	provider := di.DefaultAgentContextProvider{}
	ac, _ := provider.NewRootContext(dm, label)
	ac.Config = &corectx.AgentConfig{Label: label, Endpoints: endpoints}
	// storage + did repo
	mem := testutil.NewInMemoryStorageService()
	dm.RegisterInstance(di.TokenStorageService, mem)
	didRepository := didrepo.NewAskarDidRepository(mem)
	dm.RegisterInstance(di.TokenDidRepository, didRepository)
	// wallet
	ws := corewallet.NewWalletService(ac, corewallet.NewSimpleKeyRepository())
	dm.RegisterInstance(di.TokenWalletService, ws)
	// dids api
	resolver := dids.NewDidResolverService()
	registrar := dids.NewDidRegistrarService()
	registrar.RegisterRegistrar(peerreg.NewPeerDidRegistrar())
	api := didsapi.NewDidsApi(resolver, registrar, didRepository, ac)
	// connection service
	repo := &inMemoryConnRepo{}
	cs := services.NewConnectionService(ac, repo, ws)
	cs.SetDidsApi(api)
	return &suiteEnv{dm: dm, ctx: ac, wallet: ws, connRepo: repo, connSvc: cs}
}

func TestConnections_OOB_MultiUse_CreatesDistinctRecords(t *testing.T) {
	// Responder environment (inviter)
	resp := newConnEnv(t, "responder", []string{"http://responder"})
	// Create an invitation with connections/1.0 handshake and inline service
	inv := oobmsgs.NewOutOfBandInvitationMessage("multi-test")
	inv.AddHandshakeProtocol("https://didcomm.org/connections/1.0", nil)
	// Responder inline recipient key (base58 of a new key)
	svcKey, _ := resp.wallet.CreateKey(corewallet.KeyTypeEd25519)
	recipB58 := coreencoding.EncodeBase58(svcKey.PublicKey)
	if err := inv.AddInlineService("svc1", "http://responder", []string{recipB58}); err != nil {
		t.Fatalf("inline service: %v", err)
	}

	// Requester A
	reqA := newConnEnv(t, "requesterA", []string{"http://reqA"})
	recA, reqMsgA, oobRecA, err := reqA.connSvc.ProcessOOBInvitation(inv, services.ProcessInvitationConfig{Label: "A", AutoAcceptConnection: true})
	if err != nil {
		t.Fatalf("process oob A: %v", err)
	}
	if oobRecA == nil || recA == nil || reqMsgA == nil {
		t.Fatalf("unexpected nils from ProcessOOBInvitation A")
	}
	// Requester A sender key
	kA, _ := reqA.wallet.GetKey(recA.MyKeyId)
	senderA := coreencoding.EncodeBase58(kA.PublicKey)
	// Responder handles request A
	reqAConn, ok := reqMsgA.(*connmsg.ConnectionRequestMessage)
	if !ok {
		t.Fatalf("expected ConnectionRequestMessage for A")
	}
	_, respMsgA, err := resp.connSvc.ProcessConnectionRequest(reqAConn, recipB58, senderA)
	if err != nil {
		t.Fatalf("responder process request A: %v", err)
	}
	// Requester A processes response
	if _, err := reqA.connSvc.ProcessConnectionResponse(respMsgA); err != nil {
		t.Fatalf("requester A process response: %v", err)
	}

	// Requester B
	reqB := newConnEnv(t, "requesterB", []string{"http://reqB"})
	recB, reqMsgB, _, err := reqB.connSvc.ProcessOOBInvitation(inv, services.ProcessInvitationConfig{Label: "B", AutoAcceptConnection: true})
	if err != nil {
		t.Fatalf("process oob B: %v", err)
	}
	kB, _ := reqB.wallet.GetKey(recB.MyKeyId)
	senderB := coreencoding.EncodeBase58(kB.PublicKey)
	reqBConn, ok := reqMsgB.(*connmsg.ConnectionRequestMessage)
	if !ok {
		t.Fatalf("expected ConnectionRequestMessage for B")
	}
	if _, _, err := resp.connSvc.ProcessConnectionRequest(reqBConn, recipB58, senderB); err != nil {
		t.Fatalf("responder process request B: %v", err)
	}
	// (Optionally) requester B could process response as well, not required to verify multi-use on responder

	// Assert responder has two records (multi-use)
	all, _ := resp.connRepo.GetAll(resp.ctx)
	if len(all) != 2 {
		t.Fatalf("expected 2 connections on responder, got %d", len(all))
	}
	if all[0].ID == all[1].ID {
		t.Fatalf("expected distinct connection IDs")
	}
}

func TestConnections_DidExchange_Handshake_RequestCreated(t *testing.T) {
	env := newConnEnv(t, "req", []string{"http://req"})
	// Invitation requesting didexchange/1.1
	inv := oobmsgs.NewOutOfBandInvitationMessage("dex")
	inv.AddHandshakeProtocol("https://didcomm.org/didexchange/1.1", nil)
	// Inline service with recipient key so requester sets TheirRecipientKey
	k, _ := env.wallet.CreateKey(corewallet.KeyTypeEd25519)
	recip := coreencoding.EncodeBase58(k.PublicKey)
	if err := inv.AddInlineService("svc", "http://resp", []string{recip}); err != nil {
		t.Fatalf("inline svc: %v", err)
	}

	rec, reqMsg, _, err := env.connSvc.ProcessOOBInvitation(inv, services.ProcessInvitationConfig{Label: "dex-req"})
	if err != nil {
		t.Fatalf("process oob: %v", err)
	}
	if rec.Protocol != "https://didcomm.org/didexchange/1.1" {
		t.Fatalf("protocol mismatch: %s", rec.Protocol)
	}
	if _, ok := reqMsg.(*services.DidExchangeRequestMessage); !ok {
		t.Fatalf("expected DidExchangeRequestMessage, got %T", reqMsg)
	}
}

func TestConnections_TrustPing_ThreadCorrelation(t *testing.T) {
	env := newConnEnv(t, "tp", []string{"http://tp"})
	// Create a minimal connection record with thread id tag
	rec := services.NewConnectionRecord("c-tp")
	rec.Tags["threadId"] = "th-123"
	rec.State = services.ConnectionStateResponded
	_ = env.connRepo.Save(env.ctx, rec)

	res, err := env.connSvc.CreateTrustPing(env.ctx, rec, &services.CreateTrustPingConfig{ResponseRequested: true, Comment: "hello"})
	if err != nil {
		t.Fatalf("CreateTrustPing: %v", err)
	}
	m, ok := res.Message.(map[string]interface{})
	if !ok {
		t.Fatalf("unexpected message type: %T", res.Message)
	}
	th, _ := m["~thread"].(map[string]interface{})
	if th == nil || th["thid"] != "th-123" {
		t.Fatalf("expected thid=th-123, got %v", th)
	}
}

func TestConnections_HandshakeReuse_ByRecipientKey(t *testing.T) {
	resp := newConnEnv(t, "reuser", []string{"http://resp"})
	// Invitation with inline service and did:key recipient
	inv := oobmsgs.NewOutOfBandInvitationMessage("reuse-key")
	k, _ := resp.wallet.CreateKey(corewallet.KeyTypeEd25519)
	fp, _ := peerreg.Ed25519Fingerprint(k.PublicKey)
	rkDidKey := "did:key:" + fp
	if err := inv.AddInlineService("svc", "http://resp", []string{rkDidKey}); err != nil {
		t.Fatalf("inline svc: %v", err)
	}

	// Existing connection with normalized recipientKey matching invitation key
	existing := services.NewConnectionRecord("c-existing")
	existing.TheirRecipientKey = coreencoding.EncodeBase58(k.PublicKey) // normalized
	_ = resp.connRepo.Save(resp.ctx, existing)

	// Request reuse
	got, req, _, err := resp.connSvc.ProcessOOBInvitation(inv, services.ProcessInvitationConfig{ReuseConnection: true})
	if err != nil {
		t.Fatalf("ProcessOOBInvitation: %v", err)
	}
	if got == nil || got.ID != existing.ID {
		t.Fatalf("expected existing connection returned for reuse")
	}
	if req != nil {
		t.Fatalf("expected no request when reused")
	}
}

func TestConnections_HandshakeReuse_ByDid(t *testing.T) {
	resp := newConnEnv(t, "reuser2", []string{"http://resp2"})
	// DID-based service invitation
	inv := oobmsgs.NewOutOfBandInvitationMessage("reuse-did")
	did := "did:peer:example-reuse"
	if err := inv.AddDidService(did); err != nil {
		t.Fatalf("did svc: %v", err)
	}

	// Existing connection record with DID
	existing := services.NewConnectionRecord("c-existing-did")
	existing.Did = did
	_ = resp.connRepo.Save(resp.ctx, existing)

	got, req, _, err := resp.connSvc.ProcessOOBInvitation(inv, services.ProcessInvitationConfig{ReuseConnection: true})
	if err != nil {
		t.Fatalf("ProcessOOBInvitation: %v", err)
	}
	if got == nil || got.ID != existing.ID {
		t.Fatalf("expected existing connection returned for DID reuse")
	}
	if req != nil {
		t.Fatalf("expected no request when reused by DID")
	}
}

func TestConnections_DidRotate_Flow(t *testing.T) {
	env := newConnEnv(t, "rotate", []string{"http://ep"})
	// Seed a completed connection
	rec := services.NewConnectionRecord("c-rot")
	rec.State = services.ConnectionStateComplete
	rec.Did = "did:peer:old"
	rec.TheirDid = "did:peer:their-old"
	_ = env.connRepo.Save(env.ctx, rec)

	// Create rotate and update our DID
	rotSvc := services.NewDidRotateService(env.connSvc)
	rotate, err := rotSvc.CreateRotate(env.ctx, &services.CreateRotateConfig{Connection: rec, ToDid: "did:peer:new"})
	if err != nil {
		t.Fatalf("CreateRotate: %v", err)
	}
	if rec.Did != "did:peer:new" {
		t.Fatalf("our DID not updated")
	}
	if len(rec.PreviousDids) == 0 || rec.PreviousDids[0] != "did:peer:old" {
		t.Fatalf("previousDids not appended")
	}

	// Process rotate on the counterparty side (simulate) and ack
	ack, err := rotSvc.ProcessRotate(env.ctx, rotate, rec)
	if err != nil {
		t.Fatalf("ProcessRotate: %v", err)
	}
	if ack == nil || ack.GetType() != "https://didcomm.org/did-rotate/1.0/ack" {
		t.Fatalf("invalid ack returned")
	}

	// Process ack (no-op success)
	if err := rotSvc.ProcessRotateAck(env.ctx, ack, rec); err != nil {
		t.Fatalf("ProcessRotateAck: %v", err)
	}

	// Hangup terminates the connection
	hang, err := rotSvc.CreateHangup(env.ctx, &services.CreateHangupConfig{Connection: rec})
	if err != nil {
		t.Fatalf("CreateHangup: %v", err)
	}
	if hang.GetType() != "https://didcomm.org/did-rotate/1.0/hangup" {
		t.Fatalf("invalid hangup type")
	}
	if rec.State != services.ConnectionStateAbandoned {
		t.Fatalf("expected abandoned state")
	}
}
