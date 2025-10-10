package transport_test

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	corectx "github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/core/di"
	coreencoding "github.com/ajna-inc/essi/pkg/core/encoding"
	corestorage "github.com/ajna-inc/essi/pkg/core/storage"
	"github.com/ajna-inc/essi/pkg/core/wallet"
	didcommmessages "github.com/ajna-inc/essi/pkg/didcomm/messages"
	didcommmodels "github.com/ajna-inc/essi/pkg/didcomm/models"
	connservices "github.com/ajna-inc/essi/pkg/didcomm/modules/connections/services"
	oobrec "github.com/ajna-inc/essi/pkg/didcomm/modules/oob"
	oobmsgs "github.com/ajna-inc/essi/pkg/didcomm/modules/oob/messages"
	envelopeServices "github.com/ajna-inc/essi/pkg/didcomm/services"
	transport "github.com/ajna-inc/essi/pkg/didcomm/transport"
	dids "github.com/ajna-inc/essi/pkg/dids"
	recrepo "github.com/ajna-inc/essi/pkg/dids/repository"
	testutil "github.com/ajna-inc/essi/tests/testutil"
)

// fakeOutboundTransport captures the last encrypted message sent
type fakeOutboundTransport struct {
	last *envelopeServices.EncryptedMessage
}

func (f *fakeOutboundTransport) CanSend(endpoint string) bool {
	return len(endpoint) > 0 && (endpoint[:6] == "wss://" || endpoint[:5] == "ws://" || endpoint[:7] == "mock://")
}
func (f *fakeOutboundTransport) Send(encryptedMessage *envelopeServices.EncryptedMessage, endpoint string) (int, []byte, string, error) {
	f.last = encryptedMessage
	return 200, nil, "", nil
}

// captureTransport records the endpoint used for sending
type captureTransport struct {
	endpoint string
	last     *envelopeServices.EncryptedMessage
}

func (c *captureTransport) CanSend(endpoint string) bool { return true }
func (c *captureTransport) Send(encryptedMessage *envelopeServices.EncryptedMessage, endpoint string) (int, []byte, string, error) {
	c.endpoint = endpoint
	c.last = encryptedMessage
	return 200, nil, "", nil
}

func TestMessageSender_ChoosesAuthcrypt_WhenMyKeyAvailable(t *testing.T) {
	// Build DI and services
	dm := di.NewDependencyManager()
	provider := di.DefaultAgentContextProvider{}
	agentCtx, _ := provider.NewRootContext(dm, "test")
	ws := wallet.NewWalletService(agentCtx, wallet.NewSimpleKeyRepository())
	dm.RegisterInstance(di.TokenAgentContext, agentCtx)
	dm.RegisterInstance(di.TokenWalletService, ws)

	// Create our key and connection referencing it
	key, err := ws.CreateKey(wallet.KeyTypeEd25519)
	if err != nil {
		t.Fatalf("create key: %v", err)
	}
	conn := connservices.NewConnectionRecord("c1")
	conn.MyKeyId = key.Id

	// Envelope & sender
	es := envelopeServices.NewEnvelopeService(agentCtx)
	es.SetTypedDI(dm)
	ms := transport.NewMessageSender(agentCtx, dm, es, nil)

	// Register fake transport (subject-like) to avoid HTTP
	fake := &fakeOutboundTransport{}
	ms.RegisterOutboundTransport(fake)

	// Build a service endpoint and recipient key
	recipKeyB58 := coreencoding.EncodeBase58(key.PublicKey) // use our public key as recipient for simplicity
	svc := &didcommmodels.ResolvedDidCommService{ID: "svc", ServiceEndpoint: "wss://subject/fake", RecipientKeys: []string{recipKeyB58}}

	// Build a ping message and outbound context as service message
	msg := didcommmessages.NewBaseMessage("https://didcomm.org/trust-ping/1.0/ping")
	out := didcommmodels.NewOutboundMessageContext(msg, didcommmodels.OutboundMessageContextParams{
		AgentContext: agentCtx,
		Connection:   conn,
		ServiceParams: &didcommmodels.ServiceMessageParams{
			Service:     svc,
			ReturnRoute: false,
		},
	})

	if err := ms.SendMessage(out); err != nil {
		t.Fatalf("SendMessage: %v", err)
	}

	if fake.last == nil {
		t.Fatalf("transport did not capture message")
	}

	// Inspect protected header
	phBytes, err := base64.RawURLEncoding.DecodeString(fake.last.Protected)
	if err != nil {
		t.Fatalf("decode protected: %v", err)
	}
	var ph envelopeServices.JWEProtectedHeader
	if err := json.Unmarshal(phBytes, &ph); err != nil {
		t.Fatalf("unmarshal protected: %v", err)
	}
	if ph.Alg != "Authcrypt" {
		t.Fatalf("expected Authcrypt, got %s", ph.Alg)
	}
	if len(ph.Recipients) == 0 || ph.Recipients[0].Header.Sender == "" {
		t.Fatalf("expected sender field in recipient header for authcrypt")
	}
}

func TestMessageSender_ResolvesConnectionEndpoint_First(t *testing.T) {
	dm := di.NewDependencyManager()
	provider := di.DefaultAgentContextProvider{}
	agentCtx, _ := provider.NewRootContext(dm, "test")
	ws := wallet.NewWalletService(agentCtx, wallet.NewSimpleKeyRepository())
	dm.RegisterInstance(di.TokenAgentContext, agentCtx)
	dm.RegisterInstance(di.TokenWalletService, ws)

	// Local (our) key and their recipient key
	myKey, _ := ws.CreateKey(wallet.KeyTypeEd25519)
	theirKey, _ := ws.CreateKey(wallet.KeyTypeEd25519)

	conn := connservices.NewConnectionRecord("c2")
	conn.MyKeyId = myKey.Id
	conn.TheirEndpoint = "mock://service"
	conn.TheirRecipientKey = coreencoding.EncodeBase58(theirKey.PublicKey)

	es := envelopeServices.NewEnvelopeService(agentCtx)
	es.SetTypedDI(dm)
	ms := transport.NewMessageSender(agentCtx, dm, es, nil)
	fake := &fakeOutboundTransport{}
	ms.RegisterOutboundTransport(fake)

	msg := didcommmessages.NewBaseMessage("https://didcomm.org/trust-ping/1.0/ping")
	out := didcommmodels.NewOutboundMessageContext(msg, didcommmodels.OutboundMessageContextParams{AgentContext: agentCtx, Connection: conn})
	if err := ms.SendMessage(out); err != nil {
		t.Fatalf("SendMessage: %v", err)
	}

	if fake.last == nil {
		t.Fatalf("transport did not capture message")
	}
	// Verify it packed for the expected recipient (base58 kid in recipients)
	phBytes, _ := base64.RawURLEncoding.DecodeString(fake.last.Protected)
	var ph envelopeServices.JWEProtectedHeader
	_ = json.Unmarshal(phBytes, &ph)
	if len(ph.Recipients) == 0 || ph.Recipients[0].Header.Kid == "" {
		t.Fatalf("no recipient kid set")
	}
}

func TestMessageSender_AddsReturnRoute_ForHandshake(t *testing.T) {
	dm := di.NewDependencyManager()
	provider := di.DefaultAgentContextProvider{}
	agentCtx, _ := provider.NewRootContext(dm, "test")
	ws := wallet.NewWalletService(agentCtx, wallet.NewSimpleKeyRepository())
	dm.RegisterInstance(di.TokenAgentContext, agentCtx)
	dm.RegisterInstance(di.TokenWalletService, ws)

	// our key and their recipient key
	myKey, _ := ws.CreateKey(wallet.KeyTypeEd25519)
	theirKey, _ := ws.CreateKey(wallet.KeyTypeEd25519)

	conn := connservices.NewConnectionRecord("c3")
	conn.MyKeyId = myKey.Id
	conn.TheirEndpoint = "mock://service"
	conn.TheirRecipientKey = coreencoding.EncodeBase58(theirKey.PublicKey)

	es := envelopeServices.NewEnvelopeService(agentCtx)
	es.SetTypedDI(dm)
	ms := transport.NewMessageSender(agentCtx, dm, es, nil)
	fake := &fakeOutboundTransport{}
	ms.RegisterOutboundTransport(fake)

	// Handshake message (request) should add ~transport.return_route=all
	msg := didcommmessages.NewBaseMessage("https://didcomm.org/didexchange/1.1/request")
	out := didcommmodels.NewOutboundMessageContext(msg, didcommmodels.OutboundMessageContextParams{AgentContext: agentCtx, Connection: conn})
	if err := ms.SendMessage(out); err != nil {
		t.Fatalf("SendMessage: %v", err)
	}
	if fake.last == nil {
		t.Fatalf("no captured envelope")
	}

	// Decrypt captured envelope with same wallet to inspect plaintext
	es2 := envelopeServices.NewEnvelopeService(agentCtx)
	es2.SetTypedDI(dm)
	dec, err := es2.UnpackMessage(fake.last)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	// Check ~transport.return_route == "all"
	var raw map[string]interface{}
	if err := json.Unmarshal(dec.PlaintextRaw, &raw); err != nil {
		t.Fatalf("unmarshal raw: %v", err)
	}
	if td, ok := raw["~transport"].(map[string]interface{}); ok {
		if rr, _ := td["return_route"].(string); rr != "all" {
			t.Fatalf("expected return_route=all, got %s", rr)
		}
	} else {
		t.Fatalf("~transport decorator missing")
	}
}

func TestMessageSender_ForwardWrapping_PerRoutingKey(t *testing.T) {
	dm := di.NewDependencyManager()
	provider := di.DefaultAgentContextProvider{}
	agentCtx, _ := provider.NewRootContext(dm, "test")
	ws := wallet.NewWalletService(agentCtx, wallet.NewSimpleKeyRepository())
	dm.RegisterInstance(di.TokenAgentContext, agentCtx)
	dm.RegisterInstance(di.TokenWalletService, ws)

	myKey, _ := ws.CreateKey(wallet.KeyTypeEd25519)
	r1, _ := ws.CreateKey(wallet.KeyTypeEd25519)
	r2, _ := ws.CreateKey(wallet.KeyTypeEd25519)
	final, _ := ws.CreateKey(wallet.KeyTypeEd25519)

	conn := connservices.NewConnectionRecord("c4")
	conn.MyKeyId = myKey.Id
	es := envelopeServices.NewEnvelopeService(agentCtx)
	es.SetTypedDI(dm)
	ms := transport.NewMessageSender(agentCtx, dm, es, nil)
	fake := &fakeOutboundTransport{}
	ms.RegisterOutboundTransport(fake)

	svc := &didcommmodels.ResolvedDidCommService{
		ID:              "svc",
		ServiceEndpoint: "mock://service",
		RecipientKeys:   []string{coreencoding.EncodeBase58(final.PublicKey)},
		RoutingKeys:     []string{coreencoding.EncodeBase58(r1.PublicKey), coreencoding.EncodeBase58(r2.PublicKey)},
	}

	msg := didcommmessages.NewBaseMessage("https://example.org/test/1.0/forwardcheck")
	out := didcommmodels.NewOutboundMessageContext(msg, didcommmodels.OutboundMessageContextParams{AgentContext: agentCtx, Connection: conn, ServiceParams: &didcommmodels.ServiceMessageParams{Service: svc}})
	if err := ms.SendMessage(out); err != nil {
		t.Fatalf("SendMessage: %v", err)
	}
	if fake.last == nil {
		t.Fatalf("no captured envelope")
	}

	// Inspect outermost protected header: should be packed for router1 kid
	phBytes, err := base64.RawURLEncoding.DecodeString(fake.last.Protected)
	if err != nil {
		t.Fatalf("decode protected: %v", err)
	}
	var ph envelopeServices.JWEProtectedHeader
	if err := json.Unmarshal(phBytes, &ph); err != nil {
		t.Fatalf("unmarshal protected: %v", err)
	}
	if len(ph.Recipients) != 1 {
		t.Fatalf("expected one outer recipient, got %d", len(ph.Recipients))
	}
	if ph.Recipients[0].Header.Kid != coreencoding.EncodeBase58(r1.PublicKey) {
		t.Fatalf("outer recipient kid mismatch")
	}
}

func TestMessageSender_QueueFallback_OnTransportFailure(t *testing.T) {
	dm := di.NewDependencyManager()
	provider := di.DefaultAgentContextProvider{}
	agentCtx, _ := provider.NewRootContext(dm, "test")
	ws := wallet.NewWalletService(agentCtx, wallet.NewSimpleKeyRepository())
	dm.RegisterInstance(di.TokenAgentContext, agentCtx)
	dm.RegisterInstance(di.TokenWalletService, ws)

	myKey, _ := ws.CreateKey(wallet.KeyTypeEd25519)
	theirKey, _ := ws.CreateKey(wallet.KeyTypeEd25519)

	conn := connservices.NewConnectionRecord("c5")
	conn.MyKeyId = myKey.Id
	// Unreachable endpoint forces HTTP transport failure
	conn.TheirEndpoint = "http://127.0.0.1:9"
	conn.TheirRecipientKey = coreencoding.EncodeBase58(theirKey.PublicKey)

	es := envelopeServices.NewEnvelopeService(agentCtx)
	es.SetTypedDI(dm)
	ms := transport.NewMessageSender(agentCtx, dm, es, nil)
	// Use default HTTP outbound transport already in MessageSender

	// Clear queue and send
	repo := transport.GetGlobalQueueRepository()
	repo.Clear()
	msg := didcommmessages.NewBaseMessage("https://didcomm.org/trust-ping/1.0/ping")
	out := didcommmodels.NewOutboundMessageContext(msg, didcommmodels.OutboundMessageContextParams{AgentContext: agentCtx, Connection: conn})
	_ = ms.SendMessage(out)

	if all := repo.GetAll(); len(all) != 1 {
		t.Fatalf("expected 1 queued message, got %d", len(all))
	} else if all[0].ConnectionId != conn.ID {
		t.Fatalf("queued message connection mismatch")
	}
}

func TestMessageSender_OobInlineService_RequesterFallback(t *testing.T) {
	dm := di.NewDependencyManager()
	provider := di.DefaultAgentContextProvider{}
	agentCtx, _ := provider.NewRootContext(dm, "test-oob")
	ws := wallet.NewWalletService(agentCtx, wallet.NewSimpleKeyRepository())
	dm.RegisterInstance(di.TokenAgentContext, agentCtx)
	dm.RegisterInstance(di.TokenWalletService, ws)

	// Connection (requester) without their endpoint
	myKey, _ := ws.CreateKey(wallet.KeyTypeEd25519)
	conn := connservices.NewConnectionRecord("c6")
	conn.MyKeyId = myKey.Id
	conn.Role = "requester"

	// OOB invitation with inline service
	recipB58 := coreencoding.EncodeBase58(myKey.PublicKey) // reuse our pub as target for simplicity
	inv := oobmsgs.NewOutOfBandInvitationMessage("oob-inline")
	_ = inv.AddInlineService("svc1", "wss://subject/oob", []string{recipB58})
	oobRecord := &oobrec.OutOfBandRecord{ID: "o1", OutOfBandInvitation: inv}

	es := envelopeServices.NewEnvelopeService(agentCtx)
	es.SetTypedDI(dm)
	ms := transport.NewMessageSender(agentCtx, dm, es, nil)
	fake := &fakeOutboundTransport{}
	ms.RegisterOutboundTransport(fake)

	msg := didcommmessages.NewBaseMessage("https://example.org/test/1.0/oob")
	out := didcommmodels.NewOutboundMessageContext(msg, didcommmodels.OutboundMessageContextParams{AgentContext: agentCtx, Connection: conn, OutOfBand: oobRecord})
	if err := ms.SendMessage(out); err != nil {
		t.Fatalf("SendMessage: %v", err)
	}
	if fake.last == nil {
		t.Fatalf("no captured envelope")
	}

	phBytes, _ := base64.RawURLEncoding.DecodeString(fake.last.Protected)
	var ph envelopeServices.JWEProtectedHeader
	_ = json.Unmarshal(phBytes, &ph)
	if len(ph.Recipients) == 0 || ph.Recipients[0].Header.Kid != recipB58 {
		t.Fatalf("expected kid %s from OOB inline service", recipB58)
	}
}

func TestMessageSender_ReceivedDidRepository_Fallback(t *testing.T) {
	dm := di.NewDependencyManager()
	provider := di.DefaultAgentContextProvider{}
	agentCtx, _ := provider.NewRootContext(dm, "test-rec")
	// Register storage
	mem := testutil.NewInMemoryStorageService()
	dm.RegisterInstance(di.TokenStorageService, mem)
	ws := wallet.NewWalletService(agentCtx, wallet.NewSimpleKeyRepository())
	dm.RegisterInstance(di.TokenAgentContext, agentCtx)
	dm.RegisterInstance(di.TokenWalletService, ws)
	// Register empty DidResolverService to allow fallback to ReceivedDidRepository path
	dm.RegisterInstance(di.TokenDidResolverService, dids.NewDidResolverService())

	// Received DID repository
	rrepo := recrepo.NewReceivedDidRepository(mem)
	// Ensure storage can construct ReceivedDidRecord properly
	corestorage.RegisterRecordType("ReceivedDidRecord", func() corestorage.Record {
		return &recrepo.ReceivedDidRecord{BaseRecord: corestorage.NewBaseRecord("ReceivedDidRecord")}
	})
	dm.RegisterInstance(di.TokenReceivedDidRepository, rrepo)

	// Their DID and doc
	theirDID := "did:peer:example"
	recipKey, _ := ws.CreateKey(wallet.KeyTypeEd25519)
	doc := makeDidDoc(theirDID, "wss://subject/repo", []string{coreencoding.EncodeBase58(recipKey.PublicKey)})
	_ = rrepo.Save(agentCtx, theirDID, doc)

	// Connection with TheirDid set, no endpoint
	myKey, _ := ws.CreateKey(wallet.KeyTypeEd25519)
	conn := connservices.NewConnectionRecord("c7")
	conn.MyKeyId = myKey.Id
	conn.TheirDid = theirDID

	es := envelopeServices.NewEnvelopeService(agentCtx)
	es.SetTypedDI(dm)
	ms := transport.NewMessageSender(agentCtx, dm, es, nil)
	fake := &fakeOutboundTransport{}
	ms.RegisterOutboundTransport(fake)

	msg := didcommmessages.NewBaseMessage("https://example.org/test/1.0/repo")
	out := didcommmodels.NewOutboundMessageContext(msg, didcommmodels.OutboundMessageContextParams{AgentContext: agentCtx, Connection: conn})
	if err := ms.SendMessage(out); err != nil {
		t.Fatalf("SendMessage: %v", err)
	}
	if fake.last == nil {
		t.Fatalf("no captured envelope")
	}
	phBytes, _ := base64.RawURLEncoding.DecodeString(fake.last.Protected)
	var ph envelopeServices.JWEProtectedHeader
	_ = json.Unmarshal(phBytes, &ph)
	if len(ph.Recipients) == 0 || ph.Recipients[0].Header.Kid == "" {
		t.Fatalf("expected recipient kid from ReceivedDidRepository doc")
	}
}

func makeDidDoc(did, endpoint string, recipientKeys []string) *dids.DidDocument {
	doc := dids.NewDidDocument(did)
	svc := &dids.Service{Id: did + "#svc", Type: dids.ServiceTypeDIDComm, ServiceEndpoint: endpoint, RecipientKeys: recipientKeys}
	doc.AddService(svc)
	return doc
}

// fakeDidResolver resolves a specific DID to a provided doc
type fakeDidResolver struct {
	did string
	doc *dids.DidDocument
}

func (f *fakeDidResolver) Resolve(ctx *di.DependencyManager /* wrong type placeholder */, did string, options *dids.DidResolutionOptions) (*dids.DidResolutionResult, error) {
	return nil, nil
}

// adapter to satisfy interface with correct signature
type fakeResolver struct {
	did string
	doc *dids.DidDocument
}

func (f *fakeResolver) Resolve(ctx *corectx.AgentContext, did string, options *dids.DidResolutionOptions) (*dids.DidResolutionResult, error) {
	if did != f.did {
		return &dids.DidResolutionResult{DidResolutionMetadata: &dids.DidResolutionMetadata{Error: dids.DidResolutionErrorNotFound}}, nil
	}
	return &dids.DidResolutionResult{DidDocument: f.doc, DidResolutionMetadata: &dids.DidResolutionMetadata{}}, nil
}
func (f *fakeResolver) SupportedMethods() []string { return []string{"peer"} }

func TestMessageSender_DidResolver_Fallback(t *testing.T) {
	dm := di.NewDependencyManager()
	provider := di.DefaultAgentContextProvider{}
	agentCtx, _ := provider.NewRootContext(dm, "test-resolver")
	ws := wallet.NewWalletService(agentCtx, wallet.NewSimpleKeyRepository())
	dm.RegisterInstance(di.TokenAgentContext, agentCtx)
	dm.RegisterInstance(di.TokenWalletService, ws)

	// Register DidResolverService with fake resolver
	theirDID := "did:peer:example2"
	rk, _ := ws.CreateKey(wallet.KeyTypeEd25519)
	doc := makeDidDoc(theirDID, "wss://subject/resolver", []string{coreencoding.EncodeBase58(rk.PublicKey)})
	dr := dids.NewDidResolverService()
	dr.RegisterResolver(&fakeResolver{did: theirDID, doc: doc})
	dm.RegisterInstance(di.TokenDidResolverService, dr)

	// Connection with TheirDid only
	myKey, _ := ws.CreateKey(wallet.KeyTypeEd25519)
	conn := connservices.NewConnectionRecord("c8")
	conn.MyKeyId = myKey.Id
	conn.TheirDid = theirDID

	es := envelopeServices.NewEnvelopeService(agentCtx)
	es.SetTypedDI(dm)
	ms := transport.NewMessageSender(agentCtx, dm, es, nil)
	fake := &fakeOutboundTransport{}
	ms.RegisterOutboundTransport(fake)

	msg := didcommmessages.NewBaseMessage("https://example.org/test/1.0/resolve")
	out := didcommmodels.NewOutboundMessageContext(msg, didcommmodels.OutboundMessageContextParams{AgentContext: agentCtx, Connection: conn})
	if err := ms.SendMessage(out); err != nil {
		t.Fatalf("SendMessage: %v", err)
	}
	if fake.last == nil {
		t.Fatalf("no captured envelope")
	}
	phBytes, _ := base64.RawURLEncoding.DecodeString(fake.last.Protected)
	var ph envelopeServices.JWEProtectedHeader
	_ = json.Unmarshal(phBytes, &ph)
	if len(ph.Recipients) == 0 || ph.Recipients[0].Header.Kid != coreencoding.EncodeBase58(rk.PublicKey) {
		t.Fatalf("expected resolver-provided recipient kid")
	}
}

func TestMessageSender_ServicePreference_UsesDidCommunicationFirst(t *testing.T) {
	dm := di.NewDependencyManager()
	provider := di.DefaultAgentContextProvider{}
	agentCtx, _ := provider.NewRootContext(dm, "svc-pref")
	ws := wallet.NewWalletService(agentCtx, wallet.NewSimpleKeyRepository())
	dm.RegisterInstance(di.TokenAgentContext, agentCtx)
	dm.RegisterInstance(di.TokenWalletService, ws)

	// Register DidResolverService with fake doc containing services in non-preferred order
	dr := dids.NewDidResolverService()
	// Build DID Doc: DIDCommMessaging, IndyAgent, then did-communication
	theirDID := "did:peer:pref"
	rk, _ := ws.CreateKey(wallet.KeyTypeEd25519)
	doc := dids.NewDidDocument(theirDID)
	doc.AddService(&dids.Service{Id: "s1", Type: dids.ServiceTypeDIDCommMessaging, ServiceEndpoint: "mock://messaging", RecipientKeys: []string{coreencoding.EncodeBase58(rk.PublicKey)}})
	doc.AddService(&dids.Service{Id: "s2", Type: dids.ServiceTypeIndyAgent, ServiceEndpoint: "mock://indy", RecipientKeys: []string{coreencoding.EncodeBase58(rk.PublicKey)}})
	doc.AddService(&dids.Service{Id: "s3", Type: dids.ServiceTypeDIDComm, ServiceEndpoint: "mock://did-communication", RecipientKeys: []string{coreencoding.EncodeBase58(rk.PublicKey)}})
	dr.RegisterResolver(&fakeResolver{did: theirDID, doc: doc})
	dm.RegisterInstance(di.TokenDidResolverService, dr)

	// Connection with TheirDid only
	myKey, _ := ws.CreateKey(wallet.KeyTypeEd25519)
	conn := connservices.NewConnectionRecord("c9")
	conn.MyKeyId = myKey.Id
	conn.TheirDid = theirDID

	es := envelopeServices.NewEnvelopeService(agentCtx)
	es.SetTypedDI(dm)
	ms := transport.NewMessageSender(agentCtx, dm, es, nil)
	// Transport capturing endpoint used
	cap := &captureTransport{}
	ms.RegisterOutboundTransport(cap)

	msg := didcommmessages.NewBaseMessage("https://example.org/pref/1.0/test")
	out := didcommmodels.NewOutboundMessageContext(msg, didcommmodels.OutboundMessageContextParams{AgentContext: agentCtx, Connection: conn})
	if err := ms.SendMessage(out); err != nil {
		t.Fatalf("SendMessage: %v", err)
	}
	if cap.endpoint != "mock://did-communication" {
		t.Fatalf("expected did-communication first, got %s", cap.endpoint)
	}
}
