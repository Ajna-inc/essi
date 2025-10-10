package transport_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	corectx "github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/core/di"
	coreenc "github.com/ajna-inc/essi/pkg/core/encoding"
	"github.com/ajna-inc/essi/pkg/core/wallet"
	"github.com/ajna-inc/essi/pkg/didcomm/messages"
	didcommmodels "github.com/ajna-inc/essi/pkg/didcomm/models"
	connservices "github.com/ajna-inc/essi/pkg/didcomm/modules/connections/services"
	envelopeServices "github.com/ajna-inc/essi/pkg/didcomm/services"
	transport "github.com/ajna-inc/essi/pkg/didcomm/transport"
)

// pickFreePort returns an available TCP port bound to localhost
func pickFreePort2(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen :0: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// newReceiver spins up a MessageReceiver with minimal DI (WalletService) and EnvelopeService
func newReceiver(t *testing.T) (*transport.MessageReceiver, int, func()) {
	t.Helper()

	dm := di.NewDependencyManager()
	provider := di.DefaultAgentContextProvider{}
	agentCtx, _ := provider.NewRootContext(dm, "test")

	// Minimal wallet service backed by simple in-memory repository
	ws := wallet.NewWalletService(agentCtx, wallet.NewSimpleKeyRepository())
	dm.RegisterInstance(di.TokenAgentContext, agentCtx)
	dm.RegisterInstance(di.TokenWalletService, ws)

	es := envelopeServices.NewEnvelopeService(agentCtx)
	es.SetTypedDI(dm)

	d := transport.NewDispatcher()
	// Minimal connection service to avoid nil deref in receiver association logic
	cs := connservices.NewConnectionService(agentCtx, &fakeConnRepo{}, ws)

	mr := transport.NewMessageReceiver(agentCtx, es, cs, d, dm)
	port := pickFreePort2(t)
	if err := mr.StartHTTPServer("127.0.0.1", port); err != nil {
		t.Fatalf("start http server: %v", err)
	}
    cleanup := func() { _ = mr.StopHTTPServer() }
    // Wait for health endpoint instead of sleeping
    url := "http://127.0.0.1:" + strconv.Itoa(port) + "/health"
    deadline := time.Now().Add(2 * time.Second)
    for {
        resp, err := http.Get(url)
        if err == nil && resp != nil {
            resp.Body.Close()
            break
        }
        if time.Now().After(deadline) {
            t.Fatalf("message receiver did not become ready: %v", err)
        }
        time.Sleep(10 * time.Millisecond)
    }
    return mr, port, cleanup
}

// fakeConnRepo implements ConnectionRepository with minimal behavior for tests
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

func TestMessageReceiver_AutoDetect_Plaintext_NoContentType(t *testing.T) {
	// Arrange receiver and register a simple handler to avoid unknown-type error
	// Build a fresh receiver with a custom dispatcher that handles our message type
	dm := di.NewDependencyManager()
	provider := di.DefaultAgentContextProvider{}
	agentCtx, _ := provider.NewRootContext(dm, "test")
	ws := wallet.NewWalletService(agentCtx, wallet.NewSimpleKeyRepository())
	dm.RegisterInstance(di.TokenAgentContext, agentCtx)
	dm.RegisterInstance(di.TokenWalletService, ws)
	es := envelopeServices.NewEnvelopeService(agentCtx)
	es.SetTypedDI(dm)

	d := transport.NewDispatcher()
	const msgType = "https://example.org/test/1.0/ping"
	d.Register(msgType, func(in *transport.InboundMessageContext) (*didcommmodels.OutboundMessageContext, error) {
		// No outbound; just prove handler is invoked
		return nil, nil
	})
	cs := connservices.NewConnectionService(agentCtx, &fakeConnRepo{}, ws)
	mr := transport.NewMessageReceiver(agentCtx, es, cs, d, dm)
	port := pickFreePort2(t)
	if err := mr.StartHTTPServer("127.0.0.1", port); err != nil {
		t.Fatalf("start http: %v", err)
	}
	defer mr.StopHTTPServer()

	// Plaintext payload recognizable by auto-detect (no 'protected' field)
	msg := messages.NewBaseMessage(msgType)
	msg.Body = map[string]interface{}{"hello": "world"}
	payload := msg
	b, _ := json.Marshal(payload)
	url := "http://127.0.0.1:" + strconv.Itoa(port)
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
	// Intentionally no Content-Type header
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST plaintext: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("unexpected status: %d", resp.StatusCode)
	}
}

// Test that when decrypt fails due to no recipient key match, we ACK silently with 200
func TestMessageReceiver_Encrypted_NoMatchingRecipientKey_SilentAck(t *testing.T) {
	_, port, done := newReceiver(t)
	defer done()

	// Build a minimal encrypted message with protected header referencing a random (unknown) recipient kid
	// so that UnpackMessage fails with "no corresponding recipient key found" before decryption
	rnd := make([]byte, 32)
	for i := range rnd {
		rnd[i] = byte(1 + i)
	}
	// base58-encode using wallet/encoding? We can reuse didcomm services behavior: kid is base58 of raw Ed25519
	// For test generation we just use a fixed base64url-friendly string but better keep it base58-like.
	// A simple placeholder kid that's not in wallet keys:
	kid := "H3C2AVvLMv7Zx2Y6W9uXfXqYq3L3m5t7w9yXzA1B2C3D"

	protected := envelopeServices.JWEProtectedHeader{
		Enc: "xchacha20poly1305_ietf",
		Typ: "JWM/1.0",
		Alg: "Anoncrypt",
		Recipients: []envelopeServices.JWERecipient{{
			EncryptedKey: "AA", // not used in this path
			Header:       envelopeServices.JWERecipientHeader{Kid: kid},
		}},
	}
	ph, _ := json.Marshal(protected)
	env := &envelopeServices.EncryptedMessage{
		Protected:  base64.RawURLEncoding.EncodeToString(ph),
		IV:         "AA",
		Ciphertext: "AA",
		Tag:        "AA",
	}
	body, _ := json.Marshal(env)

	url := "http://127.0.0.1:" + strconv.Itoa(port)
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/didcomm-envelope-enc")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST encrypted: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected silent 200 for non-matching recipient, got %d", resp.StatusCode)
	}
}

func TestMessageReceiver_UnsupportedContentType_Returns415(t *testing.T) {
	_, port, done := newReceiver(t)
	defer done()
	req, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1:"+strconv.Itoa(port), bytes.NewReader([]byte("hello")))
	req.Header.Set("Content-Type", "text/plain")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("expected 415, got %d", resp.StatusCode)
	}
}

func TestMessageReceiver_JSON_Malformed_Returns400(t *testing.T) {
	_, port, done := newReceiver(t)
	defer done()
	req, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1:"+strconv.Itoa(port), bytes.NewReader([]byte("{")))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestMessageReceiver_Encrypted_MalformedJSON_Returns400(t *testing.T) {
	_, port, done := newReceiver(t)
	defer done()
	req, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1:"+strconv.Itoa(port), bytes.NewReader([]byte("not-json")))
	req.Header.Set("Content-Type", "application/didcomm-envelope-enc")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestMessageReceiver_Encrypted_UnsupportedAlg_Returns400(t *testing.T) {
	_, port, done := newReceiver(t)
	defer done()
	// Build envelope with unsupported alg
	ph := envelopeServices.JWEProtectedHeader{Enc: "xchacha20poly1305_ietf", Typ: "JWM/1.0", Alg: "Unknown", Recipients: []envelopeServices.JWERecipient{{EncryptedKey: "AA", Header: envelopeServices.JWERecipientHeader{Kid: "AB"}}}}
	b, _ := json.Marshal(ph)
	env := &envelopeServices.EncryptedMessage{Protected: base64.RawURLEncoding.EncodeToString(b), IV: "AA", Ciphertext: "AA", Tag: "AA"}
	body, _ := json.Marshal(env)
	req, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1:"+strconv.Itoa(port), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/didcomm-envelope-enc")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestMessageReceiver_SsiAgentWire_Plaintext_200(t *testing.T) {
	// Receiver with dispatcher handling our type
	dm := di.NewDependencyManager()
	provider := di.DefaultAgentContextProvider{}
	ac, _ := provider.NewRootContext(dm, "wire")
	ws := wallet.NewWalletService(ac, wallet.NewSimpleKeyRepository())
	dm.RegisterInstance(di.TokenAgentContext, ac)
	dm.RegisterInstance(di.TokenWalletService, ws)
	es := envelopeServices.NewEnvelopeService(ac)
	es.SetTypedDI(dm)
	d := transport.NewDispatcher()
	const msgType = "https://example.org/wire/1.0/test"
	d.Register(msgType, func(in *transport.InboundMessageContext) (*didcommmodels.OutboundMessageContext, error) {
		return nil, nil
	})
	cs := connservices.NewConnectionService(ac, &fakeConnRepo{}, ws)
	mr := transport.NewMessageReceiver(ac, es, cs, d, dm)
	port := pickFreePort2(t)
	if err := mr.StartHTTPServer("127.0.0.1", port); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer mr.StopHTTPServer()

	msg := messages.NewBaseMessage(msgType)
	msg.Body = map[string]interface{}{"ok": true}
	b, _ := json.Marshal(msg)
	req, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1:"+strconv.Itoa(port), bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/ssi-agent-wire")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestMessageReceiver_NoContentType_MalformedJSON_Returns400(t *testing.T) {
	_, port, done := newReceiver(t)
	defer done()
	req, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1:"+strconv.Itoa(port), bytes.NewReader([]byte("not-json")))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestMessageReceiver_Encrypted_ContentTypeWithCharset_200(t *testing.T) {
	// Server with handler
	dm := di.NewDependencyManager()
	provider := di.DefaultAgentContextProvider{}
	ac, _ := provider.NewRootContext(dm, "enc-ct")
	ws := wallet.NewWalletService(ac, wallet.NewSimpleKeyRepository())
	dm.RegisterInstance(di.TokenAgentContext, ac)
	dm.RegisterInstance(di.TokenWalletService, ws)
	es := envelopeServices.NewEnvelopeService(ac)
	es.SetTypedDI(dm)
	d := transport.NewDispatcher()
	const typ = "https://example.org/enc/1.0/test"
	d.Register(typ, func(in *transport.InboundMessageContext) (*didcommmodels.OutboundMessageContext, error) {
		return nil, nil
	})
	cs := connservices.NewConnectionService(ac, &fakeConnRepo{}, ws)
	mr := transport.NewMessageReceiver(ac, es, cs, d, dm)
	port := pickFreePort2(t)
	if err := mr.StartHTTPServer("127.0.0.1", port); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer mr.StopHTTPServer()

	// Client encrypt to server key
	srvKey, _ := ws.CreateKey(wallet.KeyTypeEd25519)
	cliDM := di.NewDependencyManager()
	ac2, _ := provider.NewRootContext(cliDM, "enc-ct-cli")
	ws2 := wallet.NewWalletService(ac2, wallet.NewSimpleKeyRepository())
	cliDM.RegisterInstance(di.TokenAgentContext, ac2)
	cliDM.RegisterInstance(di.TokenWalletService, ws2)
	es2 := envelopeServices.NewEnvelopeService(ac2)
	es2.SetTypedDI(cliDM)
	msg := messages.NewBaseMessage(typ)
	enc, err := es2.PackMessage(msg, []string{coreenc.EncodeBase58(srvKey.PublicKey)}, envelopeServices.PackageTypeAnoncrypt)
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	body, _ := json.Marshal(enc)
	req, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1:"+strconv.Itoa(port), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/didcomm-encrypted+json; charset=utf-8")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestMessageReceiver_Encrypted_ContentTypeDidcommJson_Variants(t *testing.T) {
	// Server with handler
	dm := di.NewDependencyManager()
	provider := di.DefaultAgentContextProvider{}
	ac, _ := provider.NewRootContext(dm, "enc-json")
	ws := wallet.NewWalletService(ac, wallet.NewSimpleKeyRepository())
	dm.RegisterInstance(di.TokenAgentContext, ac)
	dm.RegisterInstance(di.TokenWalletService, ws)
	es := envelopeServices.NewEnvelopeService(ac)
	es.SetTypedDI(dm)
	d := transport.NewDispatcher()
	const typ = "https://example.org/encjson/1.0/test"
	d.Register(typ, func(in *transport.InboundMessageContext) (*didcommmodels.OutboundMessageContext, error) {
		return nil, nil
	})
	cs := connservices.NewConnectionService(ac, &fakeConnRepo{}, ws)
	mr := transport.NewMessageReceiver(ac, es, cs, d, dm)
	port := pickFreePort2(t)
	if err := mr.StartHTTPServer("127.0.0.1", port); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer mr.StopHTTPServer()

	// Client encrypt to server key
	srvKey, _ := ws.CreateKey(wallet.KeyTypeEd25519)
	cliDM := di.NewDependencyManager()
	ac2, _ := provider.NewRootContext(cliDM, "enc-json-cli")
	ws2 := wallet.NewWalletService(ac2, wallet.NewSimpleKeyRepository())
	cliDM.RegisterInstance(di.TokenAgentContext, ac2)
	cliDM.RegisterInstance(di.TokenWalletService, ws2)
	es2 := envelopeServices.NewEnvelopeService(ac2)
	es2.SetTypedDI(cliDM)
	msg := messages.NewBaseMessage(typ)
	enc, err := es2.PackMessage(msg, []string{coreenc.EncodeBase58(srvKey.PublicKey)}, envelopeServices.PackageTypeAnoncrypt)
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	body, _ := json.Marshal(enc)

	cases := []string{
		"application/didcomm+json",
		"application/didcomm+json; charset=utf-8",
	}
	for _, ct := range cases {
		req, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1:"+strconv.Itoa(port), bytes.NewReader(body))
		req.Header.Set("Content-Type", ct)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST %s: %v", ct, err)
		}
		if resp.StatusCode != 200 {
			t.Fatalf("%s expected 200, got %d", ct, resp.StatusCode)
		}
		resp.Body.Close()
	}
}
func TestMessageReceiver_Plaintext_ContentTypeJSON(t *testing.T) {
	// Minimal server with handler
	dm := di.NewDependencyManager()
	provider := di.DefaultAgentContextProvider{}
	ac, _ := provider.NewRootContext(dm, "srv")
	ws := wallet.NewWalletService(ac, wallet.NewSimpleKeyRepository())
	dm.RegisterInstance(di.TokenAgentContext, ac)
	dm.RegisterInstance(di.TokenWalletService, ws)
	es := envelopeServices.NewEnvelopeService(ac)
	es.SetTypedDI(dm)
	d := transport.NewDispatcher()
	const msgType = "https://example.org/test/1.0/json"
	d.Register(msgType, func(in *transport.InboundMessageContext) (*didcommmodels.OutboundMessageContext, error) {
		return nil, nil
	})
	cs := connservices.NewConnectionService(ac, &fakeConnRepo{}, ws)
	mr := transport.NewMessageReceiver(ac, es, cs, d, dm)
	port := pickFreePort2(t)
	if err := mr.StartHTTPServer("127.0.0.1", port); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer mr.StopHTTPServer()

	msg := messages.NewBaseMessage(msgType)
	msg.Body = map[string]interface{}{"x": 1}
	b, _ := json.Marshal(msg)
	req, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1:"+strconv.Itoa(port), bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST json: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("unexpected status: %d", resp.StatusCode)
	}
}

func TestMessageReceiver_Encrypted_ContentTypeVariants(t *testing.T) {
	// Server side for inline return-route response
	dmSrv := di.NewDependencyManager()
	provider := di.DefaultAgentContextProvider{}
	acSrv, _ := provider.NewRootContext(dmSrv, "srv2")
	wsSrv := wallet.NewWalletService(acSrv, wallet.NewSimpleKeyRepository())
	dmSrv.RegisterInstance(di.TokenAgentContext, acSrv)
	dmSrv.RegisterInstance(di.TokenWalletService, wsSrv)
	esSrv := envelopeServices.NewEnvelopeService(acSrv)
	esSrv.SetTypedDI(dmSrv)
	d := transport.NewDispatcher()
	const inType = "https://example.org/test/1.0/ct"
	d.Register(inType, func(in *transport.InboundMessageContext) (*didcommmodels.OutboundMessageContext, error) {
		resp := messages.NewBaseMessage("https://example.org/test/1.0/ct_response")
		return didcommmodels.NewOutboundMessageContext(resp, didcommmodels.OutboundMessageContextParams{AgentContext: acSrv}), nil
	})
	cs := connservices.NewConnectionService(acSrv, &fakeConnRepo{}, wsSrv)
	mr := transport.NewMessageReceiver(acSrv, esSrv, cs, d, dmSrv)
	port := pickFreePort2(t)
	if err := mr.StartHTTPServer("127.0.0.1", port); err != nil {
		t.Fatalf("server: %v", err)
	}
	defer mr.StopHTTPServer()

	// Client packer
	dmCli := di.NewDependencyManager()
	acCli, _ := provider.NewRootContext(dmCli, "cli2")
	wsCli := wallet.NewWalletService(acCli, wallet.NewSimpleKeyRepository())
	dmCli.RegisterInstance(di.TokenAgentContext, acCli)
	dmCli.RegisterInstance(di.TokenWalletService, wsCli)
	esCli := envelopeServices.NewEnvelopeService(acCli)
	esCli.SetTypedDI(dmCli)
	// sender and recipient
	sk, _ := wsCli.CreateKey(wallet.KeyTypeEd25519)
	esCli.SetSenderKey(sk.PrivateKey)
	rk, _ := wsSrv.CreateKey(wallet.KeyTypeEd25519)
	recip := coreenc.EncodeBase58(rk.PublicKey)
	msg := messages.NewBaseMessage(inType)
	if msg.GetTransport() == nil {
		msg.SetTransport(&messages.TransportDecorator{})
	}
	msg.GetTransport().ReturnRoute = messages.ReturnRouteAll
	enc, err := esCli.PackMessage(msg, []string{recip}, envelopeServices.PackageTypeAuthcrypt)
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	body, _ := json.Marshal(enc)
	url := "http://127.0.0.1:" + strconv.Itoa(port)

	variants := []string{"application/didcomm-encrypted+json", "application/didcomm+json"}
	for _, ct := range variants {
		req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
		req.Header.Set("Content-Type", ct)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST %s: %v", ct, err)
		}
		if resp.StatusCode != 200 {
			t.Fatalf("%s status: %d", ct, resp.StatusCode)
		}
		resp.Body.Close()
	}
}

// Test that when an authcrypt message arrives with ~transport.return_route=all
// and the handler returns an outbound message, the receiver packs and returns
// an inline encrypted DIDComm envelope targeting the sender key.
func TestMessageReceiver_InlineReturnRoute_Authcrypt(t *testing.T) {
	// Server DI and services
	dmSrv := di.NewDependencyManager()
	provider := di.DefaultAgentContextProvider{}
	agentCtxSrv, _ := provider.NewRootContext(dmSrv, "server")
	wsSrv := wallet.NewWalletService(agentCtxSrv, wallet.NewSimpleKeyRepository())
	dmSrv.RegisterInstance(di.TokenAgentContext, agentCtxSrv)
	dmSrv.RegisterInstance(di.TokenWalletService, wsSrv)

	// Create server recipient key (the key the client will encrypt to)
	srvKey, err := wsSrv.CreateKey(wallet.KeyTypeEd25519)
	if err != nil {
		t.Fatalf("server key: %v", err)
	}

	esSrv := envelopeServices.NewEnvelopeService(agentCtxSrv)
	esSrv.SetTypedDI(dmSrv)

	// Dispatcher: register handler that returns a response outbound message
	d := transport.NewDispatcher()
	const inType = "https://example.org/test/1.0/echo"
	d.Register(inType, func(in *transport.InboundMessageContext) (*didcommmodels.OutboundMessageContext, error) {
		resp := messages.NewBaseMessage("https://example.org/test/1.0/echo_response")
		return didcommmodels.NewOutboundMessageContext(resp, didcommmodels.OutboundMessageContextParams{AgentContext: agentCtxSrv}), nil
	})

	// Connection service minimal
	cs := connservices.NewConnectionService(agentCtxSrv, &fakeConnRepo{}, wsSrv)
	mr := transport.NewMessageReceiver(agentCtxSrv, esSrv, cs, d, dmSrv)
	port := pickFreePort2(t)
	if err := mr.StartHTTPServer("127.0.0.1", port); err != nil {
		t.Fatalf("server start: %v", err)
	}
	defer mr.StopHTTPServer()

	// Client DI and services
	dmCli := di.NewDependencyManager()
	agentCtxCli, _ := provider.NewRootContext(dmCli, "client")
	wsCli := wallet.NewWalletService(agentCtxCli, wallet.NewSimpleKeyRepository())
	dmCli.RegisterInstance(di.TokenAgentContext, agentCtxCli)
	dmCli.RegisterInstance(di.TokenWalletService, wsCli)

	// Client sender key (authcrypt requires sender private key)
	cliKey, err := wsCli.CreateKey(wallet.KeyTypeEd25519)
	if err != nil {
		t.Fatalf("client key: %v", err)
	}

	esCli := envelopeServices.NewEnvelopeService(agentCtxCli)
	esCli.SetTypedDI(dmCli)
	esCli.SetSenderKey(cliKey.PrivateKey)

	// Build inbound plaintext with ~transport.return_route=all and pack authcrypt for server key
	msg := messages.NewBaseMessage(inType)
	if msg.GetTransport() == nil {
		msg.SetTransport(&messages.TransportDecorator{})
	}
	msg.GetTransport().ReturnRoute = messages.ReturnRouteAll
	recip := coreenc.EncodeBase58(srvKey.PublicKey)
	enc, err := esCli.PackMessage(msg, []string{recip}, envelopeServices.PackageTypeAuthcrypt)
	if err != nil {
		t.Fatalf("client pack: %v", err)
	}

	// POST to server
	b, _ := json.Marshal(enc)
	url := "http://127.0.0.1:" + strconv.Itoa(port)
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/didcomm-envelope-enc")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST authcrypt: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/didcomm-envelope-enc" {
		t.Fatalf("expected didcomm envelope content type, got %s", ct)
	}
	var inline envelopeServices.EncryptedMessage
	if err := json.NewDecoder(resp.Body).Decode(&inline); err != nil {
		t.Fatalf("decode inline enc: %v", err)
	}
	if inline.Protected == "" {
		t.Fatalf("inline response missing protected header")
	}

	// Decrypt inline with client wallet
	dec, err := esCli.UnpackMessage(&inline)
	if err != nil {
		t.Fatalf("client unpack inline: %v", err)
	}
	if dec.PlaintextMessage.Type != "https://example.org/test/1.0/echo_response" {
		t.Fatalf("unexpected inline response type: %s", dec.PlaintextMessage.Type)
	}
}

// dmAgentCtx kept if needed in future tests
func dmAgentCtx(t *testing.T, dm di.DependencyManager) *corectx.AgentContext {
	if any, err := dm.Resolve(di.TokenAgentContext); err == nil {
		if ac, ok := any.(*corectx.AgentContext); ok {
			return ac
		}
	}
	t.Fatalf("AgentContext not available in DI")
	return nil
}
