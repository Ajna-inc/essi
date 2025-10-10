package transport_test

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ajna-inc/essi/pkg/core/di"
	"github.com/ajna-inc/essi/pkg/core/encoding"
	"github.com/ajna-inc/essi/pkg/core/wallet"
	didcommmessages "github.com/ajna-inc/essi/pkg/didcomm/messages"
	didcommmodels "github.com/ajna-inc/essi/pkg/didcomm/models"
	connservices "github.com/ajna-inc/essi/pkg/didcomm/modules/connections/services"
	envelopeServices "github.com/ajna-inc/essi/pkg/didcomm/services"
	transport "github.com/ajna-inc/essi/pkg/didcomm/transport"
)

// Test that when an encrypted message requests return-route and the dispatcher
// returns an outbound message, MessageReceiver packs and returns an inline JWE
// response using authcrypt (when recipient private key is available).
func TestMessageReceiver_InlineReturnRoute_AuthcryptResponse(t *testing.T) {
	// Build typed DI and receiver services with a wallet containing a recipient key
	dm := di.NewDependencyManager()
	provider := di.DefaultAgentContextProvider{}
	agentCtx, _ := provider.NewRootContext(dm, "rr-inline")
	ws := wallet.NewWalletService(agentCtx, wallet.NewSimpleKeyRepository())
	dm.RegisterInstance(di.TokenAgentContext, agentCtx)
	dm.RegisterInstance(di.TokenWalletService, ws)

	// Create receiver key in wallet; this is the kid we will encrypt to
	recvKey, err := ws.CreateKey(wallet.KeyTypeEd25519)
	if err != nil {
		t.Fatalf("create receiver key: %v", err)
	}

	// Envelope service and dispatcher
	es := envelopeServices.NewEnvelopeService(agentCtx)
	es.SetTypedDI(dm)
	// Ensure kids use did:key for robust decoding during test
	es.SetKidFormatForTesting("didkey")
	d := transport.NewDispatcher()
	// Minimal connection service to satisfy receiver association logic
	cs := connservices.NewConnectionService(agentCtx, &fakeConnRepo{}, ws)

	// Register a handler for our ping type that returns a simple reply
	const pingType = "https://example.org/test/1.0/ping"
	const pongType = "https://example.org/test/1.0/pong"
	d.Register(pingType, func(in *transport.InboundMessageContext) (*didcommmodels.OutboundMessageContext, error) {
		// Build a reply message; MessageReceiver will handle inline packing
		reply := didcommmessages.NewReplyMessage(pongType, in.Message)
		out := didcommmodels.NewOutboundMessageContext(reply, didcommmodels.OutboundMessageContextParams{AgentContext: agentCtx})
		return out, nil
	})

	// Create MessageReceiver (no HTTP needed; we'll inject encrypted payload directly)
	mr := transport.NewMessageReceiver(agentCtx, es, cs, d, dm)

	// Build a sender context with its own key and pack an authcrypt message for receiver
	senderKey, err := ws.CreateKey(wallet.KeyTypeEd25519)
	if err != nil {
		t.Fatalf("create sender key: %v", err)
	}
	// Pack from a separate EnvelopeService to mirror another agent
	esSender := envelopeServices.NewEnvelopeService(agentCtx)
	esSender.SetKidFormatForTesting("didkey")
	esSender.SetSenderKey(senderKey.PrivateKey)

	// Construct plaintext ping requesting return-route
	msg := didcommmessages.NewBaseMessage(pingType)
	msg.SetReturnRoute(didcommmessages.ReturnRouteAll)
	plaintext, _ := msg.ToJSON()

	// Pack to receiver using authcrypt
	to := []string{encoding.EncodeBase58(recvKey.PublicKey)}
	enc, err := esSender.PackMessage(plaintext, to, envelopeServices.PackageTypeAuthcrypt)
	if err != nil {
		t.Fatalf("pack authcrypt: %v", err)
	}

	// Marshal encrypted envelope to bytes and feed to receiver
	body, _ := json.Marshal(enc)
	resp, status := mr.ReceiveEncrypted(body)
	if status != 200 {
		t.Fatalf("expected 200 inline response, got %d", status)
	}
	hr, ok := resp.(*transport.HttpResponse)
	if !ok || hr == nil {
		t.Fatalf("expected HttpResponse body for inline return-route")
	}
	if hr.ContentType == "" || hr.Body == nil || len(hr.Body) == 0 {
		t.Fatalf("inline response missing content-type/body")
	}

	// Inspect protected header to ensure authcrypt was used
	var got envelopeServices.EncryptedMessage
	if err := json.Unmarshal(hr.Body, &got); err != nil {
		t.Fatalf("unmarshal inline envelope: %v", err)
	}
	phBytes, err := base64.RawURLEncoding.DecodeString(got.Protected)
	if err != nil {
		t.Fatalf("decode protected: %v", err)
	}
	var ph envelopeServices.JWEProtectedHeader
	if err := json.Unmarshal(phBytes, &ph); err != nil {
		t.Fatalf("unmarshal protected: %v", err)
	}
	if strings.ToLower(ph.Alg) != "authcrypt" {
		t.Fatalf("expected authcrypt inline response, got alg=%s", ph.Alg)
	}

	// Decrypt inline response using the same wallet (contains sender key)
	esForDecrypt := envelopeServices.NewEnvelopeService(agentCtx)
	esForDecrypt.SetTypedDI(dm)
	dec, err := esForDecrypt.UnpackMessage(&got)
	if err != nil {
		t.Fatalf("decrypt inline response: %v", err)
	}
	if dec.PlaintextMessage.Type != pongType {
		t.Fatalf("unexpected response type: %s", dec.PlaintextMessage.Type)
	}
}
