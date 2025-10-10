package services_test

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	corectx "github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/core/di"
	"github.com/ajna-inc/essi/pkg/core/wallet"
	services "github.com/ajna-inc/essi/pkg/didcomm/services"
	peer "github.com/ajna-inc/essi/pkg/dids/methods/peer"
)

func buildJwsDI(t *testing.T) (*di.DependencyManager, *corectx.AgentContext, *wallet.WalletService) {
	dm := di.NewDependencyManager()
	provider := di.DefaultAgentContextProvider{}
	ac, _ := provider.NewRootContext(dm, "jws")
	ws := wallet.NewWalletService(ac, wallet.NewSimpleKeyRepository())
	dm.RegisterInstance(di.TokenAgentContext, ac)
	dm.RegisterInstance(di.TokenWalletService, ws)
	return &dm, ac, ws
}

func TestJws_CreateAndVerify_WithKid(t *testing.T) {
	_, ac, ws := buildJwsDI(t)
	key, _ := ws.CreateKey(wallet.KeyTypeEd25519)
	svc := services.NewJwsService(ws)
	payload := []byte("hello-world")
	fp, _ := peer.Ed25519Fingerprint(key.PublicKey)
	didkid := "did:key:" + fp

	jws, err := svc.CreateJws(ac, services.CreateJwsOptions{
		Payload:                payload,
		KeyId:                  key.Id,
		ProtectedHeaderOptions: &services.JwsHeader{Kid: didkid},
	})
	if err != nil {
		t.Fatalf("CreateJws: %v", err)
	}
	ok, err := svc.VerifyJws(ac, jws, payload)
	if err != nil || !ok {
		t.Fatalf("VerifyJws failed: %v ok=%v", err, ok)
	}
}

func TestJws_CreateAndVerify_WithJwk(t *testing.T) {
	_, ac, ws := buildJwsDI(t)
	key, _ := ws.CreateKey(wallet.KeyTypeEd25519)
	svc := services.NewJwsService(ws)
	payload := []byte("payload")

	jws, err := svc.CreateJws(ac, services.CreateJwsOptions{
		Payload:                payload,
		KeyId:                  key.Id,
		ProtectedHeaderOptions: &services.JwsHeader{Jwk: map[string]interface{}{"dummy": true}},
	})
	if err != nil {
		t.Fatalf("CreateJws: %v", err)
	}
	// Ensure protected contains JWK with x
	pb, _ := base64.RawURLEncoding.DecodeString(jws.Protected)
	var hdr services.JwsHeader
	_ = json.Unmarshal(pb, &hdr)
	if hdr.Jwk == nil || hdr.Jwk["x"] == nil {
		t.Fatalf("expected embedded JWK public key")
	}
	ok, err := svc.VerifyJws(ac, jws, payload)
	if err != nil || !ok {
		t.Fatalf("VerifyJws failed: %v ok=%v", err, ok)
	}
}

func TestJws_CreateSignedAttachment(t *testing.T) {
	_, ac, ws := buildJwsDI(t)
	key, _ := ws.CreateKey(wallet.KeyTypeEd25519)
	svc := services.NewJwsService(ws)
	payload := map[string]interface{}{"foo": "bar"}
	fp, _ := peer.Ed25519Fingerprint(key.PublicKey)
	invitationKey := "did:key:" + fp

	att, err := svc.CreateSignedAttachment(ac, payload, key.Id, invitationKey)
	if err != nil {
		t.Fatalf("CreateSignedAttachment: %v", err)
	}
	if att == nil || att.Data == nil || att.Data.Jws == nil {
		t.Fatalf("attachment/jws missing")
	}
	// Verify protected has jwk and header kid equals invitation key
	pb, _ := base64.RawURLEncoding.DecodeString(att.Data.Jws.Protected)
	var hdr services.JwsHeader
	_ = json.Unmarshal(pb, &hdr)
	if hdr.Jwk == nil {
		t.Fatalf("expected JWK embedded in protected header")
	}
	if kid, _ := att.Data.Jws.Header["kid"].(string); kid != invitationKey {
		t.Fatalf("expected header kid to equal invitation key")
	}
}

func TestJws_Create_WithNonEd25519Key_Fails(t *testing.T) {
	_, ac, ws := buildJwsDI(t)
	// Create X25519 key
	key, _ := ws.CreateKey(wallet.KeyTypeX25519)
	svc := services.NewJwsService(ws)
	_, err := svc.CreateJws(ac, services.CreateJwsOptions{Payload: []byte("x"), KeyId: key.Id})
	if err == nil {
		t.Fatalf("expected error for non-Ed25519 key")
	}
}

func TestJws_Verify_UnsupportedAlg_Fails(t *testing.T) {
	_, ac, ws := buildJwsDI(t)
	key, _ := ws.CreateKey(wallet.KeyTypeEd25519)
	svc := services.NewJwsService(ws)
	// Build jws with unsupported alg in protected header
	hdr := services.JwsHeader{Alg: "ES256"}
	hb, _ := json.Marshal(hdr)
	j := &services.Jws{Protected: base64.RawURLEncoding.EncodeToString(hb), Signature: "", Header: map[string]interface{}{}}
	if _, err := svc.VerifyJws(ac, j, []byte("payload")); err == nil {
		t.Fatalf("expected verify error for unsupported alg")
	}
	_ = key // avoid unused warning if build tags differ
}

func TestJws_Verify_BadSignature_ReturnsFalse(t *testing.T) {
	_, ac, ws := buildJwsDI(t)
	key, _ := ws.CreateKey(wallet.KeyTypeEd25519)
	svc := services.NewJwsService(ws)
	payload := []byte("original")
	jws, err := svc.CreateJws(ac, services.CreateJwsOptions{Payload: payload, KeyId: key.Id, ProtectedHeaderOptions: &services.JwsHeader{Jwk: map[string]interface{}{}}})
	if err != nil {
		t.Fatalf("CreateJws: %v", err)
	}
	// Verify with different payload
	ok, err := svc.VerifyJws(ac, jws, []byte("tampered"))
	if err != nil {
		t.Fatalf("VerifyJws returned error for bad signature: %v", err)
	}
	if ok {
		t.Fatalf("expected verify false for tampered payload")
	}
}

func TestJws_Verify_InvalidDidKeyKid_Fails(t *testing.T) {
	_, ac, ws := buildJwsDI(t)
	_, _ = ws.CreateKey(wallet.KeyTypeEd25519)
	svc := services.NewJwsService(ws)
	// Protected with invalid did:key kid that won't parse as Ed25519 (missing z6Mk prefix content)
	hdr := services.JwsHeader{Alg: "EdDSA", Kid: "did:key:zXYZ"}
	hb, _ := json.Marshal(hdr)
	j := &services.Jws{Protected: base64.RawURLEncoding.EncodeToString(hb), Signature: base64.RawURLEncoding.EncodeToString([]byte("sig")), Header: map[string]interface{}{}}
	if _, err := svc.VerifyJws(ac, j, []byte("payload")); err == nil {
		t.Fatalf("expected error for invalid did:key kid format")
	}
}

func TestJws_Verify_MissingProtected_Fails(t *testing.T) {
	_, ac, ws := buildJwsDI(t)
	_, _ = ws.CreateKey(wallet.KeyTypeEd25519)
	svc := services.NewJwsService(ws)
	j := &services.Jws{Protected: "", Signature: "", Header: map[string]interface{}{}}
	if _, err := svc.VerifyJws(ac, j, []byte("payload")); err == nil {
		t.Fatalf("expected error for missing protected header")
	}
}

func TestJws_Verify_JwkWrongLength_Fails(t *testing.T) {
	_, ac, ws := buildJwsDI(t)
	_, _ = ws.CreateKey(wallet.KeyTypeEd25519)
	svc := services.NewJwsService(ws)
	hdr := services.JwsHeader{Alg: "EdDSA", Jwk: map[string]interface{}{"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString([]byte("short"))}}
	hb, _ := json.Marshal(hdr)
	j := &services.Jws{Protected: base64.RawURLEncoding.EncodeToString(hb), Signature: base64.RawURLEncoding.EncodeToString([]byte("sig")), Header: map[string]interface{}{}}
	if _, err := svc.VerifyJws(ac, j, []byte("payload")); err == nil {
		t.Fatalf("expected error for wrong public key size in JWK")
	}
}
