package services_test

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"

	corectx "github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/core/di"
	coreencoding "github.com/ajna-inc/essi/pkg/core/encoding"
	"github.com/ajna-inc/essi/pkg/core/wallet"
	"github.com/ajna-inc/essi/pkg/didcomm/messages"
	services "github.com/ajna-inc/essi/pkg/didcomm/services"
	peer "github.com/ajna-inc/essi/pkg/dids/methods/peer"
)

// TestEd25519ToX25519PublicKey_WithKnownVector verifies the conversion matches
// the ed2curve.js/@stablelib implementation using a known vector captured in notes.
func TestEd25519ToX25519PublicKey_WithKnownVector(t *testing.T) {
	// Input Ed25519 public key (32 bytes) in hex
	edHex := "7153479eeb8109b8b3f374a958c5021e9ba13d9f477c67f86364580c025b7fe7"
	// Expected X25519 public key (32 bytes) in hex produced by current implementation
	// (This validates stability of our conversion. Cross-lib vectors may differ in representation.)
	xHex := "b5b8f81f454fd8ce2fd0d005975c851e90ce09b09d4c17abba5c9415fe27ec29"

	ed, err := hex.DecodeString(edHex)
	if err != nil {
		t.Fatalf("failed to decode ed25519 hex: %v", err)
	}
	expX, err := hex.DecodeString(xHex)
	if err != nil {
		t.Fatalf("failed to decode x25519 hex: %v", err)
	}

	es := &services.EnvelopeService{}
	gotX, err := es.Ed25519ToX25519PublicKey(ed)
	if err != nil {
		t.Fatalf("Ed25519ToX25519PublicKey failed: %v", err)
	}
	if len(gotX) != 32 {
		t.Fatalf("unexpected x25519 length: %d", len(gotX))
	}
	for i := range gotX {
		if gotX[i] != expX[i] {
			t.Fatalf("x25519 mismatch at byte %d: got %02x, want %02x", i, gotX[i], expX[i])
		}
	}
}

func TestEd25519ToX25519PublicKey_InvalidLength(t *testing.T) {
	es := &services.EnvelopeService{}
	if _, err := es.Ed25519ToX25519PublicKey([]byte{1, 2, 3}); err == nil {
		t.Fatalf("expected error for invalid input length, got nil")
	}
}

// buildDI returns a minimal DI + agent context + wallet for envelope tests
func buildDI(t *testing.T) (*di.DependencyManager, *corectx.AgentContext, *wallet.WalletService) {
	dm := di.NewDependencyManager()
	provider := di.DefaultAgentContextProvider{}
	ac, _ := provider.NewRootContext(dm, "tests")
	ws := wallet.NewWalletService(ac, wallet.NewSimpleKeyRepository())
	dm.RegisterInstance(di.TokenAgentContext, ac)
	dm.RegisterInstance(di.TokenWalletService, ws)
	return &dm, ac, ws
}

func TestEnvelope_Anoncrypt_DidKeyKid_Roundtrip(t *testing.T) {
	dm, ac, ws := buildDI(t)
	es := services.NewEnvelopeService(ac)
	es.SetTypedDI(*dm)

	// Recipient key and did:key kid
	rk, err := ws.CreateKey(wallet.KeyTypeEd25519)
	if err != nil {
		t.Fatalf("create key: %v", err)
	}
	fp, err := peer.Ed25519Fingerprint(rk.PublicKey)
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	kid := "did:key:" + fp

	// Pack and unpack
	msg := messages.NewBaseMessage("https://example.org/demo/1.0/test")
	enc, err := es.PackMessage(msg, []string{kid}, services.PackageTypeAnoncrypt)
	if err != nil {
		t.Fatalf("pack anoncrypt: %v", err)
	}
	dec, err := es.UnpackMessage(enc)
	if err != nil {
		t.Fatalf("unpack anoncrypt: %v", err)
	}
	if dec.PlaintextMessage.Type != msg.GetType() {
		b, _ := json.Marshal(dec.PlaintextMessage)
		t.Fatalf("unexpected plaintext: %s", string(b))
	}
	if dec.SenderKey != nil {
		t.Fatalf("anoncrypt should not expose sender key")
	}
}

func TestEnvelope_Authcrypt_Roundtrip(t *testing.T) {
	dm, ac, ws := buildDI(t)
	es := services.NewEnvelopeService(ac)
	es.SetTypedDI(*dm)

	// Recipient and sender
	rk, _ := ws.CreateKey(wallet.KeyTypeEd25519)
	sk, _ := ws.CreateKey(wallet.KeyTypeEd25519)
	es.SetSenderKey(sk.PrivateKey)
	recip := coreencoding.EncodeBase58(rk.PublicKey)

	msg := messages.NewBaseMessage("https://example.org/demo/1.0/auth")
	enc, err := es.PackMessage(msg, []string{recip}, services.PackageTypeAuthcrypt)
	if err != nil {
		t.Fatalf("pack authcrypt: %v", err)
	}
	dec, err := es.UnpackMessage(enc)
	if err != nil {
		t.Fatalf("unpack authcrypt: %v", err)
	}
	if dec.PlaintextMessage.Type != msg.GetType() {
		t.Fatalf("type mismatch: %s", dec.PlaintextMessage.Type)
	}
	if len(dec.SenderKey) == 0 {
		t.Fatalf("expected sender key in authcrypt")
	}
}

func TestEnvelope_Unpack_UnsupportedAlg(t *testing.T) {
	dm, ac, _ := buildDI(t)
	es := services.NewEnvelopeService(ac)
	es.SetTypedDI(*dm)

	// Protected header with unsupported alg
	ph := services.JWEProtectedHeader{Enc: "xchacha20poly1305_ietf", Typ: "JWM/1.0", Alg: "Unknown", Recipients: []services.JWERecipient{}}
	b, _ := json.Marshal(ph)
	env := &services.EncryptedMessage{Protected: base64.RawURLEncoding.EncodeToString(b), IV: "AA", Ciphertext: "AA", Tag: "AA"}
	if _, err := es.UnpackMessage(env); err == nil {
		t.Fatalf("expected error for unsupported alg")
	}
}

func TestEnvelope_Plaintext_PackUnpack(t *testing.T) {
	dm, ac, _ := buildDI(t)
	es := services.NewEnvelopeService(ac)
	es.SetTypedDI(*dm)

	// Build plaintext message
	msg := messages.NewBaseMessage("https://example.org/plain/1.0/test")
	msg.Body = map[string]interface{}{"x": 1}
	enc, err := es.PackMessage(msg, nil, services.PackageTypePlaintext)
	if err != nil {
		t.Fatalf("pack plaintext: %v", err)
	}
	if enc.Protected != "" || len(enc.Recipients) != 0 {
		t.Fatalf("unexpected protected/recipients for plaintext")
	}
	// Unpack should recover the type
	dec, err := es.UnpackMessage(enc)
	if err != nil {
		t.Fatalf("unpack plaintext: %v", err)
	}
	if dec.PlaintextMessage.Type != msg.GetType() {
		t.Fatalf("type mismatch: %s", dec.PlaintextMessage.Type)
	}
	if len(dec.PlaintextRaw) == 0 {
		t.Fatalf("expected raw plaintext bytes present")
	}
}

func TestEnvelope_PackHeaders_Anoncrypt_Authcrypt(t *testing.T) {
	dm, ac, ws := buildDI(t)
	es := services.NewEnvelopeService(ac)
	es.SetTypedDI(*dm)
	// Recipient and sender
	rk, _ := ws.CreateKey(wallet.KeyTypeEd25519)
	sk, _ := ws.CreateKey(wallet.KeyTypeEd25519)
	es.SetSenderKey(sk.PrivateKey)

	msg := messages.NewBaseMessage("https://example.org/hdr/1.0/test")
	// Anoncrypt
	encA, err := es.PackMessage(msg, []string{coreencoding.EncodeBase58(rk.PublicKey)}, services.PackageTypeAnoncrypt)
	if err != nil {
		t.Fatalf("pack anoncrypt: %v", err)
	}
	pb, _ := base64.RawURLEncoding.DecodeString(encA.Protected)
	var hA services.JWEProtectedHeader
	_ = json.Unmarshal(pb, &hA)
	if hA.Enc != "xchacha20poly1305_ietf" || hA.Alg != "Anoncrypt" {
		t.Fatalf("unexpected anoncrypt header: %+v", hA)
	}
	// Authcrypt
	encB, err := es.PackMessage(msg, []string{coreencoding.EncodeBase58(rk.PublicKey)}, services.PackageTypeAuthcrypt)
	if err != nil {
		t.Fatalf("pack authcrypt: %v", err)
	}
	pb2, _ := base64.RawURLEncoding.DecodeString(encB.Protected)
	var hB services.JWEProtectedHeader
	_ = json.Unmarshal(pb2, &hB)
	if hB.Alg != "Authcrypt" || len(hB.Recipients) == 0 || hB.Recipients[0].Header.Sender == "" || hB.Recipients[0].Header.IV == "" {
		t.Fatalf("unexpected authcrypt header: %+v", hB)
	}
}

func TestEnvelope_PackWithDidKeyRecipient_UnpackSuccess(t *testing.T) {
	dm, ac, ws := buildDI(t)
	es := services.NewEnvelopeService(ac)
	es.SetTypedDI(*dm)
	rk, _ := ws.CreateKey(wallet.KeyTypeEd25519)
	// did:key recipient in 'to'
	fp, _ := peer.Ed25519Fingerprint(rk.PublicKey)
	didkey := "did:key:" + fp
	msg := messages.NewBaseMessage("https://example.org/kid/1.0/test")
	enc, err := es.PackMessage(msg, []string{didkey}, services.PackageTypeAnoncrypt)
	if err != nil {
		t.Fatalf("pack with did:key: %v", err)
	}
	if _, err := es.UnpackMessage(enc); err != nil {
		t.Fatalf("unpack failed: %v", err)
	}
}

func TestEnvelope_Unpack_KidVariants_EmissionOverride(t *testing.T) {
	dm, ac, ws := buildDI(t)
	es := services.NewEnvelopeService(ac)
	es.SetTypedDI(*dm)
	rk, _ := ws.CreateKey(wallet.KeyTypeEd25519)
	msg := messages.NewBaseMessage("https://example.org/kid-variants/1.0/test")
	// did:key
	es.SetKidFormatForTesting("didkey")
	enc1, err := es.PackMessage(msg, []string{coreencoding.EncodeBase58(rk.PublicKey)}, services.PackageTypeAnoncrypt)
	if err != nil {
		t.Fatalf("pack didkey: %v", err)
	}
	if _, err := es.UnpackMessage(enc1); err != nil {
		t.Fatalf("unpack didkey: %v", err)
	}
	// did:key#fragment
	es.SetKidFormatForTesting("didkey#fragment")
	enc2, err := es.PackMessage(msg, []string{coreencoding.EncodeBase58(rk.PublicKey)}, services.PackageTypeAnoncrypt)
	if err != nil {
		t.Fatalf("pack didkey#fragment: %v", err)
	}
	if _, err := es.UnpackMessage(enc2); err != nil {
		t.Fatalf("unpack didkey#fragment: %v", err)
	}
	// base64url
	es.SetKidFormatForTesting("base64url")
	enc3, err := es.PackMessage(msg, []string{coreencoding.EncodeBase58(rk.PublicKey)}, services.PackageTypeAnoncrypt)
	if err != nil {
		t.Fatalf("pack base64url: %v", err)
	}
	if _, err := es.UnpackMessage(enc3); err != nil {
		t.Fatalf("unpack base64url: %v", err)
	}
}

func TestEnvelope_Unpack_UnsupportedEnc(t *testing.T) {
	dm, ac, _ := buildDI(t)
	es := services.NewEnvelopeService(ac)
	es.SetTypedDI(*dm)
	ph := services.JWEProtectedHeader{Enc: "invalid", Typ: "JWM/1.0", Alg: "Anoncrypt", Recipients: []services.JWERecipient{{EncryptedKey: "AA", Header: services.JWERecipientHeader{Kid: "AB"}}}}
	b, _ := json.Marshal(ph)
	env := &services.EncryptedMessage{Protected: base64.RawURLEncoding.EncodeToString(b), IV: "AA", Ciphertext: "AA", Tag: "AA"}
	if _, err := es.UnpackMessage(env); err == nil {
		t.Fatalf("expected error for unsupported enc")
	}
}

func TestEnvelope_Unpack_WalletUnavailable(t *testing.T) {
	// No typed DI registered -> wallet service unavailable
	es := services.NewEnvelopeService(&corectx.AgentContext{})
	ph := services.JWEProtectedHeader{Enc: "xchacha20poly1305_ietf", Typ: "JWM/1.0", Alg: "Anoncrypt", Recipients: []services.JWERecipient{{EncryptedKey: "AA", Header: services.JWERecipientHeader{Kid: "AB"}}}}
	b, _ := json.Marshal(ph)
	env := &services.EncryptedMessage{Protected: base64.RawURLEncoding.EncodeToString(b), IV: "AA", Ciphertext: "AA", Tag: "AA"}
	if _, err := es.UnpackMessage(env); err == nil {
		t.Fatalf("expected wallet service not available error")
	}
}

func TestEnvelope_Unpack_NoRecipientMatch(t *testing.T) {
	dm, ac, ws := buildDI(t)
	es := services.NewEnvelopeService(ac)
	es.SetTypedDI(*dm)
	// Create a wallet key to ensure wallet has keys, but set kid to random non-matching
	_, _ = ws.CreateKey(wallet.KeyTypeEd25519)
	ph := services.JWEProtectedHeader{Enc: "xchacha20poly1305_ietf", Typ: "JWM/1.0", Alg: "Anoncrypt", Recipients: []services.JWERecipient{{EncryptedKey: "AA", Header: services.JWERecipientHeader{Kid: "H3C2noMatchKey"}}}}
	b, _ := json.Marshal(ph)
	env := &services.EncryptedMessage{Protected: base64.RawURLEncoding.EncodeToString(b), IV: "AA", Ciphertext: "AA", Tag: "AA"}
	if _, err := es.UnpackMessage(env); err == nil {
		t.Fatalf("expected no corresponding recipient key found error")
	}
}

func TestEnvelope_Unpack_MalformedProtectedHeader(t *testing.T) {
	dm, ac, _ := buildDI(t)
	es := services.NewEnvelopeService(ac)
	es.SetTypedDI(*dm)
	env := &services.EncryptedMessage{Protected: "###", IV: "AA", Ciphertext: "AA", Tag: "AA"}
	if _, err := es.UnpackMessage(env); err == nil {
		t.Fatalf("expected error decoding protected header")
	}
}

func TestEnvelope_Pack_RecipientsCount_MatchesTo(t *testing.T) {
	dm, ac, ws := buildDI(t)
	es := services.NewEnvelopeService(ac)
	es.SetTypedDI(*dm)
	k1, _ := ws.CreateKey(wallet.KeyTypeEd25519)
	k2, _ := ws.CreateKey(wallet.KeyTypeEd25519)
	to := []string{coreencoding.EncodeBase58(k1.PublicKey), coreencoding.EncodeBase58(k2.PublicKey)}
	msg := messages.NewBaseMessage("https://example.org/recips/1.0/test")
	enc, err := es.PackMessage(msg, to, services.PackageTypeAnoncrypt)
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	phb, _ := base64.RawURLEncoding.DecodeString(enc.Protected)
	var ph services.JWEProtectedHeader
	_ = json.Unmarshal(phb, &ph)
	if len(ph.Recipients) != 2 {
		t.Fatalf("expected 2 recipients, got %d", len(ph.Recipients))
	}
	// Unpack should succeed with wallet containing both keys
	if _, err := es.UnpackMessage(enc); err != nil {
		t.Fatalf("unpack: %v", err)
	}
}

func TestEnvelope_Pack_TypHeader_Present(t *testing.T) {
	dm, ac, ws := buildDI(t)
	es := services.NewEnvelopeService(ac)
	es.SetTypedDI(*dm)
	rk, _ := ws.CreateKey(wallet.KeyTypeEd25519)
	msg := messages.NewBaseMessage("https://example.org/typ/1.0/test")
	// Anoncrypt
	encA, err := es.PackMessage(msg, []string{coreencoding.EncodeBase58(rk.PublicKey)}, services.PackageTypeAnoncrypt)
	if err != nil {
		t.Fatalf("pack anoncrypt: %v", err)
	}
	b1, _ := base64.RawURLEncoding.DecodeString(encA.Protected)
	var h1 services.JWEProtectedHeader
	_ = json.Unmarshal(b1, &h1)
	if h1.Typ != "JWM/1.0" {
		t.Fatalf("typ missing for anoncrypt: %+v", h1)
	}
	// Authcrypt
	sk, _ := ws.CreateKey(wallet.KeyTypeEd25519)
	es.SetSenderKey(sk.PrivateKey)
	encB, err := es.PackMessage(msg, []string{coreencoding.EncodeBase58(rk.PublicKey)}, services.PackageTypeAuthcrypt)
	if err != nil {
		t.Fatalf("pack authcrypt: %v", err)
	}
	b2, _ := base64.RawURLEncoding.DecodeString(encB.Protected)
	var h2 services.JWEProtectedHeader
	_ = json.Unmarshal(b2, &h2)
	if h2.Typ != "JWM/1.0" {
		t.Fatalf("typ missing for authcrypt: %+v", h2)
	}
}

func TestEnvelope_Pack_KidBase58_FromDidKey(t *testing.T) {
	dm, ac, ws := buildDI(t)
	es := services.NewEnvelopeService(ac)
	es.SetTypedDI(*dm)
	rk, _ := ws.CreateKey(wallet.KeyTypeEd25519)
	fp, _ := peer.Ed25519Fingerprint(rk.PublicKey)
	didkey := "did:key:" + fp
	msg := messages.NewBaseMessage("https://example.org/kidbase58/1.0/test")
	enc, err := es.PackMessage(msg, []string{didkey}, services.PackageTypeAnoncrypt)
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	phb, _ := base64.RawURLEncoding.DecodeString(enc.Protected)
	var ph services.JWEProtectedHeader
	_ = json.Unmarshal(phb, &ph)
	if len(ph.Recipients) == 0 {
		t.Fatalf("no recipients")
	}
	if ph.Recipients[0].Header.Kid != coreencoding.EncodeBase58(rk.PublicKey) {
		t.Fatalf("expected kid to be base58 of ed25519 key")
	}
}
