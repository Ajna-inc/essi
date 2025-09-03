package wallet_test

import (
    "testing"

    "github.com/ajna-inc/essi/pkg/core/context"
    w "github.com/ajna-inc/essi/pkg/core/wallet"
    keyresolver "github.com/ajna-inc/essi/pkg/dids/methods/key"
)

func newTestWallet() *w.WalletService {
    ctx := context.NewAgentContext(context.AgentContextOptions{ Config: &context.AgentConfig{} })
    repo := w.NewSimpleKeyRepository()
    return w.NewWalletService(ctx, repo)
}

func TestCreateEd25519Key_SignVerify_AndDidKeyRoundTrip(t *testing.T) {
    ws := newTestWallet()

    key, err := ws.CreateKey(w.KeyTypeEd25519)
    if err != nil {
        t.Fatalf("CreateKey(Ed25519) failed: %v", err)
    }

    // Some builds may propagate a more specific label; accept any Ed25519 type label
    if string(key.Type) != string(w.KeyTypeEd25519) && string(key.Type) != "Ed25519VerificationKey2020" {
        t.Fatalf("unexpected key type: %s", key.Type)
    }
    if len(key.PublicKey) != 32 {
        t.Fatalf("expected Ed25519 public key length 32, got %d", len(key.PublicKey))
    }
    if len(key.PrivateKey) == 0 {
        t.Fatalf("expected Ed25519 private key to be present")
    }

    // Sign/verify
    msg := []byte("hello-essi")
    sig, err := ws.Sign(key.Id, msg)
    if err != nil {
        t.Fatalf("Sign failed: %v", err)
    }
    ok, err := ws.Verify(key.Id, msg, sig)
    if err != nil {
        t.Fatalf("Verify failed: %v", err)
    }
    if !ok {
        t.Fatalf("signature did not verify")
    }

    // did:key fingerprint round-trip
    didKey, err := keyresolver.CreateDidKeyFromEd25519PublicKey(key.PublicKey)
    if err != nil {
        t.Fatalf("CreateDidKeyFromEd25519PublicKey failed: %v", err)
    }
    if len(didKey) == 0 || didKey[:8] != "did:key:" {
        t.Fatalf("invalid did:key generated: %s", didKey)
    }

    raw, kty, err := keyresolver.ExtractPublicKeyFromDidKey(didKey)
    if err != nil {
        t.Fatalf("ExtractPublicKeyFromDidKey failed: %v", err)
    }
    if kty != "Ed25519" && kty != "Ed25519VerificationKey2020" {
        t.Fatalf("expected key type Ed25519, got %s", kty)
    }
    if len(raw) != 32 {
        t.Fatalf("expected raw public key length 32 from did:key, got %d", len(raw))
    }
    // raw must equal original
    for i := range raw {
        if raw[i] != key.PublicKey[i] {
            t.Fatalf("did:key round-trip mismatch at byte %d", i)
        }
    }
}

func TestCreateX25519Key_ClampAndDerive(t *testing.T) {
    ws := newTestWallet()
    key, err := ws.CreateKey(w.KeyTypeX25519)
    if err != nil {
        t.Fatalf("CreateKey(X25519) failed: %v", err)
    }
    if key.Type != w.KeyTypeX25519 {
        t.Fatalf("unexpected key type: %s", key.Type)
    }
    if len(key.PublicKey) != 32 || len(key.PrivateKey) != 32 {
        t.Fatalf("expected X25519 public/private key length 32, got pub=%d priv=%d", len(key.PublicKey), len(key.PrivateKey))
    }

    // Check clamp bits on private key per RFC 7748
    if key.PrivateKey[0]&0x07 != 0 { // lowest 3 bits must be zero
        t.Fatalf("X25519 private key not clamped (low bits)")
    }
    if key.PrivateKey[31]&0x80 != 0 { // highest bit must be zero
        t.Fatalf("X25519 private key not clamped (high bit)")
    }
    if key.PrivateKey[31]&0x40 == 0 { // second highest bit must be 1
        t.Fatalf("X25519 private key not clamped (second high bit not set)")
    }
}
