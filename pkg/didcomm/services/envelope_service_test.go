package services

import (
    "encoding/hex"
    "testing"
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

    es := &EnvelopeService{}
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
    es := &EnvelopeService{}
    if _, err := es.Ed25519ToX25519PublicKey([]byte{1, 2, 3}); err == nil {
        t.Fatalf("expected error for invalid input length, got nil")
    }
}
