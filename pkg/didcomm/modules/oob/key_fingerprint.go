package oob

import (
    "strings"
	"github.com/ajna-inc/essi/pkg/core/encoding"
)

// FingerprintFromKeyString derives a multibase (z...) fingerprint from a key string.
// Supports did:key (with or without fragment) and raw base58 Ed25519 public keys (32 bytes).
func FingerprintFromKeyString(key string) string {
    if key == "" { return "" }
    if strings.HasPrefix(key, "did:key:") {
        // If a fragment is present, it typically contains the fingerprint
        if idx := strings.Index(key, "#"); idx != -1 {
            frag := key[idx+1:]
            if frag != "" { return frag }
        }
        // Otherwise, take the multibase part after did:key:
        val := strings.TrimPrefix(key, "did:key:")
        // Strip any lingering fragment just in case
        if idx := strings.Index(val, "#"); idx != -1 { val = val[:idx] }
        return val
    }
    // Try to interpret as base58 raw Ed25519 key (32 bytes)
    if raw, err := encoding.DecodeBase58(key); err == nil && len(raw) == 32 {
        return ed25519Fingerprint(raw)
    }
    return key
}

// ed25519Fingerprint computes multibase fingerprint z + base58(0xed01 || rawKey)
func ed25519Fingerprint(raw []byte) string {
    // multicodec prefix for Ed25519 public key is 0xed 0x01
    prefixed := append([]byte{0xed, 0x01}, raw...)
    return "z" + encoding.EncodeBase58(prefixed)
}

