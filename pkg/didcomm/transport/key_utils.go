package transport

import (
	"strings"

	"github.com/ajna-inc/essi/pkg/core/encoding"
)

// didKeyToBase58 converts a did:key fingerprint to a base58-encoded Ed25519 public key.
// Supports inputs like did:key:z... and z... (multibase) and removes the multicodec ed25519 prefix when present.
func DidKeyToBase58(kid string) string {
	if kid == "" {
		return ""
	}
	// Strip did:key: prefix
	if strings.HasPrefix(kid, "did:key:") {
		kid = strings.TrimPrefix(kid, "did:key:")
	}
	// Must be multibase z
	if !strings.HasPrefix(kid, "z") {
		return ""
	}
	enc := kid[1:]
	raw, err := encoding.DecodeBase58(enc)
	if err != nil || len(raw) < 32 {
		return ""
	}
	// Remove multicodec 0xed 0x01 prefix if present
	if len(raw) >= 34 && raw[0] == 0xed && raw[1] == 0x01 {
		raw = raw[2:]
	} else if raw[0] == 0xed {
		raw = raw[1:]
	}
	if len(raw) != 32 {
		return ""
	}
	return encoding.EncodeBase58(raw)
}

// multibaseToBase58 converts multibase 'z' ed25519 key to base58 raw ed25519
func MultibaseToBase58(mb string) string {
	if mb == "" {
		return ""
	}
	if strings.HasPrefix(mb, "z") {
		mb = mb[1:]
	}
	rawWithCodec, err := encoding.DecodeBase58(mb)
	if err != nil || len(rawWithCodec) < 2 {
		return ""
	}
	if rawWithCodec[0] == 0xed && len(rawWithCodec) >= 34 && rawWithCodec[1] == 0x01 {
		return encoding.EncodeBase58(rawWithCodec[2:])
	}
	if rawWithCodec[0] == 0xed && len(rawWithCodec) >= 33 {
		return encoding.EncodeBase58(rawWithCodec[1:])
	}
	return ""
}
