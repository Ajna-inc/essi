package peer

import (
	"crypto/ed25519"
	"fmt"

	"github.com/ajna-inc/essi/pkg/core/encoding"
)

// Ed25519Fingerprint returns the multibase base58btc encoded fingerprint for an Ed25519 public key.
func Ed25519Fingerprint(publicKey ed25519.PublicKey) (string, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return "", fmt.Errorf("invalid Ed25519 public key length")
	}

	prefixed := append([]byte{0xed, 0x01}, publicKey...)
	return "z" + encoding.EncodeBase58(prefixed), nil
}
