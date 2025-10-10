package transport_test

import (
	"testing"

	"crypto/ed25519"
	"crypto/rand"
	coreencoding "github.com/ajna-inc/essi/pkg/core/encoding"
	transport "github.com/ajna-inc/essi/pkg/didcomm/transport"
	peer "github.com/ajna-inc/essi/pkg/dids/methods/peer"
)

func TestDidKeyToBase58_And_MultibaseToBase58(t *testing.T) {
	// Generate a fresh ed25519 key and compute fingerprint
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 key: %v", err)
	}
	fp, err := peer.Ed25519Fingerprint(pub)
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	wantB58 := coreencoding.EncodeBase58(pub)

	// did:key form
	got := transport.DidKeyToBase58("did:key:" + fp)
	if got != wantB58 {
		t.Fatalf("did:key to base58 mismatch: got %s want %s", got, wantB58)
	}

	// multibase only form
	got2 := transport.MultibaseToBase58(fp)
	if got2 != wantB58 {
		t.Fatalf("multibase to base58 mismatch: got %s want %s", got2, wantB58)
	}
}

func TestDidKeyToBase58_WithFragment(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 key: %v", err)
	}
	fp, err := peer.Ed25519Fingerprint(pub)
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	did := "did:key:" + fp + "#" + fp
	want := coreencoding.EncodeBase58(pub)
	if got := transport.DidKeyToBase58(did); got != want {
		t.Fatalf("fragment to base58 mismatch: got %s want %s", got, want)
	}
}
