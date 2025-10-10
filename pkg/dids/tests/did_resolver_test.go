package dids_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/ajna-inc/essi/pkg/core/context"
	coreencoding "github.com/ajna-inc/essi/pkg/core/encoding"
	dids "github.com/ajna-inc/essi/pkg/dids"
	keyresolver "github.com/ajna-inc/essi/pkg/dids/methods/key"
)

func TestDidKeyResolver_Resolve_Ed25519(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	did, err := keyresolver.CreateDidKeyFromEd25519PublicKey(pub)
	if err != nil {
		t.Fatalf("CreateDidKeyFromEd25519PublicKey: %v", err)
	}

	svc := dids.NewDidResolverService()
	svc.RegisterResolver(keyresolver.NewDidKeyResolver())
	ctx := &context.AgentContext{}
	res, err := svc.Resolve(ctx, did, nil)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.DidDocument == nil {
		t.Fatalf("nil DID document")
	}
	doc := res.DidDocument
	if len(doc.VerificationMethod) == 0 {
		t.Fatalf("no verification methods in doc")
	}
	// Ed25519 2020 multibase
	vm := doc.VerificationMethod[0]
	if vm.Type != dids.VerificationMethodTypeEd25519VerificationKey2020 {
		t.Fatalf("unexpected vm type: %s", vm.Type)
	}
	if !strings.HasPrefix(vm.PublicKeyMultibase, "z") {
		t.Fatalf("multibase must start with 'z'")
	}
	// multibase contents equals base58(pub)
	if got := vm.PublicKeyMultibase[1:]; got != coreencoding.EncodeBase58(pub) {
		t.Fatalf("multibase content mismatch")
	}
}

func TestDidKeyResolver_Resolve_X25519(t *testing.T) {
	// 32-byte random key (X25519 pubkey size). For test we just use random bytes.
	xpub := make([]byte, 32)
	if _, err := rand.Read(xpub); err != nil {
		t.Fatalf("rand: %v", err)
	}
	did, err := keyresolver.CreateDidKeyFromX25519PublicKey(xpub)
	if err != nil {
		t.Fatalf("CreateDidKeyFromX25519PublicKey: %v", err)
	}

	svc := dids.NewDidResolverService()
	svc.RegisterResolver(keyresolver.NewDidKeyResolver())
	res, err := svc.Resolve(&context.AgentContext{}, did, nil)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.DidDocument == nil {
		t.Fatalf("nil DID document")
	}
	vm := res.DidDocument.VerificationMethod[0]
	if vm.Type != dids.VerificationMethodTypeX25519KeyAgreementKey2019 {
		t.Fatalf("unexpected vm type: %s", vm.Type)
	}
	if vm.PublicKeyMultibase == "" || !strings.HasPrefix(vm.PublicKeyMultibase, "z") {
		t.Fatalf("expected multibase z...")
	}
}

func TestDidKeyResolver_InvalidEncoding(t *testing.T) {
	svc := dids.NewDidResolverService()
	svc.RegisterResolver(keyresolver.NewDidKeyResolver())
	res, _ := svc.Resolve(&context.AgentContext{}, "did:key:x123", nil)
	if res == nil || res.DidResolutionMetadata == nil || res.DidResolutionMetadata.Error == "" {
		t.Fatalf("expected resolution error for invalid did:key")
	}
}
