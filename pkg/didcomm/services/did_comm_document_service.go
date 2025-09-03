package services

import (
	"fmt"
	"strings"

	corectx "github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/core/di"
	"github.com/ajna-inc/essi/pkg/core/encoding"
	dids "github.com/ajna-inc/essi/pkg/dids"
)

type DidCommDocumentService struct {
	resolver *dids.DidResolverService
}

func NewDidCommDocumentService() *DidCommDocumentService {
	return &DidCommDocumentService{resolver: nil}
}

// EnsureResolver ensures a resolver is available from DI (no implicit construction)
func (s *DidCommDocumentService) EnsureResolver(dm di.DependencyManager) *dids.DidResolverService {
	if s.resolver != nil {
		return s.resolver
	}
	if dep, err := dm.Resolve(di.TokenDidResolverService); err == nil {
		if r, ok := dep.(*dids.DidResolverService); ok && r != nil {
			s.resolver = r
			return s.resolver
		}
	}
	return nil
}

// ResolveService extracts endpoint and recipient keys from a DID.
func (s *DidCommDocumentService) ResolveService(ctx *corectx.AgentContext, dm di.DependencyManager, did string) (endpoint string, recipientKeys []string, routingKeys []string, err error) {
	if did == "" {
		return "", nil, nil, fmt.Errorf("did is empty")
	}
	resolver := s.EnsureResolver(dm)
	if resolver == nil {
		return "", nil, nil, fmt.Errorf("DidResolverService not available from DI")
	}
	res, rerr := resolver.Resolve(ctx, did, nil)
	if rerr != nil || res == nil || res.DidDocument == nil {
		return "", nil, nil, fmt.Errorf("failed to resolve did: %v", rerr)
	}
	doc := res.DidDocument
	for _, s := range doc.Service {
		if s == nil {
			continue
		}
		if s.Type != dids.ServiceTypeDIDComm && s.Type != dids.ServiceTypeDIDCommMessaging && s.Type != dids.ServiceTypeIndyAgent {
			continue
		}
		ep := ""
		if se, ok := s.ServiceEndpoint.(string); ok {
			ep = se
		}
		if ep == "" || len(s.RecipientKeys) == 0 {
			continue
		}
		keys := []string{}
		for _, kid := range s.RecipientKeys {
			if vm, derr := doc.DereferenceVerificationMethod(kid); derr == nil && vm != nil {
				if vm.PublicKeyBase58 != "" {
					keys = append(keys, vm.PublicKeyBase58)
					continue
				}
				if vm.PublicKeyMultibase != "" {
					if b58 := multibaseToBase58(vm.PublicKeyMultibase); b58 != "" {
						keys = append(keys, b58)
						continue
					}
				}
			}
			if !strings.HasPrefix(kid, "#") && !strings.Contains(kid, ":") {
				keys = append(keys, kid)
			}
		}
		if len(keys) > 0 {
			return ep, keys, s.RoutingKeys, nil
		}
	}
	return "", nil, nil, fmt.Errorf("didcomm service not found in did document")
}

// multibaseToBase58 converts multibase 'z' ed25519 key to base58 raw ed25519
func multibaseToBase58(mb string) string {
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
