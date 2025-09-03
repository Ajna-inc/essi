package peer

import (
	"fmt"

	"github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/core/di"
	"github.com/ajna-inc/essi/pkg/dids"
	"github.com/ajna-inc/essi/pkg/dids/domain"
	"github.com/ajna-inc/essi/pkg/dids/repository"
)

// PeerDidRegistrar handles did:peer creation and storage
type PeerDidRegistrar struct{}

// NewPeerDidRegistrar creates a new peer DID registrar
func NewPeerDidRegistrar() *PeerDidRegistrar { return &PeerDidRegistrar{} }

// Method returns the supported DID method
func (r *PeerDidRegistrar) Method() string { return "peer" }

// Create creates a new peer DID and stores it in the repository
func (r *PeerDidRegistrar) Create(agentContext *context.AgentContext, opts *dids.DidCreateOptions) (*dids.DidCreateResult, error) {
	if opts == nil {
		return nil, fmt.Errorf("options is nil")
	}

	// Get the DID repository from DI
	var didRepo repository.DidRepository
	if agentContext.DependencyManager != nil {
		if dm, ok := agentContext.DependencyManager.(di.DependencyManager); ok {
			if didRepoAny, err := dm.Resolve(di.TokenDidRepository); err == nil {
				didRepo, _ = didRepoAny.(repository.DidRepository)
			}
		}
	}
	if didRepo == nil {
		return nil, fmt.Errorf("failed to resolve DID repository from DI")
	}

	// Extract options
	var did string
	var didDocument *dids.DidDocument
	var keys []domain.DidDocumentKey

	if opts.Options != nil {
		// Check if we have a pre-created DID
		if d, ok := opts.Options["did"].(string); ok {
			did = d
		}
		// Check for DID document
		if doc, ok := opts.Options["didDocument"].(*dids.DidDocument); ok {
			didDocument = doc
		}
		// Check for keys
		if k, ok := opts.Options["keys"].([]domain.DidDocumentKey); ok {
			keys = k
		}
	}

	if did == "" {
		return nil, fmt.Errorf("did:peer requires a pre-created DID in options")
	}

	// If no document provided, create a minimal one
	if didDocument == nil {
		didDocument = &dids.DidDocument{Id: did, Controller: []string{did}}
	}

	// Store the DID in the repository
	_, err := didRepo.StoreCreatedDid(agentContext, did, didDocument, keys, map[string]string{"method": "peer"})
	if err != nil {
		return nil, fmt.Errorf("failed to store peer DID: %w", err)
	}

	return &dids.DidCreateResult{Did: did, DidDocument: didDocument}, nil
}
