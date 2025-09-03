package api

import (
	"fmt"

	"github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/dids"
	"github.com/ajna-inc/essi/pkg/dids/domain"
	"github.com/ajna-inc/essi/pkg/dids/repository"
)

// DidsApi provides the main API for DID operations
type DidsApi struct {
	resolver   *dids.DidResolverService
	registrar  *dids.DidRegistrarService
	repository repository.DidRepository
	ctx        *context.AgentContext
}

// NewDidsApi creates a new DidsApi instance
func NewDidsApi(
	resolver *dids.DidResolverService,
	registrar *dids.DidRegistrarService,
	repository repository.DidRepository,
	ctx *context.AgentContext,
) *DidsApi {
	return &DidsApi{
		resolver:   resolver,
		registrar:  registrar,
		repository: repository,
		ctx:        ctx,
	}
}

// Create creates a new DID and stores it in the repository
func (a *DidsApi) Create(opts *dids.DidCreateOptions) (*dids.DidCreateResult, error) {
	result, err := a.registrar.Create(a.ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create DID: %w", err)
	}

	if a.repository != nil && result != nil {
		var keys []domain.DidDocumentKey
		for i, keyId := range result.Keys {
			keys = append(keys, domain.DidDocumentKey{
				KmsKeyId:                 keyId,
				DidDocumentRelativeKeyId: fmt.Sprintf("#key-%d", i),
			})
		}

		_, err = a.repository.StoreCreatedDid(
			a.ctx,
			result.Did,
			result.DidDocument,
			keys,
			nil,
		)
		if err != nil {
			fmt.Printf("Warning: failed to store created DID in repository: %v\n", err)
		}
	}

	return result, nil
}

// Resolve resolves a DID to its document
func (a *DidsApi) Resolve(did string) (*dids.DidResolutionResult, error) {
	if a.repository != nil {
		record, _ := a.repository.FindCreatedDid(a.ctx, did)
		if record == nil {
			record, _ = a.repository.FindReceivedDid(a.ctx, did)
		}

		if record != nil && record.DidDocument != nil {
			createdAt := record.CreatedAt
			updatedAt := record.UpdatedAt
			return &dids.DidResolutionResult{
				DidDocument: record.DidDocument,
				DidDocumentMetadata: &dids.DidDocumentMetadata{
					Created: &createdAt,
					Updated: &updatedAt,
				},
				DidResolutionMetadata: &dids.DidResolutionMetadata{},
			}, nil
		}
	}

	return a.resolver.Resolve(a.ctx, did, nil)
}

// ResolveDidDocument is a convenience method that returns just the document
func (a *DidsApi) ResolveDidDocument(did string) (*dids.DidDocument, error) {
	result, err := a.Resolve(did)
	if err != nil {
		return nil, err
	}
	if result.DidDocument == nil {
		return nil, fmt.Errorf("DID document not found for %s", did)
	}
	return result.DidDocument, nil
}

// Import imports an existing DID into the repository
func (a *DidsApi) Import(did string, didDocument *dids.DidDocument, keys []domain.DidDocumentKey, overwrite bool) error {
	if a.repository == nil {
		return fmt.Errorf("repository not available")
	}

	existing, _ := a.repository.FindCreatedDid(a.ctx, did)
	if existing != nil && !overwrite {
		return fmt.Errorf("DID %s already exists. Set overwrite=true to update", did)
	}

	if didDocument == nil {
		resolved, err := a.ResolveDidDocument(did)
		if err != nil {
			return fmt.Errorf("failed to resolve DID document: %w", err)
		}
		didDocument = resolved
	}

	if didDocument.Id != did {
		return fmt.Errorf("DID document ID %s does not match DID %s", didDocument.Id, did)
	}

	if existing != nil {
		existing.DidDocument = didDocument
		existing.Keys = keys
		return a.repository.Update(a.ctx, existing)
	}

	_, err := a.repository.StoreCreatedDid(a.ctx, did, didDocument, keys, nil)
	return err
}

// GetCreatedDids returns all DIDs created by this agent
func (a *DidsApi) GetCreatedDids(method string) ([]*repository.DidRecord, error) {
	if a.repository == nil {
		return nil, fmt.Errorf("repository not available")
	}

	return a.repository.GetCreatedDids(a.ctx, repository.GetDidsOptions{
		Method: method,
	})
}

// GetReceivedDids returns all DIDs received from other agents
func (a *DidsApi) GetReceivedDids(method string) ([]*repository.DidRecord, error) {
	if a.repository == nil {
		return nil, fmt.Errorf("repository not available")
	}

	return a.repository.GetReceivedDids(a.ctx, repository.GetDidsOptions{
		Method: method,
	})
}

// GetAllDids returns all stored DIDs
func (a *DidsApi) GetAllDids() ([]*repository.DidRecord, error) {
	if a.repository == nil {
		return nil, fmt.Errorf("repository not available")
	}

	return a.repository.GetAll(a.ctx)
}

// StoreReceivedDid stores a DID received from another agent
func (a *DidsApi) StoreReceivedDid(did string, didDocument *dids.DidDocument) error {
	if a.repository == nil {
		return fmt.Errorf("repository not available")
	}

	if didDocument == nil {
		resolved, err := a.ResolveDidDocument(did)
		if err != nil {
			return fmt.Errorf("failed to resolve DID document: %w", err)
		}
		didDocument = resolved
	}

	_, err := a.repository.StoreReceivedDid(a.ctx, did, didDocument, nil)
	return err
}

// FindByRecipientKey finds DIDs associated with a recipient key
func (a *DidsApi) FindByRecipientKey(keyFingerprint string, role domain.DidDocumentRole) (*repository.DidRecord, error) {
	if a.repository == nil {
		return nil, fmt.Errorf("repository not available")
	}

	return a.repository.FindByRecipientKey(a.ctx, keyFingerprint, role)
}