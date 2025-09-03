package repository

import (
	"github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/dids"
	"github.com/ajna-inc/essi/pkg/dids/domain"
)

// GetDidsOptions provides filtering options for querying DIDs
type GetDidsOptions struct {
	Method string // Filter by DID method (e.g., "key", "peer", "kanon")
	Did    string // Filter by specific DID
}

// DidRepository defines the interface for DID storage operations
type DidRepository interface {
	// Store operations
	StoreCreatedDid(ctx *context.AgentContext, did string, didDocument *dids.DidDocument, keys []domain.DidDocumentKey, tags map[string]string) (*DidRecord, error)
	StoreReceivedDid(ctx *context.AgentContext, did string, didDocument *dids.DidDocument, tags map[string]string) (*DidRecord, error)
	
	// Find operations
	FindById(ctx *context.AgentContext, id string) (*DidRecord, error)
	FindCreatedDid(ctx *context.AgentContext, did string) (*DidRecord, error)
	FindReceivedDid(ctx *context.AgentContext, did string) (*DidRecord, error)
	FindByRecipientKey(ctx *context.AgentContext, keyFingerprint string, role domain.DidDocumentRole) (*DidRecord, error)
	FindAllByRecipientKey(ctx *context.AgentContext, keyFingerprint string) ([]*DidRecord, error)
	
	// Query operations
	GetCreatedDids(ctx *context.AgentContext, options GetDidsOptions) ([]*DidRecord, error)
	GetReceivedDids(ctx *context.AgentContext, options GetDidsOptions) ([]*DidRecord, error)
	GetAll(ctx *context.AgentContext) ([]*DidRecord, error)
	
	// Update and delete operations
	Update(ctx *context.AgentContext, record *DidRecord) error
	Delete(ctx *context.AgentContext, id string) error
}