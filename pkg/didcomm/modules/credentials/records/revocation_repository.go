package records

import (
	"context"
	"fmt"
	
	agentcontext "github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/core/storage"
)

// RevocationRegistryRepository handles revocation registry storage
type RevocationRegistryRepository interface {
	// Public registry methods
	SavePublic(ctx *agentcontext.AgentContext, record *RevocationRegistryDefinitionRecord) error
	FindPublicByRegistryId(ctx *agentcontext.AgentContext, registryId string) (*RevocationRegistryDefinitionRecord, error)
	FindAllPublicByCredDefId(ctx *agentcontext.AgentContext, credDefId string) ([]*RevocationRegistryDefinitionRecord, error)
	
	// Private registry methods
	SavePrivate(ctx *agentcontext.AgentContext, record *RevocationRegistryDefinitionPrivateRecord) error
	FindPrivateByRegistryId(ctx *agentcontext.AgentContext, registryId string) (*RevocationRegistryDefinitionPrivateRecord, error)
	FindActivePrivateByCredDefId(ctx *agentcontext.AgentContext, credDefId string) (*RevocationRegistryDefinitionPrivateRecord, error)
	UpdatePrivate(ctx *agentcontext.AgentContext, record *RevocationRegistryDefinitionPrivateRecord) error
}

// AskarRevocationRepository implements RevocationRegistryRepository using Askar storage
type AskarRevocationRepository struct {
	storage interface {
		Save(ctx context.Context, record storage.Record) error
		Update(ctx context.Context, record storage.Record) error
		FindSingleByQuery(ctx context.Context, recordClass string, query storage.Query) (storage.Record, error)
		FindByQuery(ctx context.Context, recordClass string, query storage.Query) ([]storage.Record, error)
	}
}

// NewAskarRevocationRepository creates a new revocation repository
func NewAskarRevocationRepository(storage interface {
	Save(ctx context.Context, record storage.Record) error
	Update(ctx context.Context, record storage.Record) error
	FindSingleByQuery(ctx context.Context, recordClass string, query storage.Query) (storage.Record, error)
	FindByQuery(ctx context.Context, recordClass string, query storage.Query) ([]storage.Record, error)
}) *AskarRevocationRepository {
	return &AskarRevocationRepository{
		storage: storage,
	}
}

// SavePublic saves a public revocation registry definition
func (r *AskarRevocationRepository) SavePublic(ctx *agentcontext.AgentContext, record *RevocationRegistryDefinitionRecord) error {
	if record.BaseRecord.Type == "" {
		record.BaseRecord.Type = "RevocationRegistryDefinitionRecord"
	}
	
	// Set tags for querying
	record.BaseRecord.SetTag("revocationRegistryDefinitionId", record.RevocationRegistryDefinitionId)
	record.BaseRecord.SetTag("credentialDefinitionId", record.CredentialDefinitionId)
	
	return r.storage.Save(ctx.Context, record)
}

// FindPublicByRegistryId finds a public registry by ID
func (r *AskarRevocationRepository) FindPublicByRegistryId(ctx *agentcontext.AgentContext, registryId string) (*RevocationRegistryDefinitionRecord, error) {
	query := storage.NewQuery().WithTag("revocationRegistryDefinitionId", registryId)
	
	record, err := r.storage.FindSingleByQuery(ctx.Context, "RevocationRegistryDefinitionRecord", *query)
	if err != nil {
		return nil, err
	}
	
	if regRecord, ok := record.(*RevocationRegistryDefinitionRecord); ok {
		return regRecord, nil
	}
	
	// Fallback deserialization
	data, err := record.ToJSON()
	if err != nil {
		return nil, fmt.Errorf("failed to get record data: %w", err)
	}
	
	var regRecord RevocationRegistryDefinitionRecord
	if err := regRecord.FromJSON(data); err != nil {
		return nil, fmt.Errorf("failed to deserialize record: %w", err)
	}
	
	return &regRecord, nil
}

// FindAllPublicByCredDefId finds all public registries for a credential definition
func (r *AskarRevocationRepository) FindAllPublicByCredDefId(ctx *agentcontext.AgentContext, credDefId string) ([]*RevocationRegistryDefinitionRecord, error) {
	query := storage.NewQuery().WithTag("credentialDefinitionId", credDefId)
	
	records, err := r.storage.FindByQuery(ctx.Context, "RevocationRegistryDefinitionRecord", *query)
	if err != nil {
		return nil, err
	}
	
	var result []*RevocationRegistryDefinitionRecord
	for _, record := range records {
		if regRecord, ok := record.(*RevocationRegistryDefinitionRecord); ok {
			result = append(result, regRecord)
		} else {
			// Fallback deserialization
			data, err := record.ToJSON()
			if err != nil {
				continue
			}
			
			var regRecord RevocationRegistryDefinitionRecord
			if err := regRecord.FromJSON(data); err != nil {
				continue
			}
			result = append(result, &regRecord)
		}
	}
	
	return result, nil
}

// SavePrivate saves a private revocation registry definition
func (r *AskarRevocationRepository) SavePrivate(ctx *agentcontext.AgentContext, record *RevocationRegistryDefinitionPrivateRecord) error {
	if record.BaseRecord.Type == "" {
		record.BaseRecord.Type = "RevocationRegistryDefinitionPrivateRecord"
	}
	
	// Set tags for querying
	record.BaseRecord.SetTag("revocationRegistryDefinitionId", record.RevocationRegistryDefinitionId)
	record.BaseRecord.SetTag("credentialDefinitionId", record.CredentialDefinitionId)
	record.BaseRecord.SetTag("state", string(record.State))
	
	return r.storage.Save(ctx.Context, record)
}

// FindPrivateByRegistryId finds a private registry by ID
func (r *AskarRevocationRepository) FindPrivateByRegistryId(ctx *agentcontext.AgentContext, registryId string) (*RevocationRegistryDefinitionPrivateRecord, error) {
	query := storage.NewQuery().WithTag("revocationRegistryDefinitionId", registryId)
	
	record, err := r.storage.FindSingleByQuery(ctx.Context, "RevocationRegistryDefinitionPrivateRecord", *query)
	if err != nil {
		return nil, err
	}
	
	if regRecord, ok := record.(*RevocationRegistryDefinitionPrivateRecord); ok {
		return regRecord, nil
	}
	
	// Fallback deserialization
	data, err := record.ToJSON()
	if err != nil {
		return nil, fmt.Errorf("failed to get record data: %w", err)
	}
	
	var regRecord RevocationRegistryDefinitionPrivateRecord
	if err := regRecord.FromJSON(data); err != nil {
		return nil, fmt.Errorf("failed to deserialize record: %w", err)
	}
	
	return &regRecord, nil
}

// FindActivePrivateByCredDefId finds an active private registry for a credential definition
func (r *AskarRevocationRepository) FindActivePrivateByCredDefId(ctx *agentcontext.AgentContext, credDefId string) (*RevocationRegistryDefinitionPrivateRecord, error) {
	query := storage.NewQuery().
		WithTag("credentialDefinitionId", credDefId).
		WithTag("state", string(RevocationStateActive))
	
	record, err := r.storage.FindSingleByQuery(ctx.Context, "RevocationRegistryDefinitionPrivateRecord", *query)
	if err != nil {
		return nil, err
	}
	
	if regRecord, ok := record.(*RevocationRegistryDefinitionPrivateRecord); ok {
		return regRecord, nil
	}
	
	// Fallback deserialization
	data, err := record.ToJSON()
	if err != nil {
		return nil, fmt.Errorf("failed to get record data: %w", err)
	}
	
	var regRecord RevocationRegistryDefinitionPrivateRecord
	if err := regRecord.FromJSON(data); err != nil {
		return nil, fmt.Errorf("failed to deserialize record: %w", err)
	}
	
	return &regRecord, nil
}

// UpdatePrivate updates a private registry record
func (r *AskarRevocationRepository) UpdatePrivate(ctx *agentcontext.AgentContext, record *RevocationRegistryDefinitionPrivateRecord) error {
	// Update tags
	record.BaseRecord.SetTag("state", string(record.State))
	
	return r.storage.Update(ctx.Context, record)
}