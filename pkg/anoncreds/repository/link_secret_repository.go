package repository

import (
	"context"
	"fmt"
	
	agentcontext "github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/core/storage"
)

// LinkSecretRepository handles link secret storage
type LinkSecretRepository interface {
	Save(ctx *agentcontext.AgentContext, record *LinkSecretRecord) error
	Update(ctx *agentcontext.AgentContext, record *LinkSecretRecord) error
	GetDefault(ctx *agentcontext.AgentContext) (*LinkSecretRecord, error)
	FindDefault(ctx *agentcontext.AgentContext) (*LinkSecretRecord, error)
	GetByLinkSecretId(ctx *agentcontext.AgentContext, linkSecretId string) (*LinkSecretRecord, error)
	FindByLinkSecretId(ctx *agentcontext.AgentContext, linkSecretId string) (*LinkSecretRecord, error)
	GetAll(ctx *agentcontext.AgentContext) ([]*LinkSecretRecord, error)
}

// AskarLinkSecretRepository implements LinkSecretRepository using Askar storage
type AskarLinkSecretRepository struct {
	storage interface {
		Save(ctx context.Context, record storage.Record) error
		Update(ctx context.Context, record storage.Record) error
		FindSingleByQuery(ctx context.Context, recordClass string, query storage.Query) (storage.Record, error)
		FindByQuery(ctx context.Context, recordClass string, query storage.Query) ([]storage.Record, error)
	}
}

// NewAskarLinkSecretRepository creates a new link secret repository
func NewAskarLinkSecretRepository(storage interface {
	Save(ctx context.Context, record storage.Record) error
	Update(ctx context.Context, record storage.Record) error
	FindSingleByQuery(ctx context.Context, recordClass string, query storage.Query) (storage.Record, error)
	FindByQuery(ctx context.Context, recordClass string, query storage.Query) ([]storage.Record, error)
}) *AskarLinkSecretRepository {
	return &AskarLinkSecretRepository{
		storage: storage,
	}
}

// Save saves a link secret record
func (r *AskarLinkSecretRepository) Save(ctx *agentcontext.AgentContext, record *LinkSecretRecord) error {
	if record.BaseRecord.Type == "" {
		record.BaseRecord.Type = "LinkSecretRecord"
	}
	
	// Set tags for querying
	record.BaseRecord.SetTag("linkSecretId", record.LinkSecretId)
	if record.IsDefault {
		record.BaseRecord.SetTag("isDefault", "true")
	}
	
	return r.storage.Save(ctx.Context, record)
}

// Update updates a link secret record
func (r *AskarLinkSecretRepository) Update(ctx *agentcontext.AgentContext, record *LinkSecretRecord) error {
	// Update tags
	if record.IsDefault {
		record.BaseRecord.SetTag("isDefault", "true")
	} else {
		record.BaseRecord.RemoveTag("isDefault")
	}
	
	return r.storage.Update(ctx.Context, record)
}

// GetDefault gets the default link secret (errors if not found)
func (r *AskarLinkSecretRepository) GetDefault(ctx *agentcontext.AgentContext) (*LinkSecretRecord, error) {
	query := storage.NewQuery().WithTag("isDefault", "true")
	
	record, err := r.storage.FindSingleByQuery(ctx.Context, "LinkSecretRecord", *query)
	if err != nil {
		return nil, fmt.Errorf("no default link secret found: %w", err)
	}
	
	return r.convertToLinkSecretRecord(record)
}

// FindDefault finds the default link secret (returns nil if not found)
func (r *AskarLinkSecretRepository) FindDefault(ctx *agentcontext.AgentContext) (*LinkSecretRecord, error) {
	query := storage.NewQuery().WithTag("isDefault", "true")
	
	record, err := r.storage.FindSingleByQuery(ctx.Context, "LinkSecretRecord", *query)
	if err != nil {
		// Return nil if not found (find methods don't error on not found)
		return nil, nil
	}
	
	return r.convertToLinkSecretRecord(record)
}

// GetByLinkSecretId gets a link secret by ID (errors if not found)
func (r *AskarLinkSecretRepository) GetByLinkSecretId(ctx *agentcontext.AgentContext, linkSecretId string) (*LinkSecretRecord, error) {
	query := storage.NewQuery().WithTag("linkSecretId", linkSecretId)
	
	record, err := r.storage.FindSingleByQuery(ctx.Context, "LinkSecretRecord", *query)
	if err != nil {
		return nil, fmt.Errorf("link secret %s not found: %w", linkSecretId, err)
	}
	
	return r.convertToLinkSecretRecord(record)
}

// FindByLinkSecretId finds a link secret by ID (returns nil if not found)
func (r *AskarLinkSecretRepository) FindByLinkSecretId(ctx *agentcontext.AgentContext, linkSecretId string) (*LinkSecretRecord, error) {
	query := storage.NewQuery().WithTag("linkSecretId", linkSecretId)
	
	record, err := r.storage.FindSingleByQuery(ctx.Context, "LinkSecretRecord", *query)
	if err != nil {
		// Return nil if not found (find methods don't error on not found)
		return nil, nil
	}
	
	return r.convertToLinkSecretRecord(record)
}

// GetAll gets all link secret records
func (r *AskarLinkSecretRepository) GetAll(ctx *agentcontext.AgentContext) ([]*LinkSecretRecord, error) {
	records, err := r.storage.FindByQuery(ctx.Context, "LinkSecretRecord", *storage.NewQuery())
	if err != nil {
		return nil, err
	}
	
	var result []*LinkSecretRecord
	for _, record := range records {
		lsRecord, err := r.convertToLinkSecretRecord(record)
		if err != nil {
			continue
		}
		result = append(result, lsRecord)
	}
	
	return result, nil
}

// convertToLinkSecretRecord converts a generic record to LinkSecretRecord
func (r *AskarLinkSecretRepository) convertToLinkSecretRecord(record storage.Record) (*LinkSecretRecord, error) {
	if lsRecord, ok := record.(*LinkSecretRecord); ok {
		return lsRecord, nil
	}
	
	// Fallback deserialization
	data, err := record.ToJSON()
	if err != nil {
		return nil, fmt.Errorf("failed to get record data: %w", err)
	}
	
	var lsRecord LinkSecretRecord
	if err := lsRecord.FromJSON(data); err != nil {
		return nil, fmt.Errorf("failed to deserialize record: %w", err)
	}
	
	return &lsRecord, nil
}