package repository

import (
	"context"
	"encoding/json"
	"fmt"

	agentcontext "github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/core/storage"
	"github.com/ajna-inc/essi/pkg/dids"
	"github.com/ajna-inc/essi/pkg/dids/domain"
)

// AskarDidRepository implements DidRepository using Askar storage
type AskarDidRepository struct {
	storage storage.StorageService
}

// NewAskarDidRepository creates a new Askar-based DID repository
func NewAskarDidRepository(storageService storage.StorageService) *AskarDidRepository {
	return &AskarDidRepository{
		storage: storageService,
	}
}

// StoreCreatedDid stores a DID that was created by this agent
func (r *AskarDidRepository) StoreCreatedDid(
	ctx *agentcontext.AgentContext,
	did string,
	didDocument *dids.DidDocument,
	keys []domain.DidDocumentKey,
	tags map[string]string,
) (*DidRecord, error) {
	record := NewDidRecord(DidRecordProps{
		Did:         did,
		Role:        domain.DidDocumentRoleCreated,
		DidDocument: didDocument,
		Keys:        keys,
		Tags:        tags,
	})

	if err := r.storage.Save(context.Background(), record); err != nil {
		return nil, fmt.Errorf("failed to store created DID: %w", err)
	}

	return record, nil
}

// StoreReceivedDid stores a DID that was received from another agent
func (r *AskarDidRepository) StoreReceivedDid(
	ctx *agentcontext.AgentContext,
	did string,
	didDocument *dids.DidDocument,
	tags map[string]string,
) (*DidRecord, error) {
	record := NewDidRecord(DidRecordProps{
		Did:         did,
		Role:        domain.DidDocumentRoleReceived,
		DidDocument: didDocument,
		Tags:        tags,
	})

	if err := r.storage.Save(context.Background(), record); err != nil {
		return nil, fmt.Errorf("failed to store received DID: %w", err)
	}

	return record, nil
}

// FindById finds a DID record by its ID
func (r *AskarDidRepository) FindById(ctx *agentcontext.AgentContext, id string) (*DidRecord, error) {
	rec, err := r.storage.GetById(context.Background(), "DidRecord", id)
	if err != nil {
		return nil, err
	}
	return r.cast(rec)
}

// FindCreatedDid finds a created DID by its identifier
func (r *AskarDidRepository) FindCreatedDid(ctx *agentcontext.AgentContext, did string) (*DidRecord, error) {
	query := storage.NewQuery().
		WithTag("did", did).
		WithTag("role", string(domain.DidDocumentRoleCreated))

	rec, err := r.storage.FindSingleByQuery(context.Background(), "DidRecord", *query)
	if err != nil {
		return nil, err
	}
	return r.cast(rec)
}

// FindReceivedDid finds a received DID by its identifier
func (r *AskarDidRepository) FindReceivedDid(ctx *agentcontext.AgentContext, did string) (*DidRecord, error) {
	query := storage.NewQuery().
		WithTag("did", did).
		WithTag("role", string(domain.DidDocumentRoleReceived))

	rec, err := r.storage.FindSingleByQuery(context.Background(), "DidRecord", *query)
	if err != nil {
		return nil, err
	}
	return r.cast(rec)
}

// FindByRecipientKey finds a DID record by recipient key fingerprint
func (r *AskarDidRepository) FindByRecipientKey(
	ctx *agentcontext.AgentContext,
	keyFingerprint string,
	role domain.DidDocumentRole,
) (*DidRecord, error) {
	query := storage.NewQuery().
		WithTag("recipientKeyFingerprints", keyFingerprint).
		WithTag("role", string(role))

	rec, err := r.storage.FindSingleByQuery(context.Background(), "DidRecord", *query)
	if err != nil {
		return nil, err
	}
	return r.cast(rec)
}

// FindAllByRecipientKey finds all DID records by recipient key fingerprint
func (r *AskarDidRepository) FindAllByRecipientKey(
	ctx *agentcontext.AgentContext,
	keyFingerprint string,
) ([]*DidRecord, error) {
	query := storage.NewQuery().
		WithTag("recipientKeyFingerprints", keyFingerprint)

	records, err := r.storage.FindByQuery(context.Background(), "DidRecord", *query)
	if err != nil {
		return nil, err
	}
	return r.castList(records), nil
}

// GetCreatedDids gets all created DIDs with optional filtering
func (r *AskarDidRepository) GetCreatedDids(
	ctx *agentcontext.AgentContext,
	options GetDidsOptions,
) ([]*DidRecord, error) {
	query := storage.NewQuery().
		WithTag("role", string(domain.DidDocumentRoleCreated))

	if options.Method != "" {
		query = query.WithTag("method", options.Method)
	}
	if options.Did != "" {
		query = query.WithTag("did", options.Did)
	}

	records, err := r.storage.FindByQuery(context.Background(), "DidRecord", *query)
	if err != nil {
		return nil, err
	}
	return r.castList(records), nil
}

// GetReceivedDids gets all received DIDs with optional filtering
func (r *AskarDidRepository) GetReceivedDids(
	ctx *agentcontext.AgentContext,
	options GetDidsOptions,
) ([]*DidRecord, error) {
	query := storage.NewQuery().
		WithTag("role", string(domain.DidDocumentRoleReceived))

	if options.Method != "" {
		query = query.WithTag("method", options.Method)
	}
	if options.Did != "" {
		query = query.WithTag("did", options.Did)
	}

	records, err := r.storage.FindByQuery(context.Background(), "DidRecord", *query)
	if err != nil {
		return nil, err
	}
	return r.castList(records), nil
}

// GetAll gets all DID records
func (r *AskarDidRepository) GetAll(ctx *agentcontext.AgentContext) ([]*DidRecord, error) {
	records, err := r.storage.GetAll(context.Background(), "DidRecord")
	if err != nil {
		return nil, err
	}
	return r.castList(records), nil
}

// Update updates an existing DID record
func (r *AskarDidRepository) Update(ctx *agentcontext.AgentContext, record *DidRecord) error {
	// Ensure tags are up to date
	tags := record.GetTags()
	tags["did"] = record.Did
	tags["role"] = string(record.Role)
	
	if parsed := parseDid(record.Did); parsed != nil {
		tags["method"] = parsed.Method
		tags["methodSpecificIdentifier"] = parsed.Id
	}
	
	record.SetTags(tags)
	
	return r.storage.Update(context.Background(), record)
}

// Delete deletes a DID record by ID
func (r *AskarDidRepository) Delete(ctx *agentcontext.AgentContext, id string) error {
	return r.storage.DeleteById(context.Background(), "DidRecord", id)
}

// cast converts a generic storage.Record to DidRecord
func (r *AskarDidRepository) cast(rec storage.Record) (*DidRecord, error) {
	if dr, ok := rec.(*DidRecord); ok {
		return dr, nil
	}

	var out DidRecord
	b, err := rec.ToJSON()
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// castList converts a list of storage.Record to []*DidRecord
func (r *AskarDidRepository) castList(records []storage.Record) []*DidRecord {
	out := make([]*DidRecord, 0, len(records))
	for _, rec := range records {
		if dr, err := r.cast(rec); err == nil {
			out = append(out, dr)
		}
	}
	return out
}