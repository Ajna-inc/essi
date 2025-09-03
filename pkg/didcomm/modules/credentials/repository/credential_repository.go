package repository

import (
	"fmt"

	"github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/core/events"
	"github.com/ajna-inc/essi/pkg/core/storage"
	"github.com/ajna-inc/essi/pkg/didcomm/modules/credentials/records"
)

// CredentialRepository extends Repository pattern
// It does NOT implement its own storage, it uses the injected StorageService
type CredentialRepository struct {
	storageService storage.StorageService
	eventEmitter   events.Bus
}

// NewCredentialRepository creates a new credential repository
// This follows credo-ts pattern - takes StorageService and EventEmitter via constructor
func NewCredentialRepository(storageService storage.StorageService, eventEmitter events.Bus) *CredentialRepository {
	return &CredentialRepository{
		storageService: storageService,
		eventEmitter:   eventEmitter,
	}
}

// Save saves a credential record using the storage service
func (r *CredentialRepository) Save(ctx *context.AgentContext, record *records.CredentialRecord) error {
	// Convert to storage record
	storageRecord := credentialRecordToStorage(record)

	// Use storage service
	err := r.storageService.Save(ctx.Context, storageRecord)
	if err != nil {
		return fmt.Errorf("failed to save credential record: %w", err)
	}

	// Emit event
	if r.eventEmitter != nil {
		r.eventEmitter.Publish("CredentialRecord.saved", events.Event{
			Name: "CredentialRecord.saved",
			Data: record,
		})
	}

	return nil
}

// Update updates a credential record
func (r *CredentialRepository) Update(ctx *context.AgentContext, record *records.CredentialRecord) error {
	// Convert to storage record
	storageRecord := credentialRecordToStorage(record)

	// Use storage service
	err := r.storageService.Update(ctx.Context, storageRecord)
	if err != nil {
		return fmt.Errorf("failed to update credential record: %w", err)
	}

	// Emit event
	if r.eventEmitter != nil {
		r.eventEmitter.Publish("CredentialRecord.updated", events.Event{
			Name: "CredentialRecord.updated",
			Data: record,
		})
	}

	return nil
}

// FindById gets a credential record by ID
func (r *CredentialRepository) FindById(ctx *context.AgentContext, id string) (*records.CredentialRecord, error) {
	record, err := r.storageService.GetById(ctx.Context, "CredentialRecord", id)
	if err != nil {
		return nil, fmt.Errorf("credential record not found: %w", err)
	}

	return storageToCredentialRecord(record), nil
}

// FindByThreadId gets a credential record by thread ID
func (r *CredentialRepository) FindByThreadId(ctx *context.AgentContext, threadId string) (*records.CredentialRecord, error) {
	query := storage.NewQuery().WithTag("threadId", threadId)
	record, err := r.storageService.FindSingleByQuery(ctx.Context, "CredentialRecord", *query)
	if err != nil {
		return nil, fmt.Errorf("credential record not found for thread %s: %w", threadId, err)
	}

	return storageToCredentialRecord(record), nil
}

// GetAll gets all credential records
func (r *CredentialRepository) GetAll(ctx *context.AgentContext) ([]*records.CredentialRecord, error) {
	storageRecords, err := r.storageService.GetAll(ctx.Context, "CredentialRecord")
	if err != nil {
		return nil, fmt.Errorf("failed to get all credential records: %w", err)
	}

	credentialRecords := make([]*records.CredentialRecord, 0, len(storageRecords))
	for _, sr := range storageRecords {
		credentialRecords = append(credentialRecords, storageToCredentialRecord(sr))
	}

	return credentialRecords, nil
}

// Delete deletes a credential record
func (r *CredentialRepository) Delete(ctx *context.AgentContext, id string) error {
	err := r.storageService.DeleteById(ctx.Context, "CredentialRecord", id)
	if err != nil {
		return fmt.Errorf("failed to delete credential record: %w", err)
	}

	// Emit event
	if r.eventEmitter != nil {
		r.eventEmitter.Publish("CredentialRecord.deleted", events.Event{
			Name: "CredentialRecord.deleted",
			Data: map[string]string{"id": id},
		})
	}

	return nil
}

// Helper to convert CredentialRecord to storage.Record
func credentialRecordToStorage(cr *records.CredentialRecord) storage.Record {
	// Create a CredentialStorageRecord that implements storage.Record
	storageRecord := records.NewCredentialStorageRecord(cr)
	return storageRecord
}

// Helper to convert storage.Record back to CredentialRecord
func storageToCredentialRecord(sr storage.Record) *records.CredentialRecord {
	// Check if it's already a CredentialStorageRecord
	if csr, ok := sr.(*records.CredentialStorageRecord); ok {
		return csr.CredentialRecord
	}

	// Otherwise, deserialize from JSON
	cr := &records.CredentialRecord{}
	if data, err := sr.ToJSON(); err == nil {
		if err := cr.FromJSON(data); err == nil {
			return cr
		}
	}

	// Fallback: create from basic fields if deserialization fails
	cr = &records.CredentialRecord{}
	cr.ID = sr.GetId()

	// Restore from tags
	if threadId, ok := sr.GetTag("threadId"); ok {
		cr.ThreadId = threadId
	}
	if connectionId, ok := sr.GetTag("connectionId"); ok {
		cr.ConnectionId = connectionId
	}
	if state, ok := sr.GetTag("state"); ok {
		cr.State = records.CredentialState(state)
	}
	if role, ok := sr.GetTag("role"); ok {
		cr.Role = role
	}

	cr.CreatedAt = sr.GetCreatedAt()
	cr.UpdatedAt = sr.GetUpdatedAt()

	return cr
}

// Implement Repository interface
var _ records.Repository = (*CredentialRepository)(nil)
