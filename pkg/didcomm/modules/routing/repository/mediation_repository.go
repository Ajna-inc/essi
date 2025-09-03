package repository

import (
	"fmt"

	"github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/core/events"
	"github.com/ajna-inc/essi/pkg/core/storage"
	"github.com/ajna-inc/essi/pkg/didcomm/modules/routing/records"
)

// MediationRepository extends Repository pattern
// It does NOT implement its own storage, it uses the injected StorageService
type MediationRepository struct {
	storageService storage.StorageService
	eventEmitter   events.Bus
}

// NewMediationRepository creates a new mediation repository
// This follows credo-ts pattern - takes StorageService and EventEmitter via constructor
func NewMediationRepository(storageService storage.StorageService, eventEmitter events.Bus) *MediationRepository {
	return &MediationRepository{
		storageService: storageService,
		eventEmitter:   eventEmitter,
	}
}

// Save saves a mediation record using the storage service
func (r *MediationRepository) Save(ctx *context.AgentContext, record *records.MediationRecord) error {
	// Convert to storage record
	storageRecord := mediationRecordToStorage(record)

	// Use storage service
	err := r.storageService.Save(ctx.Context, storageRecord)
	if err != nil {
		return fmt.Errorf("failed to save mediation record: %w", err)
	}

	// Emit event
	if r.eventEmitter != nil {
		r.eventEmitter.Publish("MediationRecord.saved", events.Event{
			Name: "MediationRecord.saved",
			Data: record,
		})
	}

	return nil
}

// Update updates a mediation record
func (r *MediationRepository) Update(ctx *context.AgentContext, record *records.MediationRecord) error {
	// Convert to storage record
	storageRecord := mediationRecordToStorage(record)

	// Use storage service
	err := r.storageService.Update(ctx.Context, storageRecord)
	if err != nil {
		return fmt.Errorf("failed to update mediation record: %w", err)
	}

	// Emit event
	if r.eventEmitter != nil {
		r.eventEmitter.Publish("MediationRecord.updated", events.Event{
			Name: "MediationRecord.updated",
			Data: record,
		})
	}

	return nil
}

// FindByConnectionId finds a mediation record by connection ID
func (r *MediationRepository) FindByConnectionId(ctx *context.AgentContext, connectionId string) (*records.MediationRecord, error) {
	query := storage.NewQuery().WithTag("connectionId", connectionId)
	record, err := r.storageService.FindSingleByQuery(ctx.Context, "MediationRecord", *query)
	if err != nil {
		return nil, fmt.Errorf("mediation record not found for connection %s: %w", connectionId, err)
	}

	return storageToMediationRecord(record), nil
}

// FindDefault finds the default mediation record
func (r *MediationRepository) FindDefault(ctx *context.AgentContext) (*records.MediationRecord, error) {
	query := storage.NewQuery().WithTag("default", "true")
	record, err := r.storageService.FindSingleByQuery(ctx.Context, "MediationRecord", *query)
	if err != nil {
		return nil, fmt.Errorf("no default mediator found: %w", err)
	}

	return storageToMediationRecord(record), nil
}

// GetById gets a mediation record by ID
func (r *MediationRepository) GetById(ctx *context.AgentContext, id string) (*records.MediationRecord, error) {
	record, err := r.storageService.GetById(ctx.Context, "MediationRecord", id)
	if err != nil {
		return nil, fmt.Errorf("mediation record not found: %w", err)
	}

	return storageToMediationRecord(record), nil
}

// GetAll gets all mediation records
func (r *MediationRepository) GetAll(ctx *context.AgentContext) ([]*records.MediationRecord, error) {
	storageRecords, err := r.storageService.GetAll(ctx.Context, "MediationRecord")
	if err != nil {
		return nil, fmt.Errorf("failed to get all mediation records: %w", err)
	}

	mediationRecords := make([]*records.MediationRecord, 0, len(storageRecords))
	for _, sr := range storageRecords {
		mediationRecords = append(mediationRecords, storageToMediationRecord(sr))
	}

	return mediationRecords, nil
}

// Delete deletes a mediation record
func (r *MediationRepository) Delete(ctx *context.AgentContext, id string) error {
	err := r.storageService.DeleteById(ctx.Context, "MediationRecord", id)
	if err != nil {
		return fmt.Errorf("failed to delete mediation record: %w", err)
	}

	// Emit event
	if r.eventEmitter != nil {
		r.eventEmitter.Publish("MediationRecord.deleted", events.Event{
			Name: "MediationRecord.deleted",
			Data: map[string]string{"id": id},
		})
	}

	return nil
}

// Helper to convert MediationRecord to storage.Record
func mediationRecordToStorage(mr *records.MediationRecord) storage.Record {
	// Create a MediationStorageRecord that implements storage.Record
	storageRecord := records.NewMediationStorageRecord(mr)
	return storageRecord
}

// Helper to convert storage.Record back to MediationRecord
func storageToMediationRecord(sr storage.Record) *records.MediationRecord {
	// Check if it's already a MediationStorageRecord
	if msr, ok := sr.(*records.MediationStorageRecord); ok {
		return msr.MediationRecord
	}

	// Otherwise, deserialize from JSON
	mr := &records.MediationRecord{}
	if data, err := sr.ToJSON(); err == nil {
		if err := mr.FromJSON(data); err == nil {
			return mr
		}
	}

	// Fallback: create from basic fields if deserialization fails
	mr = &records.MediationRecord{
		ID: sr.GetId(),
	}

	// Restore from tags
	if connectionId, ok := sr.GetTag("connectionId"); ok {
		mr.ConnectionId = connectionId
	}
	if threadId, ok := sr.GetTag("threadId"); ok {
		mr.ThreadId = threadId
	}
	if state, ok := sr.GetTag("state"); ok {
		mr.State = records.MediationState(state)
	}
	if role, ok := sr.GetTag("role"); ok {
		mr.Role = records.MediationRole(role)
	}
	if def, ok := sr.GetTag("default"); ok {
		mr.Default = (def == "true")
	}

	return mr
}

// Implement Repository interface
var _ records.Repository = (*MediationRepository)(nil)
