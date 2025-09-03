package repository

import (
	"fmt"

	"github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/core/events"
	"github.com/ajna-inc/essi/pkg/core/storage"
	"github.com/ajna-inc/essi/pkg/didcomm/modules/proofs/records"
)

// ProofRepository extends Repository pattern
// It does NOT implement its own storage, it uses the injected StorageService
type ProofRepository struct {
	storageService storage.StorageService
	eventEmitter   events.Bus
}

// NewProofRepository creates a new proof repository
// This follows credo-ts pattern - takes StorageService and EventEmitter via constructor
func NewProofRepository(storageService storage.StorageService, eventEmitter events.Bus) *ProofRepository {
	return &ProofRepository{
		storageService: storageService,
		eventEmitter:   eventEmitter,
	}
}

// Save saves a proof record using the storage service
func (r *ProofRepository) Save(ctx *context.AgentContext, record *records.ProofRecord) error {
	// Convert to storage record
	storageRecord := proofRecordToStorage(record)

	// Use storage service
	err := r.storageService.Save(ctx.Context, storageRecord)
	if err != nil {
		return fmt.Errorf("failed to save proof record: %w", err)
	}

	// Emit event
	if r.eventEmitter != nil {
		r.eventEmitter.Publish("ProofRecord.saved", events.Event{
			Name: "ProofRecord.saved",
			Data: record,
		})
	}

	return nil
}

// Update updates a proof record
func (r *ProofRepository) Update(ctx *context.AgentContext, record *records.ProofRecord) error {
	// Convert to storage record
	storageRecord := proofRecordToStorage(record)

	// Use storage service
	err := r.storageService.Update(ctx.Context, storageRecord)
	if err != nil {
		return fmt.Errorf("failed to update proof record: %w", err)
	}

	// Emit event
	if r.eventEmitter != nil {
		r.eventEmitter.Publish("ProofRecord.updated", events.Event{
			Name: "ProofRecord.updated",
			Data: record,
		})
	}

	return nil
}

// GetById gets a proof record by ID
func (r *ProofRepository) GetById(ctx *context.AgentContext, id string) (*records.ProofRecord, error) {
	record, err := r.storageService.GetById(ctx.Context, "ProofRecord", id)
	if err != nil {
		return nil, fmt.Errorf("proof record not found: %w", err)
	}

	return storageToProofRecord(record), nil
}

// GetByThreadId gets a proof record by thread ID
// This is  getByThreadAndConnectionId
func (r *ProofRepository) GetByThreadId(ctx *context.AgentContext, threadId string) (*records.ProofRecord, error) {
	query := storage.NewQuery().WithTag("threadId", threadId)
	record, err := r.storageService.FindSingleByQuery(ctx.Context, "ProofRecord", *query)
	if err != nil {
		return nil, fmt.Errorf("proof record not found for thread %s: %w", threadId, err)
	}

	return storageToProofRecord(record), nil
}

// GetByThreadAndConnectionId gets a proof record by thread and connection ID

func (r *ProofRepository) GetByThreadAndConnectionId(
	ctx *context.AgentContext,
	threadId string,
	connectionId string,
) (*records.ProofRecord, error) {
	query := storage.NewQuery().WithTag("threadId", threadId).WithTag("connectionId", connectionId)
	record, err := r.storageService.FindSingleByQuery(ctx.Context, "ProofRecord", *query)
	if err != nil {
		return nil, fmt.Errorf("proof record not found: %w", err)
	}

	return storageToProofRecord(record), nil
}

// GetByConnectionId gets proof records by connection ID
func (r *ProofRepository) GetByConnectionId(ctx *context.AgentContext, connectionId string) ([]*records.ProofRecord, error) {
	query := storage.NewQuery().WithTag("connectionId", connectionId)
	storageRecords, err := r.storageService.FindByQuery(ctx.Context, "ProofRecord", *query)
	if err != nil {
		return nil, fmt.Errorf("failed to find proof records: %w", err)
	}

	proofRecords := make([]*records.ProofRecord, 0, len(storageRecords))
	for _, sr := range storageRecords {
		proofRecords = append(proofRecords, storageToProofRecord(sr))
	}

	return proofRecords, nil
}

// GetByState gets proof records by state
func (r *ProofRepository) GetByState(ctx *context.AgentContext, state string) ([]*records.ProofRecord, error) {
	query := storage.NewQuery().WithTag("state", state)
	storageRecords, err := r.storageService.FindByQuery(ctx.Context, "ProofRecord", *query)
	if err != nil {
		return nil, fmt.Errorf("failed to find proof records: %w", err)
	}

	proofRecords := make([]*records.ProofRecord, 0, len(storageRecords))
	for _, sr := range storageRecords {
		proofRecords = append(proofRecords, storageToProofRecord(sr))
	}

	return proofRecords, nil
}

// GetByParentThreadAndConnectionId gets proof records by parent thread and connection ID

func (r *ProofRepository) GetByParentThreadAndConnectionId(
	ctx *context.AgentContext,
	parentThreadId string,
	connectionId string,
) ([]*records.ProofRecord, error) {
	query := storage.NewQuery().WithTag("parentThreadId", parentThreadId).WithTag("connectionId", connectionId)
	storageRecords, err := r.storageService.FindByQuery(ctx.Context, "ProofRecord", *query)
	if err != nil {
		return nil, fmt.Errorf("failed to find proof records: %w", err)
	}

	proofRecords := make([]*records.ProofRecord, 0, len(storageRecords))
	for _, sr := range storageRecords {
		proofRecords = append(proofRecords, storageToProofRecord(sr))
	}

	return proofRecords, nil
}

// Delete deletes a proof record
func (r *ProofRepository) Delete(ctx *context.AgentContext, id string) error {
	err := r.storageService.DeleteById(ctx.Context, "ProofRecord", id)
	if err != nil {
		return fmt.Errorf("failed to delete proof record: %w", err)
	}

	// Emit event
	if r.eventEmitter != nil {
		r.eventEmitter.Publish("ProofRecord.deleted", events.Event{
			Name: "ProofRecord.deleted",
			Data: map[string]string{"id": id},
		})
	}

	return nil
}

// Helper to convert ProofRecord to storage.Record
func proofRecordToStorage(pr *records.ProofRecord) storage.Record {
	// Create a ProofStorageRecord that implements storage.Record
	storageRecord := records.NewProofStorageRecord(pr)
	return storageRecord
}

// Helper to convert storage.Record back to ProofRecord
func storageToProofRecord(sr storage.Record) *records.ProofRecord {
	// Check if it's already a ProofStorageRecord
	if psr, ok := sr.(*records.ProofStorageRecord); ok {
		return psr.ProofRecord
	}

	// Otherwise, deserialize from JSON
	pr := &records.ProofRecord{}
	if data, err := sr.ToJSON(); err == nil {
		if err := pr.FromJSON(data); err == nil {
			return pr
		}
	}

	// Fallback: create from basic fields if deserialization fails
	pr = &records.ProofRecord{
		ID: sr.GetId(),
	}

	// Restore from tags
	if threadId, ok := sr.GetTag("threadId"); ok {
		pr.ThreadId = threadId
	}
	if parentThreadId, ok := sr.GetTag("parentThreadId"); ok {
		pr.ParentThreadId = parentThreadId
	}
	if connectionId, ok := sr.GetTag("connectionId"); ok {
		pr.ConnectionId = connectionId
	}
	if state, ok := sr.GetTag("state"); ok {
		pr.State = state
	}
	if role, ok := sr.GetTag("role"); ok {
		pr.Role = role
	}

	pr.CreatedAt = sr.GetCreatedAt()
	pr.UpdatedAt = sr.GetUpdatedAt()

	return pr
}

// Implement Repository interface
var _ records.Repository = (*ProofRepository)(nil)
