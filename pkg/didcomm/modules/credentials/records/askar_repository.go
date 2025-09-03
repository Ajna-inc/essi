package records

import (
	stdcontext "context"
	"encoding/json"
	"fmt"

	"github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/core/storage"
)


// AskarRepository implements Repository using Askar storage
type AskarRepository struct {
	storage storage.StorageService
}

// NewAskarRepository creates a new Askar-backed repository
func NewAskarRepository(storageService storage.StorageService) *AskarRepository {
	return &AskarRepository{
		storage: storageService,
	}
}

// Save saves a credential record
func (r *AskarRepository) Save(ctx *context.AgentContext, record *CredentialRecord) error {
	if record == nil {
		return fmt.Errorf("record cannot be nil")
	}

	// Ensure record has proper type set
	if record.BaseRecord == nil {
		record.BaseRecord = &storage.BaseRecord{
			Type: "CredentialRecord",
			Tags: make(map[string]string),
		}
	}
	if record.BaseRecord.Type == "" {
		record.BaseRecord.Type = "CredentialRecord"
	}
	
	// Add tags for querying
	record.BaseRecord.SetTag("threadId", record.ThreadId)
	record.BaseRecord.SetTag("connectionId", record.ConnectionId)
	record.BaseRecord.SetTag("state", string(record.State))
	record.BaseRecord.SetTag("role", string(record.Role))

	// Save to storage directly
	return r.storage.Save(ctx.Context, record)
}

// Update updates a credential record
func (r *AskarRepository) Update(ctx *context.AgentContext, record *CredentialRecord) error {
	if record == nil {
		return fmt.Errorf("record cannot be nil")
	}

	// Ensure record has proper type set
	if record.BaseRecord == nil {
		record.BaseRecord = &storage.BaseRecord{
			Type: "CredentialRecord",
			Tags: make(map[string]string),
		}
	}
	if record.BaseRecord.Type == "" {
		record.BaseRecord.Type = "CredentialRecord"
	}
	
	// Update tags
	record.BaseRecord.SetTag("threadId", record.ThreadId)
	record.BaseRecord.SetTag("connectionId", record.ConnectionId)
	record.BaseRecord.SetTag("state", string(record.State))
	record.BaseRecord.SetTag("role", string(record.Role))

	// Update in storage directly
	return r.storage.Update(ctx.Context, record)
}

// FindById retrieves a credential record by ID
func (r *AskarRepository) FindById(ctx *context.AgentContext, id string) (*CredentialRecord, error) {
	storageRecord, err := r.storage.GetById(ctx.Context, "CredentialRecord", id)
	if err != nil {
		return nil, err
	}

	// The storage should return a properly typed CredentialRecord
	// thanks to our factory registration
	if credRecord, ok := storageRecord.(*CredentialRecord); ok {
		return credRecord, nil
	}

	// Fallback: manually deserialize if we got a BaseRecord
	data, err := storageRecord.ToJSON()
	if err != nil {
		return nil, fmt.Errorf("failed to get record data: %w", err)
	}

	var record CredentialRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, fmt.Errorf("failed to deserialize record: %w", err)
	}

	return &record, nil
}

// FindByThreadId retrieves a credential record by thread ID
func (r *AskarRepository) FindByThreadId(ctx *context.AgentContext, threadID string) (*CredentialRecord, error) {
	query := storage.NewQuery().WithTag("threadId", threadID)
	
	record, err := r.storage.FindSingleByQuery(ctx.Context, "CredentialRecord", *query)
	if err != nil {
		return nil, err
	}

	// The storage should return a properly typed CredentialRecord
	if credRecord, ok := record.(*CredentialRecord); ok {
		return credRecord, nil
	}

	// Fallback: manually deserialize if we got a BaseRecord
	data, err := record.ToJSON()
	if err != nil {
		return nil, fmt.Errorf("failed to get record data: %w", err)
	}

	var credRecord CredentialRecord
	if err := json.Unmarshal(data, &credRecord); err != nil {
		return nil, fmt.Errorf("failed to deserialize record: %w", err)
	}

	return &credRecord, nil
}

// GetByConnectionID retrieves all credential records for a connection
func (r *AskarRepository) GetByConnectionID(ctx *context.AgentContext, connectionID string) ([]*CredentialRecord, error) {
	query := storage.NewQuery().WithTag("connectionId", connectionID)
	
	records, err := r.storage.FindByQuery(ctx.Context, "CredentialRecord", *query)
	if err != nil {
		return nil, err
	}

	credRecords := make([]*CredentialRecord, 0, len(records))
	for _, record := range records {
		data, err := record.ToJSON()
		if err != nil {
			continue
		}

		// Try to cast to CredentialRecord first
		if credRecord, ok := record.(*CredentialRecord); ok {
			credRecords = append(credRecords, credRecord)
			continue
		}

		// Fallback: deserialize manually
		var credRecord CredentialRecord
		if err := json.Unmarshal(data, &credRecord); err != nil {
			continue
		}

		credRecords = append(credRecords, &credRecord)
	}

	return credRecords, nil
}

// GetAll retrieves all credential records
func (r *AskarRepository) GetAll(ctx *context.AgentContext) ([]*CredentialRecord, error) {
	records, err := r.storage.GetAll(ctx.Context, "CredentialRecord")
	if err != nil {
		return nil, err
	}

	credRecords := make([]*CredentialRecord, 0, len(records))
	for _, record := range records {
		data, err := record.ToJSON()
		if err != nil {
			continue
		}

		// Try to cast to CredentialRecord first
		if credRecord, ok := record.(*CredentialRecord); ok {
			credRecords = append(credRecords, credRecord)
			continue
		}

		// Fallback: deserialize manually
		var credRecord CredentialRecord
		if err := json.Unmarshal(data, &credRecord); err != nil {
			continue
		}

		credRecords = append(credRecords, &credRecord)
	}

	return credRecords, nil
}

// Delete deletes a credential record
func (r *AskarRepository) Delete(ctx *context.AgentContext, id string) error {
	return r.storage.DeleteById(ctx.Context, "CredentialRecord", id)
}

// GetByState retrieves credential records by state
func (r *AskarRepository) GetByState(ctx *context.AgentContext, state CredentialState) ([]*CredentialRecord, error) {
	query := storage.NewQuery().WithTag("state", string(state))
	
	records, err := r.storage.FindByQuery(ctx.Context, "CredentialRecord", *query)
	if err != nil {
		return nil, err
	}

	credRecords := make([]*CredentialRecord, 0, len(records))
	for _, record := range records {
		data, err := record.ToJSON()
		if err != nil {
			continue
		}

		// Try to cast to CredentialRecord first
		if credRecord, ok := record.(*CredentialRecord); ok {
			credRecords = append(credRecords, credRecord)
			continue
		}

		// Fallback: deserialize manually
		var credRecord CredentialRecord
		if err := json.Unmarshal(data, &credRecord); err != nil {
			continue
		}

		credRecords = append(credRecords, &credRecord)
	}

	return credRecords, nil
}

// GetByRole retrieves credential records by role
func (r *AskarRepository) GetByRole(role string) ([]*CredentialRecord, error) {
	query := storage.NewQuery().WithTag("role", string(role))
	
	records, err := r.storage.FindByQuery(stdcontext.Background(), "CredentialRecord", *query)
	if err != nil {
		return nil, err
	}

	credRecords := make([]*CredentialRecord, 0, len(records))
	for _, record := range records {
		data, err := record.ToJSON()
		if err != nil {
			continue
		}

		// Try to cast to CredentialRecord first
		if credRecord, ok := record.(*CredentialRecord); ok {
			credRecords = append(credRecords, credRecord)
			continue
		}

		// Fallback: deserialize manually
		var credRecord CredentialRecord
		if err := json.Unmarshal(data, &credRecord); err != nil {
			continue
		}

		credRecords = append(credRecords, &credRecord)
	}

	return credRecords, nil
}