package repository

import (
	"context"
	"fmt"

	"github.com/ajna-inc/essi/pkg/core/storage"
)

// CredentialDefinitionRepository manages credential definition records
// Following Credo-TS naming: AnonCredsCredentialDefinitionRepository
type CredentialDefinitionRepository struct {
	storageService storage.StorageService
}

// NewCredentialDefinitionRepository creates a new repository instance
func NewCredentialDefinitionRepository(storageService storage.StorageService) *CredentialDefinitionRepository {
	return &CredentialDefinitionRepository{
		storageService: storageService,
	}
}

// Save stores a credential definition record
func (r *CredentialDefinitionRepository) Save(ctx context.Context, record *CredentialDefinitionRecord) error {
	return r.storageService.Save(ctx, record)
}

// Update updates an existing credential definition record
func (r *CredentialDefinitionRepository) Update(ctx context.Context, record *CredentialDefinitionRecord) error {
	return r.storageService.Update(ctx, record)
}

// Delete removes a credential definition record
func (r *CredentialDefinitionRepository) Delete(ctx context.Context, record *CredentialDefinitionRecord) error {
	return r.storageService.Delete(ctx, record)
}

// GetById retrieves a credential definition record by ID
func (r *CredentialDefinitionRepository) GetById(ctx context.Context, id string) (*CredentialDefinitionRecord, error) {
	record, err := r.storageService.GetById(ctx, "CredentialDefinitionRecord", id)
	if err != nil {
		return nil, err
	}

	credDefRecord, ok := record.(*CredentialDefinitionRecord)
	if !ok {
		return nil, fmt.Errorf("record is not a CredentialDefinitionRecord")
	}

	return credDefRecord, nil
}

// GetByCredentialDefinitionId retrieves a record by credential definition ID
// This is the main lookup method - checks both qualified and unqualified IDs
func (r *CredentialDefinitionRepository) GetByCredentialDefinitionId(
	ctx context.Context,
	credentialDefinitionId string,
) (*CredentialDefinitionRecord, error) {
	// Query by credentialDefinitionId tag
	query := storage.Query{
		Equal: map[string]interface{}{
			"credentialDefinitionId": credentialDefinitionId,
		},
	}

	records, err := r.storageService.FindByQuery(ctx, "CredentialDefinitionRecord", query)
	if err != nil {
		return nil, err
	}

	if len(records) == 0 {
		return nil, fmt.Errorf("credential definition not found: %s", credentialDefinitionId)
	}

	if len(records) > 1 {
		return nil, fmt.Errorf("multiple credential definitions found for ID: %s", credentialDefinitionId)
	}

	credDefRecord, ok := records[0].(*CredentialDefinitionRecord)
	if !ok {
		return nil, fmt.Errorf("record is not a CredentialDefinitionRecord")
	}

	return credDefRecord, nil
}

// FindByCredentialDefinitionId attempts to find a record by credential definition ID
// Returns nil if not found (no error)
func (r *CredentialDefinitionRepository) FindByCredentialDefinitionId(
	ctx context.Context,
	credentialDefinitionId string,
) (*CredentialDefinitionRecord, error) {
	query := storage.Query{
		Equal: map[string]interface{}{
			"credentialDefinitionId": credentialDefinitionId,
		},
	}

	records, err := r.storageService.FindByQuery(ctx, "CredentialDefinitionRecord", query)
	if err != nil {
		return nil, err
	}

	if len(records) == 0 {
		return nil, nil // Not found, but not an error
	}

	credDefRecord, ok := records[0].(*CredentialDefinitionRecord)
	if !ok {
		return nil, fmt.Errorf("record is not a CredentialDefinitionRecord")
	}

	return credDefRecord, nil
}

// FindByQuery finds records matching the given query
func (r *CredentialDefinitionRepository) FindByQuery(
	ctx context.Context,
	query storage.Query,
) ([]*CredentialDefinitionRecord, error) {
	records, err := r.storageService.FindByQuery(ctx, "CredentialDefinitionRecord", query)
	if err != nil {
		return nil, err
	}

	credDefRecords := make([]*CredentialDefinitionRecord, 0, len(records))
	for _, record := range records {
		credDefRecord, ok := record.(*CredentialDefinitionRecord)
		if !ok {
			continue
		}
		credDefRecords = append(credDefRecords, credDefRecord)
	}

	return credDefRecords, nil
}

// GetAll retrieves all credential definition records
func (r *CredentialDefinitionRepository) GetAll(ctx context.Context) ([]*CredentialDefinitionRecord, error) {
	records, err := r.storageService.GetAll(ctx, "CredentialDefinitionRecord")
	if err != nil {
		return nil, err
	}

	credDefRecords := make([]*CredentialDefinitionRecord, 0, len(records))
	for _, record := range records {
		credDefRecord, ok := record.(*CredentialDefinitionRecord)
		if !ok {
			continue
		}
		credDefRecords = append(credDefRecords, credDefRecord)
	}

	return credDefRecords, nil
}