package repository

import (
	"context"
	"fmt"

	"github.com/ajna-inc/essi/pkg/core/storage"
)

// CredentialDefinitionPrivateRepository manages credential definition private records
// Following Credo-TS naming: AnonCredsCredentialDefinitionPrivateRepository
type CredentialDefinitionPrivateRepository struct {
	storageService storage.StorageService
}

// NewCredentialDefinitionPrivateRepository creates a new repository instance
func NewCredentialDefinitionPrivateRepository(storageService storage.StorageService) *CredentialDefinitionPrivateRepository {
	return &CredentialDefinitionPrivateRepository{
		storageService: storageService,
	}
}

// Save stores a credential definition private record
func (r *CredentialDefinitionPrivateRepository) Save(ctx context.Context, record *CredentialDefinitionPrivateRecord) error {
	return r.storageService.Save(ctx, record)
}

// Update updates an existing credential definition private record
func (r *CredentialDefinitionPrivateRepository) Update(ctx context.Context, record *CredentialDefinitionPrivateRecord) error {
	return r.storageService.Update(ctx, record)
}

// Delete removes a credential definition private record
func (r *CredentialDefinitionPrivateRepository) Delete(ctx context.Context, record *CredentialDefinitionPrivateRecord) error {
	return r.storageService.Delete(ctx, record)
}

// GetById retrieves a credential definition private record by ID
func (r *CredentialDefinitionPrivateRepository) GetById(ctx context.Context, id string) (*CredentialDefinitionPrivateRecord, error) {
	record, err := r.storageService.GetById(ctx, "CredentialDefinitionPrivateRecord", id)
	if err != nil {
		return nil, err
	}

	privateRecord, ok := record.(*CredentialDefinitionPrivateRecord)
	if !ok {
		return nil, fmt.Errorf("record is not a CredentialDefinitionPrivateRecord")
	}

	return privateRecord, nil
}

// GetByCredentialDefinitionId retrieves a private record by credential definition ID
func (r *CredentialDefinitionPrivateRepository) GetByCredentialDefinitionId(
	ctx context.Context,
	credentialDefinitionId string,
) (*CredentialDefinitionPrivateRecord, error) {
	query := storage.Query{
		Equal: map[string]interface{}{
			"credentialDefinitionId": credentialDefinitionId,
		},
	}

	records, err := r.storageService.FindByQuery(ctx, "CredentialDefinitionPrivateRecord", query)
	if err != nil {
		return nil, err
	}

	if len(records) == 0 {
		return nil, fmt.Errorf("credential definition private not found: %s", credentialDefinitionId)
	}

	if len(records) > 1 {
		return nil, fmt.Errorf("multiple credential definition privates found for ID: %s", credentialDefinitionId)
	}

	privateRecord, ok := records[0].(*CredentialDefinitionPrivateRecord)
	if !ok {
		return nil, fmt.Errorf("record is not a CredentialDefinitionPrivateRecord")
	}

	return privateRecord, nil
}

// FindByCredentialDefinitionId attempts to find a private record by credential definition ID
// Returns nil if not found (no error)
func (r *CredentialDefinitionPrivateRepository) FindByCredentialDefinitionId(
	ctx context.Context,
	credentialDefinitionId string,
) (*CredentialDefinitionPrivateRecord, error) {
	query := storage.Query{
		Equal: map[string]interface{}{
			"credentialDefinitionId": credentialDefinitionId,
		},
	}

	records, err := r.storageService.FindByQuery(ctx, "CredentialDefinitionPrivateRecord", query)
	if err != nil {
		return nil, err
	}

	if len(records) == 0 {
		return nil, nil // Not found, but not an error
	}

	privateRecord, ok := records[0].(*CredentialDefinitionPrivateRecord)
	if !ok {
		return nil, fmt.Errorf("record is not a CredentialDefinitionPrivateRecord")
	}

	return privateRecord, nil
}