package repository

import (
	"context"
	"fmt"

	"github.com/ajna-inc/essi/pkg/core/storage"
)

// KeyCorrectnessProofRepository manages key correctness proof records
// Following Credo-TS naming: AnonCredsKeyCorrectnessProofRepository
type KeyCorrectnessProofRepository struct {
	storageService storage.StorageService
}

// NewKeyCorrectnessProofRepository creates a new repository instance
func NewKeyCorrectnessProofRepository(storageService storage.StorageService) *KeyCorrectnessProofRepository {
	return &KeyCorrectnessProofRepository{
		storageService: storageService,
	}
}

// Save stores a key correctness proof record
func (r *KeyCorrectnessProofRepository) Save(ctx context.Context, record *KeyCorrectnessProofRecord) error {
	return r.storageService.Save(ctx, record)
}

// Update updates an existing key correctness proof record
func (r *KeyCorrectnessProofRepository) Update(ctx context.Context, record *KeyCorrectnessProofRecord) error {
	return r.storageService.Update(ctx, record)
}

// Delete removes a key correctness proof record
func (r *KeyCorrectnessProofRepository) Delete(ctx context.Context, record *KeyCorrectnessProofRecord) error {
	return r.storageService.Delete(ctx, record)
}

// GetById retrieves a key correctness proof record by ID
func (r *KeyCorrectnessProofRepository) GetById(ctx context.Context, id string) (*KeyCorrectnessProofRecord, error) {
	record, err := r.storageService.GetById(ctx, "KeyCorrectnessProofRecord", id)
	if err != nil {
		return nil, err
	}

	kcpRecord, ok := record.(*KeyCorrectnessProofRecord)
	if !ok {
		return nil, fmt.Errorf("record is not a KeyCorrectnessProofRecord")
	}

	return kcpRecord, nil
}

// GetByCredentialDefinitionId retrieves a key correctness proof record by credential definition ID
func (r *KeyCorrectnessProofRepository) GetByCredentialDefinitionId(
	ctx context.Context,
	credentialDefinitionId string,
) (*KeyCorrectnessProofRecord, error) {
	query := storage.Query{
		Equal: map[string]interface{}{
			"credentialDefinitionId": credentialDefinitionId,
		},
	}

	records, err := r.storageService.FindByQuery(ctx, "KeyCorrectnessProofRecord", query)
	if err != nil {
		return nil, err
	}

	if len(records) == 0 {
		return nil, fmt.Errorf("key correctness proof not found: %s", credentialDefinitionId)
	}

	if len(records) > 1 {
		return nil, fmt.Errorf("multiple key correctness proofs found for ID: %s", credentialDefinitionId)
	}

	kcpRecord, ok := records[0].(*KeyCorrectnessProofRecord)
	if !ok {
		return nil, fmt.Errorf("record is not a KeyCorrectnessProofRecord")
	}

	return kcpRecord, nil
}

// FindByCredentialDefinitionId attempts to find a key correctness proof record by credential definition ID
// Returns nil if not found (no error)
func (r *KeyCorrectnessProofRepository) FindByCredentialDefinitionId(
	ctx context.Context,
	credentialDefinitionId string,
) (*KeyCorrectnessProofRecord, error) {
	query := storage.Query{
		Equal: map[string]interface{}{
			"credentialDefinitionId": credentialDefinitionId,
		},
	}

	records, err := r.storageService.FindByQuery(ctx, "KeyCorrectnessProofRecord", query)
	if err != nil {
		return nil, err
	}

	if len(records) == 0 {
		return nil, nil // Not found, but not an error
	}

	kcpRecord, ok := records[0].(*KeyCorrectnessProofRecord)
	if !ok {
		return nil, fmt.Errorf("record is not a KeyCorrectnessProofRecord")
	}

	return kcpRecord, nil
}