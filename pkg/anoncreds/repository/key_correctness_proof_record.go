package repository

import (
	"encoding/json"

	"github.com/ajna-inc/essi/pkg/core/storage"
)

// KeyCorrectnessProofRecord stores the key correctness proof for a credential definition
// Following Credo-TS naming: AnonCredsKeyCorrectnessProofRecord
type KeyCorrectnessProofRecord struct {
	*storage.BaseRecord

	CredentialDefinitionID string                 `json:"credentialDefinitionId"`
	Value                  map[string]interface{} `json:"value"` // Key correctness proof
}

// NewKeyCorrectnessProofRecord creates a new key correctness proof record
func NewKeyCorrectnessProofRecord(
	credentialDefinitionID string,
	value map[string]interface{},
) *KeyCorrectnessProofRecord {
	record := &KeyCorrectnessProofRecord{
		BaseRecord:             storage.NewBaseRecord("KeyCorrectnessProofRecord"),
		CredentialDefinitionID: credentialDefinitionID,
		Value:                  value,
	}

	// Set tag for efficient querying
	record.SetTag("credentialDefinitionId", credentialDefinitionID)

	return record
}

// ToJSON serializes the record to JSON
func (r *KeyCorrectnessProofRecord) ToJSON() ([]byte, error) {
	return json.Marshal(r)
}

// FromJSON deserializes the record from JSON
func (r *KeyCorrectnessProofRecord) FromJSON(data []byte) error {
	return json.Unmarshal(data, r)
}

// Clone creates a deep copy of the record
func (r *KeyCorrectnessProofRecord) Clone() storage.Record {
	cloned := &KeyCorrectnessProofRecord{
		BaseRecord: &storage.BaseRecord{
			ID:        r.ID,
			Type:      r.Type,
			Tags:      make(map[string]string),
			CreatedAt: r.CreatedAt,
			UpdatedAt: r.UpdatedAt,
		},
		CredentialDefinitionID: r.CredentialDefinitionID,
		Value:                  make(map[string]interface{}),
	}

	// Deep copy tags
	for k, v := range r.Tags {
		cloned.Tags[k] = v
	}

	// Deep copy value
	for k, v := range r.Value {
		cloned.Value[k] = v
	}

	return cloned
}