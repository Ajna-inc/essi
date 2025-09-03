package repository

import (
	"encoding/json"

	"github.com/ajna-inc/essi/pkg/core/storage"
)

// CredentialDefinitionPrivateRecord stores the private part of a credential definition
// Following Credo-TS naming: AnonCredsCredentialDefinitionPrivateRecord
type CredentialDefinitionPrivateRecord struct {
	*storage.BaseRecord

	CredentialDefinitionID string                 `json:"credentialDefinitionId"`
	Value                  map[string]interface{} `json:"value"` // Private key material
}

// NewCredentialDefinitionPrivateRecord creates a new private record
func NewCredentialDefinitionPrivateRecord(
	credentialDefinitionID string,
	value map[string]interface{},
) *CredentialDefinitionPrivateRecord {
	record := &CredentialDefinitionPrivateRecord{
		BaseRecord:             storage.NewBaseRecord("CredentialDefinitionPrivateRecord"),
		CredentialDefinitionID: credentialDefinitionID,
		Value:                  value,
	}

	// Set tag for efficient querying
	record.SetTag("credentialDefinitionId", credentialDefinitionID)

	return record
}

// ToJSON serializes the record to JSON
func (r *CredentialDefinitionPrivateRecord) ToJSON() ([]byte, error) {
	return json.Marshal(r)
}

// FromJSON deserializes the record from JSON
func (r *CredentialDefinitionPrivateRecord) FromJSON(data []byte) error {
	return json.Unmarshal(data, r)
}

// Clone creates a deep copy of the record
func (r *CredentialDefinitionPrivateRecord) Clone() storage.Record {
	cloned := &CredentialDefinitionPrivateRecord{
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