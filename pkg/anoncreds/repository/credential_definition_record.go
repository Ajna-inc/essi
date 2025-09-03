package repository

import (
	"encoding/json"

	"github.com/ajna-inc/essi/pkg/anoncreds/registry"
	"github.com/ajna-inc/essi/pkg/core/storage"
)

// CredentialDefinitionRecord represents a stored credential definition
// Following Credo-TS naming: AnonCredsCredentialDefinitionRecord
type CredentialDefinitionRecord struct {
	*storage.BaseRecord

	// Core fields
	CredentialDefinitionID string                               `json:"credentialDefinitionId"`
	CredentialDefinition   registry.CredentialDefinition        `json:"credentialDefinition"`
	MethodName             string                               `json:"methodName"` // e.g., "kanon", "indy"
}

// NewCredentialDefinitionRecord creates a new credential definition record
func NewCredentialDefinitionRecord(
	credentialDefinitionID string,
	credentialDefinition registry.CredentialDefinition,
	methodName string,
) *CredentialDefinitionRecord {
	record := &CredentialDefinitionRecord{
		BaseRecord:             storage.NewBaseRecord("CredentialDefinitionRecord"),
		CredentialDefinitionID: credentialDefinitionID,
		CredentialDefinition:   credentialDefinition,
		MethodName:             methodName,
	}

	// Set tags for efficient querying
	record.SetTag("credentialDefinitionId", credentialDefinitionID)
	record.SetTag("schemaId", credentialDefinition.SchemaId)
	record.SetTag("issuerId", credentialDefinition.IssuerId)
	record.SetTag("tag", credentialDefinition.Tag)
	record.SetTag("methodName", methodName)

	return record
}

// ToJSON serializes the record to JSON
func (r *CredentialDefinitionRecord) ToJSON() ([]byte, error) {
	return json.Marshal(r)
}

// FromJSON deserializes the record from JSON
func (r *CredentialDefinitionRecord) FromJSON(data []byte) error {
	return json.Unmarshal(data, r)
}

// Clone creates a deep copy of the record
func (r *CredentialDefinitionRecord) Clone() storage.Record {
	cloned := &CredentialDefinitionRecord{
		BaseRecord:             &storage.BaseRecord{
			ID:        r.ID,
			Type:      r.Type,
			Tags:      make(map[string]string),
			CreatedAt: r.CreatedAt,
			UpdatedAt: r.UpdatedAt,
		},
		CredentialDefinitionID: r.CredentialDefinitionID,
		CredentialDefinition:   r.CredentialDefinition,
		MethodName:             r.MethodName,
	}

	// Deep copy tags
	for k, v := range r.Tags {
		cloned.Tags[k] = v
	}

	return cloned
}