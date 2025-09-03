package records

import (
	"encoding/json"
	"fmt"
	
	"github.com/ajna-inc/essi/pkg/core/storage"
)

// RevocationRegistryState represents the state of a revocation registry
type RevocationRegistryState string

const (
	RevocationStateCreated RevocationRegistryState = "created"
	RevocationStateActive  RevocationRegistryState = "active"
	RevocationStateFull    RevocationRegistryState = "full"
)

// RevocationRegistryDefinitionRecord stores public revocation registry definition
type RevocationRegistryDefinitionRecord struct {
	*storage.BaseRecord
	
	RevocationRegistryDefinitionId string                 `json:"revocationRegistryDefinitionId"`
	CredentialDefinitionId         string                 `json:"credentialDefinitionId"`
	RevocationRegistryDefinition   map[string]interface{} `json:"revocationRegistryDefinition"`
}

// RevocationRegistryDefinitionPrivateRecord stores private revocation registry data
type RevocationRegistryDefinitionPrivateRecord struct {
	*storage.BaseRecord
	
	RevocationRegistryDefinitionId string                  `json:"revocationRegistryDefinitionId"`
	CredentialDefinitionId         string                  `json:"credentialDefinitionId"`
	Value                         map[string]interface{}  `json:"value"` // Private key data
	State                         RevocationRegistryState `json:"state"`
	CurrentIndex                  int                     `json:"currentIndex"`
	MaxCredNum                    int                     `json:"maxCredNum"`
}

// NewRevocationRegistryDefinitionRecord creates a new public registry record
func NewRevocationRegistryDefinitionRecord(id string) *RevocationRegistryDefinitionRecord {
	return &RevocationRegistryDefinitionRecord{
		BaseRecord: &storage.BaseRecord{
			ID:   id,
			Type: "RevocationRegistryDefinitionRecord",
			Tags: make(map[string]string),
		},
	}
}

// NewRevocationRegistryDefinitionPrivateRecord creates a new private registry record  
func NewRevocationRegistryDefinitionPrivateRecord(id string) *RevocationRegistryDefinitionPrivateRecord {
	return &RevocationRegistryDefinitionPrivateRecord{
		BaseRecord: &storage.BaseRecord{
			ID:   id,
			Type: "RevocationRegistryDefinitionPrivateRecord",
			Tags: make(map[string]string),
		},
		State:        RevocationStateCreated,
		CurrentIndex: 0,
	}
}

// ToJSON serializes the record
func (r *RevocationRegistryDefinitionRecord) ToJSON() ([]byte, error) {
	return json.Marshal(r)
}

// FromJSON deserializes the record
func (r *RevocationRegistryDefinitionRecord) FromJSON(data []byte) error {
	return json.Unmarshal(data, r)
}

// ToJSON serializes the private record
func (r *RevocationRegistryDefinitionPrivateRecord) ToJSON() ([]byte, error) {
	return json.Marshal(r)
}

// FromJSON deserializes the private record
func (r *RevocationRegistryDefinitionPrivateRecord) FromJSON(data []byte) error {
	return json.Unmarshal(data, r)
}

// GetNextIndex returns the next available revocation index
func (r *RevocationRegistryDefinitionPrivateRecord) GetNextIndex() (int, error) {
	if r.State == RevocationStateFull {
		return 0, fmt.Errorf("revocation registry is full")
	}
	
	r.CurrentIndex++
	if r.CurrentIndex >= r.MaxCredNum {
		r.State = RevocationStateFull
	}
	
	return r.CurrentIndex, nil
}

// Register record types with factory
func init() {
	storage.RegisterRecordType("RevocationRegistryDefinitionRecord", func() storage.Record {
		return &RevocationRegistryDefinitionRecord{
			BaseRecord: &storage.BaseRecord{
				Type: "RevocationRegistryDefinitionRecord",
				Tags: make(map[string]string),
			},
		}
	})
	
	storage.RegisterRecordType("RevocationRegistryDefinitionPrivateRecord", func() storage.Record {
		return &RevocationRegistryDefinitionPrivateRecord{
			BaseRecord: &storage.BaseRecord{
				Type: "RevocationRegistryDefinitionPrivateRecord",
				Tags: make(map[string]string),
			},
			State: RevocationStateCreated,
		}
	})
}