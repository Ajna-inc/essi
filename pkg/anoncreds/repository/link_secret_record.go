package repository

import (
	"encoding/json"
	
	"github.com/ajna-inc/essi/pkg/core/storage"
)

// LinkSecretRecord stores link secret information
type LinkSecretRecord struct {
	*storage.BaseRecord
	
	LinkSecretId string `json:"linkSecretId"`
	Value        string `json:"value,omitempty"` // The actual link secret value (optional)
	IsDefault    bool   `json:"isDefault"`
}

// NewLinkSecretRecord creates a new link secret record
func NewLinkSecretRecord(id, linkSecretId string) *LinkSecretRecord {
	return &LinkSecretRecord{
		BaseRecord: &storage.BaseRecord{
			ID:   id,
			Type: "LinkSecretRecord",
			Tags: make(map[string]string),
		},
		LinkSecretId: linkSecretId,
		IsDefault:    false,
	}
}

// ToJSON serializes the record
func (r *LinkSecretRecord) ToJSON() ([]byte, error) {
	return json.Marshal(r)
}

// FromJSON deserializes the record
func (r *LinkSecretRecord) FromJSON(data []byte) error {
	return json.Unmarshal(data, r)
}

// SetAsDefault marks this link secret as default
func (r *LinkSecretRecord) SetAsDefault(isDefault bool) {
	r.IsDefault = isDefault
	if isDefault {
		r.BaseRecord.SetTag("isDefault", "true")
	} else {
		r.BaseRecord.RemoveTag("isDefault")
	}
}

// Register record type with factory
func init() {
	storage.RegisterRecordType("LinkSecretRecord", func() storage.Record {
		return &LinkSecretRecord{
			BaseRecord: &storage.BaseRecord{
				Type: "LinkSecretRecord",
				Tags: make(map[string]string),
			},
		}
	})
}