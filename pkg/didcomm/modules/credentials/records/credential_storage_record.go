package records

import (
	"encoding/json"
	"time"

	"github.com/ajna-inc/essi/pkg/core/storage"
)

// CredentialStorageRecord wraps CredentialRecord to implement storage.Record interface
type CredentialStorageRecord struct {
	*CredentialRecord
	tags map[string]string
}

// NewCredentialStorageRecord creates a new CredentialStorageRecord from a CredentialRecord
func NewCredentialStorageRecord(cr *CredentialRecord) *CredentialStorageRecord {
	return &CredentialStorageRecord{
		CredentialRecord: cr,
		tags:            make(map[string]string),
	}
}

// GetId implements storage.Record
func (r *CredentialStorageRecord) GetId() string {
	return r.ID
}

// SetId implements storage.Record
func (r *CredentialStorageRecord) SetId(id string) {
	r.ID = id
}

// GetType implements storage.Record
func (r *CredentialStorageRecord) GetType() string {
	return "CredentialRecord"
}

// GetTags implements storage.Record
func (r *CredentialStorageRecord) GetTags() map[string]string {
	if r.tags == nil {
		r.tags = make(map[string]string)
	}
	
	// Build tags from CredentialRecord fields - matches credo-ts getTags()
	r.tags["threadId"] = r.ThreadId
	if r.ConnectionId != "" {
		r.tags["connectionId"] = r.ConnectionId
	}
	r.tags["state"] = string(r.State)
	r.tags["role"] = r.Role
	
	// Add any additional tags from the BaseRecord Tags field
	if r.BaseRecord != nil && r.BaseRecord.Tags != nil {
		for k, v := range r.BaseRecord.Tags {
			r.tags[k] = v
		}
	}
	
	return r.tags
}

// SetTags implements storage.Record
func (r *CredentialStorageRecord) SetTags(tags map[string]string) {
	r.tags = tags
}

// GetTag implements storage.Record
func (r *CredentialStorageRecord) GetTag(key string) (string, bool) {
	tags := r.GetTags()
	val, ok := tags[key]
	return val, ok
}

// SetTag implements storage.Record
func (r *CredentialStorageRecord) SetTag(key, value string) {
	if r.tags == nil {
		r.tags = make(map[string]string)
	}
	r.tags[key] = value
	r.UpdatedAt = time.Now()
}

// GetCreatedAt implements storage.Record
func (r *CredentialStorageRecord) GetCreatedAt() time.Time {
	if r.BaseRecord != nil {
		return r.BaseRecord.CreatedAt
	}
	return time.Time{}
}

// GetUpdatedAt implements storage.Record
func (r *CredentialStorageRecord) GetUpdatedAt() time.Time {
	if r.BaseRecord != nil {
		return r.BaseRecord.UpdatedAt
	}
	return time.Time{}
}

// SetUpdatedAt implements storage.Record
func (r *CredentialStorageRecord) SetUpdatedAt(t time.Time) {
	if r.BaseRecord != nil {
		r.BaseRecord.UpdatedAt = t
	}
}

// Clone implements storage.Record
func (r *CredentialStorageRecord) Clone() storage.Record {
	// Marshal and unmarshal to create a deep copy
	data, _ := json.Marshal(r.CredentialRecord)
	var cloned CredentialRecord
	json.Unmarshal(data, &cloned)
	
	newRecord := &CredentialStorageRecord{
		CredentialRecord: &cloned,
		tags:            make(map[string]string),
	}
	
	// Copy tags
	for k, v := range r.tags {
		newRecord.tags[k] = v
	}
	
	return newRecord
}

// ToJSON implements storage.Record
func (r *CredentialStorageRecord) ToJSON() ([]byte, error) {
	// Serialize the entire CredentialRecord to JSON
	return json.Marshal(r.CredentialRecord)
}

// FromJSON implements storage.Record
func (r *CredentialStorageRecord) FromJSON(data []byte) error {
	// Deserialize JSON into CredentialRecord
	if r.CredentialRecord == nil {
		r.CredentialRecord = &CredentialRecord{}
	}
	return json.Unmarshal(data, r.CredentialRecord)
}

// CredentialRecordConstructor creates a new CredentialStorageRecord for the factory
func CredentialRecordConstructor() storage.Record {
	return &CredentialStorageRecord{
		CredentialRecord: &CredentialRecord{
			BaseRecord: &storage.BaseRecord{
				Type: "CredentialRecord",
				Tags: make(map[string]string),
			},
		},
		tags: make(map[string]string),
	}
}

// init registers the CredentialRecord type with the factory
func init() {
	storage.RegisterRecordType("CredentialRecord", CredentialRecordConstructor)
}