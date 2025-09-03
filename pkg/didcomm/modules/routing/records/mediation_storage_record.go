package records

import (
	"encoding/json"
	"time"

	"github.com/ajna-inc/essi/pkg/core/storage"
)

// MediationStorageRecord wraps MediationRecord to implement storage.Record interface
type MediationStorageRecord struct {
	*MediationRecord
	tags map[string]string
}

// NewMediationStorageRecord creates a new MediationStorageRecord from a MediationRecord
func NewMediationStorageRecord(mr *MediationRecord) *MediationStorageRecord {
	return &MediationStorageRecord{
		MediationRecord: mr,
		tags:           make(map[string]string),
	}
}

// GetId implements storage.Record
func (r *MediationStorageRecord) GetId() string {
	return r.ID
}

// SetId implements storage.Record
func (r *MediationStorageRecord) SetId(id string) {
	r.ID = id
}

// GetType implements storage.Record
func (r *MediationStorageRecord) GetType() string {
	return "MediationRecord"
}

// GetTags implements storage.Record
func (r *MediationStorageRecord) GetTags() map[string]string {
	if r.tags == nil {
		r.tags = make(map[string]string)
	}
	
	// Build tags from MediationRecord fields
	r.tags["connectionId"] = r.ConnectionId
	r.tags["threadId"] = r.ThreadId
	r.tags["state"] = string(r.State)
	r.tags["role"] = string(r.Role)
	if r.Default {
		r.tags["default"] = "true"
	} else {
		r.tags["default"] = "false"
	}
	
	// Add any additional tags from the Tags field
	for k, v := range r.Tags {
		r.tags[k] = v
	}
	
	return r.tags
}

// SetTags implements storage.Record
func (r *MediationStorageRecord) SetTags(tags map[string]string) {
	r.tags = tags
}

// GetTag implements storage.Record
func (r *MediationStorageRecord) GetTag(key string) (string, bool) {
	tags := r.GetTags()
	val, ok := tags[key]
	return val, ok
}

// SetTag implements storage.Record
func (r *MediationStorageRecord) SetTag(key, value string) {
	if r.tags == nil {
		r.tags = make(map[string]string)
	}
	r.tags[key] = value
	r.UpdatedAt = time.Now()
}

// GetCreatedAt implements storage.Record
func (r *MediationStorageRecord) GetCreatedAt() time.Time {
	return r.CreatedAt
}

// GetUpdatedAt implements storage.Record
func (r *MediationStorageRecord) GetUpdatedAt() time.Time {
	return r.UpdatedAt
}

// SetUpdatedAt implements storage.Record
func (r *MediationStorageRecord) SetUpdatedAt(t time.Time) {
	r.UpdatedAt = t
}

// Clone implements storage.Record
func (r *MediationStorageRecord) Clone() storage.Record {
	// Marshal and unmarshal to create a deep copy
	data, _ := json.Marshal(r.MediationRecord)
	var cloned MediationRecord
	json.Unmarshal(data, &cloned)
	
	newRecord := &MediationStorageRecord{
		MediationRecord: &cloned,
		tags:           make(map[string]string),
	}
	
	// Copy tags
	for k, v := range r.tags {
		newRecord.tags[k] = v
	}
	
	return newRecord
}

// ToJSON implements storage.Record
func (r *MediationStorageRecord) ToJSON() ([]byte, error) {
	// Serialize the entire MediationRecord to JSON
	return json.Marshal(r.MediationRecord)
}

// FromJSON implements storage.Record
func (r *MediationStorageRecord) FromJSON(data []byte) error {
	// Deserialize JSON into MediationRecord
	if r.MediationRecord == nil {
		r.MediationRecord = &MediationRecord{}
	}
	return json.Unmarshal(data, r.MediationRecord)
}

// MediationRecordConstructor creates a new MediationStorageRecord for the factory
func MediationRecordConstructor() storage.Record {
	return &MediationStorageRecord{
		MediationRecord: &MediationRecord{
			Metadata: make(map[string]interface{}),
			Tags:     make(map[string]string),
		},
		tags: make(map[string]string),
	}
}

// init registers the MediationRecord type with the factory
func init() {
	storage.RegisterRecordType("MediationRecord", MediationRecordConstructor)
}