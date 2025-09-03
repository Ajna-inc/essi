package records

import (
	"encoding/json"
	"time"

	"github.com/ajna-inc/essi/pkg/core/storage"
)

// ProofStorageRecord wraps ProofRecord to implement storage.Record interface
type ProofStorageRecord struct {
	*ProofRecord
	tags map[string]string
}

// NewProofStorageRecord creates a new ProofStorageRecord from a ProofRecord
func NewProofStorageRecord(pr *ProofRecord) *ProofStorageRecord {
	return &ProofStorageRecord{
		ProofRecord: pr,
		tags:        make(map[string]string),
	}
}

// GetId implements storage.Record
func (r *ProofStorageRecord) GetId() string {
	return r.ID
}

// SetId implements storage.Record
func (r *ProofStorageRecord) SetId(id string) {
	r.ID = id
}

// GetType implements storage.Record
func (r *ProofStorageRecord) GetType() string {
	return "ProofRecord"
}

// GetTags implements storage.Record
func (r *ProofStorageRecord) GetTags() map[string]string {
	if r.tags == nil {
		r.tags = make(map[string]string)
	}
	
	// Build tags from ProofRecord fields - matches credo-ts getTags()
	r.tags["threadId"] = r.ThreadId
	if r.ParentThreadId != "" {
		r.tags["parentThreadId"] = r.ParentThreadId
	}
	if r.ConnectionId != "" {
		r.tags["connectionId"] = r.ConnectionId
	}
	r.tags["state"] = r.State
	r.tags["role"] = r.Role
	
	// Add any additional tags from the Tags field
	for k, v := range r.Tags {
		r.tags[k] = v
	}
	
	return r.tags
}

// SetTags implements storage.Record
func (r *ProofStorageRecord) SetTags(tags map[string]string) {
	r.tags = tags
}

// GetTag implements storage.Record
func (r *ProofStorageRecord) GetTag(key string) (string, bool) {
	tags := r.GetTags()
	val, ok := tags[key]
	return val, ok
}

// SetTag implements storage.Record
func (r *ProofStorageRecord) SetTag(key, value string) {
	if r.tags == nil {
		r.tags = make(map[string]string)
	}
	r.tags[key] = value
	r.UpdatedAt = time.Now()
}

// GetCreatedAt implements storage.Record
func (r *ProofStorageRecord) GetCreatedAt() time.Time {
	return r.CreatedAt
}

// GetUpdatedAt implements storage.Record
func (r *ProofStorageRecord) GetUpdatedAt() time.Time {
	return r.UpdatedAt
}

// SetUpdatedAt implements storage.Record
func (r *ProofStorageRecord) SetUpdatedAt(t time.Time) {
	r.UpdatedAt = t
}

// Clone implements storage.Record
func (r *ProofStorageRecord) Clone() storage.Record {
	// Marshal and unmarshal to create a deep copy
	data, _ := json.Marshal(r.ProofRecord)
	var cloned ProofRecord
	json.Unmarshal(data, &cloned)
	
	newRecord := &ProofStorageRecord{
		ProofRecord: &cloned,
		tags:        make(map[string]string),
	}
	
	// Copy tags
	for k, v := range r.tags {
		newRecord.tags[k] = v
	}
	
	return newRecord
}

// ToJSON implements storage.Record
func (r *ProofStorageRecord) ToJSON() ([]byte, error) {
	// Serialize the entire ProofRecord to JSON
	return json.Marshal(r.ProofRecord)
}

// FromJSON implements storage.Record
func (r *ProofStorageRecord) FromJSON(data []byte) error {
	// Deserialize JSON into ProofRecord
	if r.ProofRecord == nil {
		r.ProofRecord = &ProofRecord{}
	}
	return json.Unmarshal(data, r.ProofRecord)
}

// ProofRecordConstructor creates a new ProofStorageRecord for the factory
func ProofRecordConstructor() storage.Record {
	return &ProofStorageRecord{
		ProofRecord: &ProofRecord{
			Metadata: make(map[string]interface{}),
			Tags:     make(map[string]string),
		},
		tags: make(map[string]string),
	}
}

// init registers the ProofRecord type with the factory
func init() {
	storage.RegisterRecordType("ProofRecord", ProofRecordConstructor)
}