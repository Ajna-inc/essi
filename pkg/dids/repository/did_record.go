package repository

import (
	"encoding/json"
	"time"

	"github.com/ajna-inc/essi/pkg/core/storage"
	"github.com/ajna-inc/essi/pkg/core/utils"
	"github.com/ajna-inc/essi/pkg/dids"
	"github.com/ajna-inc/essi/pkg/dids/domain"
)

// DidRecordProps contains the properties for creating a new DidRecord
type DidRecordProps struct {
	ID          string
	Did         string
	Role        domain.DidDocumentRole
	DidDocument *dids.DidDocument
	Keys        []domain.DidDocumentKey
	CreatedAt   time.Time
	Tags        map[string]string
}

// DidRecord represents a stored DID with its document and metadata
type DidRecord struct {
	*storage.BaseRecord

	// Did is the decentralized identifier
	Did string `json:"did"`

	// Role indicates whether this DID was created or received
	Role domain.DidDocumentRole `json:"role"`

	// DidDocument contains the full DID document (optional, as it can be resolved)
	DidDocument *dids.DidDocument `json:"didDocument,omitempty"`

	// Keys contains the KMS key references for this DID (only for created DIDs)
	Keys []domain.DidDocumentKey `json:"keys,omitempty"`
}

// NewDidRecord creates a new DID record with the given properties
func NewDidRecord(props DidRecordProps) *DidRecord {
	if props.ID == "" {
		props.ID = utils.NewUUID().String()
	}
	if props.CreatedAt.IsZero() {
		props.CreatedAt = time.Now()
	}

	record := &DidRecord{
		BaseRecord: &storage.BaseRecord{
			ID:        props.ID,
			Type:      "DidRecord",
			CreatedAt: props.CreatedAt,
			UpdatedAt: props.CreatedAt,
		},
		Did:         props.Did,
		Role:        props.Role,
		DidDocument: props.DidDocument,
		Keys:        props.Keys,
	}

	// Set tags for efficient querying
	tags := make(map[string]string)
	if props.Tags != nil {
		for k, v := range props.Tags {
			tags[k] = v
		}
	}

	// Add default tags
	tags["did"] = props.Did
	tags["role"] = string(props.Role)

	// Parse DID to extract method
	if parsed := parseDid(props.Did); parsed != nil {
		tags["method"] = parsed.Method
		tags["methodSpecificIdentifier"] = parsed.Id
	}

	// Add recipient key fingerprints if we have a DID document
	if props.DidDocument != nil && len(props.DidDocument.VerificationMethod) > 0 {
		// Store fingerprints for recipient key lookup
		fingerprints := extractRecipientKeyFingerprints(props.DidDocument)
		if len(fingerprints) > 0 {
			tags["recipientKeyFingerprints"] = fingerprints[0] // Store first for single lookup
			// For multiple fingerprints, we'd need to handle this differently
		}
	}

	record.BaseRecord.SetTags(tags)

	return record
}

// ToJSON serializes the entire DidRecord including all fields
func (r *DidRecord) ToJSON() ([]byte, error) {
	return json.Marshal(r)
}

// FromJSON deserializes the entire DidRecord including all fields
func (r *DidRecord) FromJSON(data []byte) error {
	return json.Unmarshal(data, r)
}

// Clone creates a deep copy of the DidRecord
func (r *DidRecord) Clone() storage.Record {
	clone := &DidRecord{}
	if r.BaseRecord != nil {
		clone.BaseRecord = r.BaseRecord.Clone().(*storage.BaseRecord)
	}

	clone.Did = r.Did
	clone.Role = r.Role

	if r.DidDocument != nil {
		// Deep copy the DID document
		docBytes, _ := json.Marshal(r.DidDocument)
		var clonedDoc dids.DidDocument
		json.Unmarshal(docBytes, &clonedDoc)
		clone.DidDocument = &clonedDoc
	}

	if r.Keys != nil {
		clone.Keys = make([]domain.DidDocumentKey, len(r.Keys))
		copy(clone.Keys, r.Keys)
	}

	return clone
}

// parseDid is a helper to parse DID strings
func parseDid(did string) *dids.ParsedDid {
	parsed, _ := dids.ParseDid(did)
	return parsed
}

// extractRecipientKeyFingerprints extracts key fingerprints from DID document
func extractRecipientKeyFingerprints(doc *dids.DidDocument) []string {
	var fingerprints []string
	// This would need proper implementation based on your key fingerprint logic
	// For now, returning empty slice
	return fingerprints
}

// Register the DidRecord type with the storage factory at startup
func init() {
	storage.RegisterRecordType("DidRecord", func() storage.Record {
		return &DidRecord{
			BaseRecord: &storage.BaseRecord{
				Type: "DidRecord",
				Tags: make(map[string]string),
			},
		}
	})
}