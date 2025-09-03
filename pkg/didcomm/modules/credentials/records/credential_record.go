package records

import (
	"encoding/json"
	
	"github.com/ajna-inc/essi/pkg/core/storage"
)

type CredentialState string

const (
	// States as defined in RFC 0036 and RFC 0453
	StateProposalSent       CredentialState = "proposal-sent"
	StateProposalReceived   CredentialState = "proposal-received"
	StateOfferSent          CredentialState = "offer-sent"
	StateOfferReceived      CredentialState = "offer-received"
	StateDeclined           CredentialState = "declined"
	StateRequestSent        CredentialState = "request-sent"
	StateRequestReceived    CredentialState = "request-received"
	StateCredentialIssued   CredentialState = "credential-issued"
	StateCredentialReceived CredentialState = "credential-received"
	StateDone               CredentialState = "done"
	StateAbandoned          CredentialState = "abandoned"
)

// AutoAcceptCredential defines auto-accept strategies
type AutoAcceptCredential string

const (
	// Always auto-accept the credential
	AutoAcceptAlways AutoAcceptCredential = "always"
	// Auto-accept if content is approved
	AutoAcceptContentApproved AutoAcceptCredential = "contentApproved"
	// Never auto-accept
	AutoAcceptNever AutoAcceptCredential = "never"
)

type CredentialRecord struct {
	*storage.BaseRecord
	ConnectionId    string                 `json:"connectionId"`
	ThreadId        string                 `json:"threadId"`
	Role            string                 `json:"role"`
	State           CredentialState        `json:"state"`
	Formats         []string               `json:"formats,omitempty"`
	RequestMetadata map[string]interface{} `json:"requestMetadata,omitempty"`
	// Store preview attributes (raw values) for compatibility with TS
	// key -> raw value; encoding can be derived as needed
	PreviewAttributes map[string]string        `json:"previewAttributes,omitempty"`
	OfferPayload      map[string]interface{} `json:"offerPayload,omitempty"`
	// Auto-accept configuration for this credential exchange
	AutoAcceptCredential AutoAcceptCredential `json:"autoAcceptCredential,omitempty"`
	// Store credential attributes for validation
	CredentialAttributes map[string]string `json:"credentialAttributes,omitempty"`
	// Revocation support
	RevocationRegistryId string `json:"revocationRegistryId,omitempty"`
	CredentialRevocationId string `json:"credentialRevocationId,omitempty"`
}

func NewCredentialRecord(id string) *CredentialRecord {
	return &CredentialRecord{
		BaseRecord: &storage.BaseRecord{
			ID:   id,
			Type: "CredentialRecord",
			Tags: map[string]string{},
		},
		State: StateOfferReceived,
	}
}

// ToJSON serializes the entire CredentialRecord including all fields
func (r *CredentialRecord) ToJSON() ([]byte, error) {
	return json.Marshal(r)
}

// FromJSON deserializes the entire CredentialRecord including all fields
func (r *CredentialRecord) FromJSON(data []byte) error {
	return json.Unmarshal(data, r)
}

// Register this record type with the factory
func init() {
	storage.RegisterRecordType("CredentialRecord", func() storage.Record {
		return &CredentialRecord{
			BaseRecord: &storage.BaseRecord{
				Type: "CredentialRecord",
				Tags: make(map[string]string),
			},
		}
	})
}
