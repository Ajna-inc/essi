package records

import (
	"encoding/json"
	"time"

	"github.com/ajna-inc/essi/pkg/core/context"
)

// MediationRole indicates mediator or recipient
type MediationRole string

const (
	MediationRoleMediator  MediationRole = "mediator"
	MediationRoleRecipient MediationRole = "recipient"
)

// MediationState tracks mediation record lifecycle
type MediationState string

const (
	MediationStateRequested MediationState = "requested"
	MediationStateGranted   MediationState = "granted"
	MediationStateDenied    MediationState = "denied"
)

// MediationRecord stores mediation state for a connection
type MediationRecord struct {
	ID            string         `json:"id"`
	Role          MediationRole  `json:"role"`
	State         MediationState `json:"state"`
	ConnectionId  string         `json:"connectionId"`
	ThreadId      string         `json:"threadId"`
	Endpoint      string         `json:"endpoint,omitempty"`
	RecipientKeys []string       `json:"recipientKeys,omitempty"`
	RoutingKeys   []string       `json:"routingKeys,omitempty"`
	Default       bool           `json:"default"`
	CreatedAt     time.Time      `json:"createdAt"`
	UpdatedAt     time.Time      `json:"updatedAt"`
	
	// Metadata for additional information
	Metadata map[string]interface{} `json:"metadata,omitempty"`
	Tags     map[string]string      `json:"tags,omitempty"`
}

// NewMediationRecord creates a new mediation record
func NewMediationRecord(id string) *MediationRecord {
	now := time.Now()
	return &MediationRecord{
		ID:        id,
		CreatedAt: now,
		UpdatedAt: now,
		Metadata:  make(map[string]interface{}),
		Tags:      make(map[string]string),
	}
}

// GetId returns the record ID
func (r *MediationRecord) GetId() string {
	return r.ID
}

// GetType returns the record type
func (r *MediationRecord) GetType() string {
	return "MediationRecord"
}

// ToJSON serializes the MediationRecord to JSON
func (r *MediationRecord) ToJSON() ([]byte, error) {
	return json.Marshal(r)
}

// FromJSON deserializes JSON into the MediationRecord
func (r *MediationRecord) FromJSON(data []byte) error {
	return json.Unmarshal(data, r)
}

// Repository interface for mediation records
type Repository interface {
	Save(ctx *context.AgentContext, record *MediationRecord) error
	Update(ctx *context.AgentContext, record *MediationRecord) error
	GetById(ctx *context.AgentContext, id string) (*MediationRecord, error)
	FindByConnectionId(ctx *context.AgentContext, connectionId string) (*MediationRecord, error)
	FindDefault(ctx *context.AgentContext) (*MediationRecord, error)
	GetAll(ctx *context.AgentContext) ([]*MediationRecord, error)
	Delete(ctx *context.AgentContext, id string) error
}