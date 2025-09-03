package records

import (
	"encoding/json"
	"time"

	"github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/didcomm/modules/proofs/models"
)

type ProofRecord struct {
	ID              string                 `json:"id"`
	ConnectionId    string                 `json:"connectionId,omitempty"`
	ThreadId        string                 `json:"threadId"`
	ParentThreadId  string                 `json:"parentThreadId,omitempty"`
	State           string                 `json:"state"`
	Role            string                 `json:"role"`
	ProtocolVersion string                 `json:"protocolVersion"`
	AutoAcceptProof models.AutoAcceptProof `json:"autoAcceptProof,omitempty"`
	AutoAccept      bool                   `json:"autoAccept,omitempty"`
	ErrorMessage    string                 `json:"errorMessage,omitempty"`
	Error           string                 `json:"error,omitempty"`
	IsVerified      bool                   `json:"isVerified"`
	CreatedAt       time.Time              `json:"createdAt"`
	UpdatedAt       time.Time              `json:"updatedAt"`
	
	// Format-specific data
	ProofFormats map[string]interface{} `json:"proofFormats,omitempty"`
	ProofRequest map[string]interface{} `json:"proofRequest,omitempty"`
	Presentation map[string]interface{} `json:"presentation,omitempty"`
	
	// Metadata for additional information
	Metadata map[string]interface{} `json:"metadata,omitempty"`
	Tags     map[string]string      `json:"tags,omitempty"`
}

func NewProofRecord(id string) *ProofRecord {
	now := time.Now()
	return &ProofRecord{
		ID:        id,
		CreatedAt: now,
		UpdatedAt: now,
		Metadata:  make(map[string]interface{}),
	}
}

// GetId returns the record ID
func (r *ProofRecord) GetId() string {
	return r.ID
}

// GetType returns the record type
func (r *ProofRecord) GetType() string {
	return "ProofRecord"
}

// ToJSON serializes the ProofRecord to JSON
func (r *ProofRecord) ToJSON() ([]byte, error) {
	return json.Marshal(r)
}

// FromJSON deserializes JSON into the ProofRecord
func (r *ProofRecord) FromJSON(data []byte) error {
	return json.Unmarshal(data, r)
}

type Repository interface {
	Save(ctx *context.AgentContext, record *ProofRecord) error
	Update(ctx *context.AgentContext, record *ProofRecord) error
	GetById(ctx *context.AgentContext, id string) (*ProofRecord, error)
	GetByThreadId(ctx *context.AgentContext, threadId string) (*ProofRecord, error)
	GetByConnectionId(ctx *context.AgentContext, connectionId string) ([]*ProofRecord, error)
	GetByState(ctx *context.AgentContext, state string) ([]*ProofRecord, error)
	Delete(ctx *context.AgentContext, id string) error
}