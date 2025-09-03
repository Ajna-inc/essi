package holder

import (
	regsvc "github.com/ajna-inc/essi/pkg/anoncreds/registry"
	"github.com/ajna-inc/essi/pkg/anoncreds/services"
	"github.com/ajna-inc/essi/pkg/core/context"
)

// LinkSecretRepository manages link secret storage
type LinkSecretRepository interface {
	Save(ctx *context.AgentContext, id string, linkSecret string) error
	Get(ctx *context.AgentContext, id string) (string, error)
	Delete(ctx *context.AgentContext, id string) error
	GetAll(ctx *context.AgentContext) (map[string]string, error)
}

// CredentialRecord represents a stored credential
type CredentialRecord struct {
	Id                     string                 `json:"id"`
	Credential             string                 `json:"credential"`
	CredentialDefinitionId string                 `json:"credentialDefinitionId"`
	SchemaId               string                 `json:"schemaId"`
	RevocationRegistryId   string                 `json:"revocationRegistryId,omitempty"`
	CredentialRevocationId string                 `json:"credentialRevocationId,omitempty"`
	ConnectionId           string                 `json:"connectionId,omitempty"`
	ThreadId               string                 `json:"threadId,omitempty"`
	Metadata               map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt              int64                  `json:"createdAt"`
	UpdatedAt              int64                  `json:"updatedAt"`
}

// CredentialRepository manages credential storage
type CredentialRepository interface {
	Save(ctx *context.AgentContext, record *CredentialRecord) error
	Update(ctx *context.AgentContext, record *CredentialRecord) error
	GetById(ctx *context.AgentContext, id string) (*CredentialRecord, error)
	GetByFilter(ctx *context.AgentContext, filter *services.CredentialFilter) ([]*CredentialRecord, error)
	GetAll(ctx *context.AgentContext) ([]*CredentialRecord, error)
	Delete(ctx *context.AgentContext, id string) error
}

// RegistryService now accepts the DI router directly
// This can be used if future holder operations need registry access
type RegistryService = *regsvc.Service
