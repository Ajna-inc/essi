package records

import (
	"github.com/ajna-inc/essi/pkg/core/context"
)

type Repository interface {
	Save(ctx *context.AgentContext, rec *CredentialRecord) error
	Update(ctx *context.AgentContext, rec *CredentialRecord) error
	FindById(ctx *context.AgentContext, id string) (*CredentialRecord, error)
	FindByThreadId(ctx *context.AgentContext, thid string) (*CredentialRecord, error)
	GetAll(ctx *context.AgentContext) ([]*CredentialRecord, error)
}
