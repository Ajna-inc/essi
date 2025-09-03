package crypto

import (
	"github.com/ajna-inc/essi/pkg/core/context"
)

// Signer interface for creating digital signatures
type Signer interface {
	Sign(ctx *context.AgentContext, data []byte) ([]byte, error)
	GetKeyType() string
	GetKeyId() string
}

// Verifier interface for verifying digital signatures  
type Verifier interface {
	Verify(ctx *context.AgentContext, data []byte, signature []byte) (bool, error)
	GetKeyType() string
}

// KeyManager interface for key operations
type KeyManager interface {
	CreateKey(ctx *context.AgentContext, keyType string) (string, error)
	GetKey(ctx *context.AgentContext, keyId string) (interface{}, error)
	Sign(ctx *context.AgentContext, keyId string, data []byte) ([]byte, error)
	Verify(ctx *context.AgentContext, keyId string, data []byte, signature []byte) (bool, error)
}

// JwsService interface for JSON Web Signature operations
type JwsService interface {
	CreateJws(ctx *context.AgentContext, options interface{}) (interface{}, error)
	VerifyJws(ctx *context.AgentContext, jws interface{}, payload []byte) (bool, error)
}