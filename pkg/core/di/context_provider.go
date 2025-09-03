package di

import (
	"context"

	contextpkg "github.com/ajna-inc/essi/pkg/core/context"
)

// AgentContextProvider creates root and child AgentContexts
type AgentContextProvider interface {
	NewRootContext(dm DependencyManager, correlationId string) (*contextpkg.AgentContext, error)
	NewChildContext(parent *contextpkg.AgentContext, correlationId string) (*contextpkg.AgentContext, error)
}

// DefaultAgentContextProvider is the default implementation using the DI container for config and legacy DM
type DefaultAgentContextProvider struct{}

// NewRootContext creates a root AgentContext bound to the provided DependencyManager
func (DefaultAgentContextProvider) NewRootContext(dm DependencyManager, correlationId string) (*contextpkg.AgentContext, error) {
	agentCfgAny, _ := dm.Resolve(TokenAgentConfig)
	agentCfg, _ := agentCfgAny.(*contextpkg.AgentConfig)

	root := contextpkg.NewAgentContext(contextpkg.AgentContextOptions{
		Context:              context.Background(),
		ContextCorrelationId: correlationId,
		IsRootAgentContext:   true,
		Config:               agentCfg,
	})

	// Store the DM reference in the context
	root.SetDependencyManager(dm)

	return root, nil
}

// NewChildContext creates a child AgentContext linked to the parent
func (DefaultAgentContextProvider) NewChildContext(parent *contextpkg.AgentContext, correlationId string) (*contextpkg.AgentContext, error) {
	return parent.WithCorrelationId(correlationId), nil
}
