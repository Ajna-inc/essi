package context

import (
	"context"
	"sync"
)

// AgentContext represents the context for agent operations
type AgentContext struct {
	// Context for cancellation and timeout
	Context context.Context

	// DependencyManager provides access to the DI container
	DependencyManager interface{}

	// ContextCorrelationId allows correlation across sessions
	ContextCorrelationId string

	// IsRootAgentContext indicates if this is the root context
	IsRootAgentContext bool

	// Config provides access to agent configuration
	Config *AgentConfig

	// mutex for thread safety
	mutex sync.RWMutex
}

// AgentConfig represents the agent configuration
type AgentConfig struct {
	Label        string        `json:"label"`
	WalletConfig *WalletConfig `json:"walletConfig,omitempty"`
	Endpoints    []string      `json:"endpoints,omitempty"`
	InboundHost  string        `json:"inboundHost,omitempty"`
	InboundPort  int           `json:"inboundPort,omitempty"`
	Logger       interface{}   `json:"logger,omitempty"`
	// MediatorInvitationUrl, if set, will be used to automatically connect to a mediator
	// and request mediation on agent initialization, similar to Credo-TS MediationRecipientModule.
	MediatorInvitationUrl string `json:"mediatorInvitationUrl,omitempty"`
	// AutoAcceptCredentials defines when to auto-accept credentials (never, always, contentApproved)
	AutoAcceptCredentials string `json:"autoAcceptCredentials,omitempty"`
	// AutoAcceptConnections defines when to auto-accept connections
	AutoAcceptConnections bool                   `json:"autoAcceptConnections,omitempty"`
	ExtraConfig           map[string]interface{} `json:"extraConfig,omitempty"`
}

// WalletConfig represents wallet configuration
type WalletConfig struct {
	ID                  string `json:"id"`
	Key                 string `json:"key"`
	KeyDerivationMethod string `json:"keyDerivationMethod,omitempty"`
}

// NewAgentContext creates a new agent context
func NewAgentContext(opts AgentContextOptions) *AgentContext {
	ctx := opts.Context
	if ctx == nil {
		ctx = context.Background()
	}

	return &AgentContext{
		Context:              ctx,
		ContextCorrelationId: opts.ContextCorrelationId,
		IsRootAgentContext:   opts.IsRootAgentContext,
		Config:               opts.Config,
	}
}

// AgentContextOptions represents options for creating an agent context
type AgentContextOptions struct {
	Context              context.Context
	ContextCorrelationId string
	IsRootAgentContext   bool
	Config               *AgentConfig
}

// WithContext creates a new agent context with a different context
func (ac *AgentContext) WithContext(ctx context.Context) *AgentContext {
	ac.mutex.Lock()
	defer ac.mutex.Unlock()

	return &AgentContext{
		Context:              ctx,
		DependencyManager:    ac.DependencyManager,
		ContextCorrelationId: ac.ContextCorrelationId,
		IsRootAgentContext:   ac.IsRootAgentContext,
		Config:               ac.Config,
	}
}

// SetDependencyManager sets the dependency manager
func (ac *AgentContext) SetDependencyManager(dm interface{}) {
	ac.mutex.Lock()
	defer ac.mutex.Unlock()
	ac.DependencyManager = dm
}

// WithCorrelationId creates a new agent context with a different correlation ID
func (ac *AgentContext) WithCorrelationId(correlationId string) *AgentContext {
	ac.mutex.Lock()
	defer ac.mutex.Unlock()

	return &AgentContext{
		Context:              ac.Context,
		DependencyManager:    ac.DependencyManager,
		ContextCorrelationId: correlationId,
		IsRootAgentContext:   false, // Child contexts are not root contexts
		Config:               ac.Config,
	}
}

// GetCorrelationId returns the context correlation ID
func (ac *AgentContext) GetCorrelationId() string {
	ac.mutex.RLock()
	defer ac.mutex.RUnlock()

	return ac.ContextCorrelationId
}

// EndSession ends the session for this agent context
func (ac *AgentContext) EndSession() error {
	// TODO: Implement session cleanup
	// This should notify the agent context provider that the session is ending
	return nil
}

// ToJSON returns a JSON representation of the agent context
func (ac *AgentContext) ToJSON() map[string]interface{} {
	ac.mutex.RLock()
	defer ac.mutex.RUnlock()

	return map[string]interface{}{
		"contextCorrelationId": ac.ContextCorrelationId,
		"isRootAgentContext":   ac.IsRootAgentContext,
		"hasDependencyManager": ac.DependencyManager != nil,
		"hasConfig":            ac.Config != nil,
	}
}
