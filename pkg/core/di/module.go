package di

import (
	contextpkg "github.com/ajna-inc/essi/pkg/core/context"
)

// Module represents a pluggable module with DI registration and lifecycle hooks
type Module interface {
	// Register is called once when the module is added to the container.
	// It should register configs, interfaces, factories and singletons.
	Register(dm DependencyManager) error

	// OnInitializeContext is called when the root AgentContext is initialized.
	// It may open connections (e.g., storage) and register context-bound instances.
	OnInitializeContext(ctx *contextpkg.AgentContext) error

	// OnShutdown is called during agent shutdown to cleanup resources.
	OnShutdown(ctx *contextpkg.AgentContext) error
}

// DependencyManager defines the DI API surfaced to modules
type DependencyManager interface {
	// Registration methods
	RegisterInstance(token Token, instance any)
	RegisterSingleton(token Token, factory func(DependencyManager) (any, error))
	RegisterFactory(token Token, factory func(DependencyManager) (any, error))
	RegisterContextScoped(token Token, factory func(DependencyManager) (any, error))

	// Resolution methods
	Resolve(token Token) (any, error)
	IsRegistered(token Token) bool

	// Context management
	SetContext(ctx *contextpkg.AgentContext)
	GetContext() *contextpkg.AgentContext
	ClearContextInstances(contextId string)

	// Module lifecycle
	RegisterModules(modules []Module) error
	InitializeModules(ctx *contextpkg.AgentContext) error
	ShutdownModules(ctx *contextpkg.AgentContext) error
}
