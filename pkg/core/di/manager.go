package di

import (
	"fmt"
	"sync"

	contextpkg "github.com/ajna-inc/essi/pkg/core/context"
)

// Lifecycle defines the lifetime of a registered dependency
type Lifecycle int

const (
	// Singleton creates one instance that lives for the entire application
	Singleton Lifecycle = iota
	// ContextScoped creates one instance per agent context
	ContextScoped
	// Transient creates a new instance on each resolve
	Transient
)

// providerFunc creates an instance on demand using the dependency manager
type providerFunc func(DependencyManager) (any, error)

type registration struct {
	instance  any
	factory   providerFunc
	lifecycle Lifecycle
	// For context-scoped instances, we store per-context instances
	contextInstances map[string]any // map[contextId]instance
}

// dependencyManager is a typed DI container
type dependencyManager struct {
	mu            sync.RWMutex
	registrations map[string]*registration
	modules       []Module
	// Current context for context-scoped resolution
	currentContext *contextpkg.AgentContext
}

// NewDependencyManager creates a new typed DI container
func NewDependencyManager() DependencyManager {
	return &dependencyManager{
		registrations: make(map[string]*registration),
		modules:       make([]Module, 0, 8),
	}
}

// RegisterInstance registers a concrete instance for a token
func (dm *dependencyManager) RegisterInstance(token Token, instance any) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	dm.registrations[token.Name] = &registration{instance: instance}
}

// RegisterSingleton registers a lazy singleton factory for a token
func (dm *dependencyManager) RegisterSingleton(token Token, factory func(DependencyManager) (any, error)) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	pf := func(dmx DependencyManager) (any, error) {
		return factory(dmx)
	}
	dm.registrations[token.Name] = &registration{
		factory:   pf,
		lifecycle: Singleton,
	}
}

// RegisterFactory registers a factory that creates a new instance on each Resolve
func (dm *dependencyManager) RegisterFactory(token Token, factory func(DependencyManager) (any, error)) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	pf := func(dmx DependencyManager) (any, error) {
		return factory(dmx)
	}
	dm.registrations[token.Name] = &registration{
		factory:   pf,
		lifecycle: Transient,
	}
}

// RegisterContextScoped registers a factory that creates one instance per agent context
func (dm *dependencyManager) RegisterContextScoped(token Token, factory func(DependencyManager) (any, error)) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	pf := func(dmx DependencyManager) (any, error) {
		return factory(dmx)
	}
	dm.registrations[token.Name] = &registration{
		factory:          pf,
		lifecycle:        ContextScoped,
		contextInstances: make(map[string]any),
	}
}

// Typed registration helper functions - standalone functions that work with generics

// RegisterTypedSingleton registers a typed singleton service using standalone function
func RegisterTypedSingleton[T any](dm DependencyManager, token TypedToken[T], factory func(DependencyManager) (T, error)) {
	dm.RegisterSingleton(token.ToToken(), func(dm DependencyManager) (any, error) {
		return factory(dm)
	})
}

// RegisterTypedContextScoped registers a typed context-scoped service using standalone function  
func RegisterTypedContextScoped[T any](dm DependencyManager, token TypedToken[T], factory func(DependencyManager) (T, error)) {
	dm.RegisterContextScoped(token.ToToken(), func(dm DependencyManager) (any, error) {
		return factory(dm)
	})
}

// Resolve resolves an instance for a token
func (dm *dependencyManager) Resolve(token Token) (any, error) {
	dm.mu.RLock()
	reg, ok := dm.registrations[token.Name]
	currentCtx := dm.currentContext
	dm.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("dependency not found: %s", token.Name)
	}

	// Handle based on lifecycle
	switch reg.lifecycle {
	case Singleton:
		// Fast path for stored instance
		if reg.instance != nil {
			return reg.instance, nil
		}

		// Create via factory
		if reg.factory == nil {
			return nil, fmt.Errorf("dependency '%s' has no instance or factory", token.Name)
		}

		created, err := reg.factory(dm)
		if err != nil {
			return nil, err
		}

		// Store created instance
		dm.mu.Lock()
		reg.instance = created
		dm.mu.Unlock()
		
		return created, nil

	case ContextScoped:
		if currentCtx == nil {
			return nil, fmt.Errorf("cannot resolve context-scoped dependency '%s' without active context", token.Name)
		}

		contextId := currentCtx.GetCorrelationId()
		
		// Check if instance exists for this context
		dm.mu.RLock()
		if instance, exists := reg.contextInstances[contextId]; exists {
			dm.mu.RUnlock()
			return instance, nil
		}
		dm.mu.RUnlock()

		// Create new instance for this context
		if reg.factory == nil {
			return nil, fmt.Errorf("dependency '%s' has no factory", token.Name)
		}

		created, err := reg.factory(dm)
		if err != nil {
			return nil, err
		}

		// Store for this context
		dm.mu.Lock()
		reg.contextInstances[contextId] = created
		dm.mu.Unlock()

		return created, nil

	case Transient:
		// Always create new instance
		if reg.factory == nil {
			return nil, fmt.Errorf("dependency '%s' has no factory", token.Name)
		}

		return reg.factory(dm)

	default:
		// Instance without lifecycle (backward compatibility)
		if reg.instance != nil {
			return reg.instance, nil
		}
		return nil, fmt.Errorf("dependency '%s' has no instance", token.Name)
	}
}

// IsRegistered returns whether a token has a registration
func (dm *dependencyManager) IsRegistered(token Token) bool {
	dm.mu.RLock()
	_, ok := dm.registrations[token.Name]
	dm.mu.RUnlock()
	return ok
}

// RegisterModules registers and stores modules for lifecycle management
func (dm *dependencyManager) RegisterModules(modules []Module) error {
	for _, m := range modules {
		if m == nil {
			continue
		}
		if err := m.Register(dm); err != nil {
			return err
		}
		dm.modules = append(dm.modules, m)
	}
	return nil
}

// SetContext sets the current context for context-scoped resolution
func (dm *dependencyManager) SetContext(ctx *contextpkg.AgentContext) {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	dm.currentContext = ctx
}

// GetContext returns the current context
func (dm *dependencyManager) GetContext() *contextpkg.AgentContext {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	return dm.currentContext
}

// ClearContextInstances clears all context-scoped instances for a given context
func (dm *dependencyManager) ClearContextInstances(contextId string) {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	
	for _, reg := range dm.registrations {
		if reg.lifecycle == ContextScoped && reg.contextInstances != nil {
			delete(reg.contextInstances, contextId)
		}
	}
}

// InitializeModules calls OnInitializeContext on all registered modules in registration order
func (dm *dependencyManager) InitializeModules(ctx *contextpkg.AgentContext) error {
	// Set context for context-scoped resolution
	dm.SetContext(ctx)
	
	for _, m := range dm.modules {
		if err := m.OnInitializeContext(ctx); err != nil {
			return err
		}
	}
	return nil
}

// ShutdownModules calls OnShutdown on all registered modules in reverse order
func (dm *dependencyManager) ShutdownModules(ctx *contextpkg.AgentContext) error {
	for i := len(dm.modules) - 1; i >= 0; i-- {
		m := dm.modules[i]
		if err := m.OnShutdown(ctx); err != nil {
			return err
		}
	}
	return nil
}

