package oob

import (
	"github.com/ajna-inc/essi/pkg/core/di"
	contextpkg "github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/core/events"
	"github.com/ajna-inc/essi/pkg/core/logger"
	"github.com/ajna-inc/essi/pkg/core/storage"
)

// OutOfBandModule implements the out-of-band protocol module
type OutOfBandModule struct{}

// NewOutOfBandModule creates a new out-of-band module
func NewOutOfBandModule() *OutOfBandModule {
	return &OutOfBandModule{}
}

// Register registers the module dependencies with the DI container
func (m *OutOfBandModule) Register(dm di.DependencyManager) error {
	// Register storage-backed OutOfBandRepository
	dm.RegisterSingleton(di.TokenOutOfBandRepository, func(dm di.DependencyManager) (any, error) {
		storageSvcAny, err := dm.Resolve(di.TokenStorageService)
		if err != nil { return nil, err }
		eventBusAny, err := dm.Resolve(di.TokenEventBus)
		if err != nil { return nil, err }
		storageSvc, _ := storageSvcAny.(storage.StorageService)
		eventBus, _ := eventBusAny.(events.Bus)
		return NewOutOfBandRepository(storageSvc, eventBus), nil
	})
	
	// Register OutOfBandService (utility, currently optional)
	dm.RegisterSingleton(di.TokenOutOfBandService, func(dm di.DependencyManager) (any, error) {
		return NewOutOfBandService(), nil
	})
	
	// Register OutOfBandApi as context-scoped
	dm.RegisterContextScoped(di.TokenOobApi, func(dm di.DependencyManager) (any, error) {
		eventEmitter, err := di.ResolveAs[events.Bus](dm, di.TokenEventBus)
		if err != nil {
			return nil, err
		}
		
		agentContext, err := di.ResolveAs[*contextpkg.AgentContext](dm, di.TokenAgentContext)
		if err != nil {
			return nil, err
		}
		
		log, _ := di.ResolveAs[logger.Logger](dm, di.TokenLogger)
		if log == nil {
			log = logger.NewDefaultLogger(logger.InfoLevel)
		}
		
		return NewOutOfBandApi(eventEmitter, log, agentContext), nil
	})
	
	return nil
}

// OnInitializeContext initializes the module for a specific agent context
func (m *OutOfBandModule) OnInitializeContext(ctx *contextpkg.AgentContext) error {
	return nil
}

// OnShutdown cleans up module resources
func (m *OutOfBandModule) OnShutdown(ctx *contextpkg.AgentContext) error {
	return nil
}