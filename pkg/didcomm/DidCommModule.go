package didcomm

import (
	"fmt"

	contextpkg "github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/core/di"
	"github.com/ajna-inc/essi/pkg/core/logger"
	corestorage "github.com/ajna-inc/essi/pkg/core/storage"
	"github.com/ajna-inc/essi/pkg/core/wallet"
	"github.com/ajna-inc/essi/pkg/didcomm/crypto/jws"
	"github.com/ajna-inc/essi/pkg/didcomm/modules/connections"
	connservices "github.com/ajna-inc/essi/pkg/didcomm/modules/connections/services"
	"github.com/ajna-inc/essi/pkg/didcomm/modules/oob"
	"github.com/ajna-inc/essi/pkg/didcomm/registrations"
	"github.com/ajna-inc/essi/pkg/didcomm/services"
	transport "github.com/ajna-inc/essi/pkg/didcomm/transport"
	receivedrepo "github.com/ajna-inc/essi/pkg/dids/repository"
)

// Minimal FeatureRegistry and Protocol for Discover Features parity
// (lightweight internal implementation to advertise supported protocols)
type Protocol struct {
	ID    string
	Roles []string
}

type FeatureRegistry struct{ protocols []Protocol }

func NewFeatureRegistry() *FeatureRegistry { return &FeatureRegistry{protocols: []Protocol{}} }
func (fr *FeatureRegistry) Register(protocols ...Protocol) {
	for _, p := range protocols {
		replaced := false
		for i := range fr.protocols {
			if fr.protocols[i].ID == p.ID {
				fr.protocols[i] = p
				replaced = true
				break
			}
		}
		if !replaced {
			fr.protocols = append(fr.protocols, p)
		}
	}
}
func (fr *FeatureRegistry) List() []Protocol { return fr.protocols }

// DidCommModuleConfig holds configuration for the DIDComm module
type DidCommModuleConfig struct {
	ConnectionImageUrl string
	Connections        *connections.ConnectionsModuleConfig
}

type DidCommModule struct {
	config  *DidCommModuleConfig
	modules []di.Module
}

func NewDidCommModule(config *DidCommModuleConfig) *DidCommModule {
	if config == nil {
		config = &DidCommModuleConfig{}
	}
	modules := []di.Module{di.Module(oob.NewOutOfBandModule()), di.Module(connections.NewConnectionsModule(config.Connections))}
	return &DidCommModule{config: config, modules: modules}
}

func (m *DidCommModule) Register(dm di.DependencyManager) error {
	// Register config
	dm.RegisterInstance(di.Token{Name: "DidCommModuleConfig"}, m.config)
	// FeatureRegistry
	dm.RegisterSingleton(di.TokenFeatureRegistry, func(dm di.DependencyManager) (any, error) { return NewFeatureRegistry(), nil })
	// Sub-modules
	for _, module := range m.modules {
		if err := module.Register(dm); err != nil {
			return err
		}
	}
	// Default Logger
	dm.RegisterSingleton(di.TokenLogger, func(dm di.DependencyManager) (any, error) { return logger.NewDefaultLogger(logger.InfoLevel), nil })
	// Transport placeholders
	dm.RegisterSingleton(di.TokenMessageSender, func(dm di.DependencyManager) (any, error) { return nil, nil })
	dm.RegisterSingleton(di.TokenMessageReceiver, func(dm di.DependencyManager) (any, error) { return nil, nil })
	// ReceivedDidRepository
	dm.RegisterSingleton(di.TokenReceivedDidRepository, func(dm di.DependencyManager) (any, error) {
		any, err := dm.Resolve(di.TokenStorageService)
		if err != nil {
			return nil, err
		}
		storage, ok := any.(corestorage.StorageService)
		if !ok {
			return nil, fmt.Errorf("StorageService missing")
		}
		return receivedrepo.NewReceivedDidRepository(storage), nil
	})
	// EnvelopeService
	dm.RegisterSingleton(di.TokenEnvelopeService, func(dm di.DependencyManager) (any, error) {
		agentCtx, err := di.ResolveAs[*contextpkg.AgentContext](dm, di.TokenAgentContext)
		if err != nil {
			return nil, err
		}
		es := services.NewEnvelopeService(agentCtx)
		es.SetTypedDI(dm)
		return es, nil
	})
	// WalletService
	dm.RegisterSingleton(di.TokenWalletService, func(dm di.DependencyManager) (any, error) {
		storeAny, err := dm.Resolve(di.TokenStorageService)
		if err != nil {
			return nil, err
		}
		store, ok := storeAny.(corestorage.StorageService)
		if !ok {
			return nil, fmt.Errorf("StorageService missing")
		}
		agentCtx, err := di.ResolveAs[*contextpkg.AgentContext](dm, di.TokenAgentContext)
		if err != nil {
			return nil, err
		}
		repo := wallet.NewStorageKeyRepository(store)
		return wallet.NewWalletService(agentCtx, repo), nil
	})
	// DidCommDocumentService
	dm.RegisterSingleton(di.TokenDidCommDocumentService, func(dm di.DependencyManager) (any, error) { return services.NewDidCommDocumentService(), nil })
	// JwsService
	dm.RegisterSingleton(di.TokenJwsService, func(dm di.DependencyManager) (any, error) {
		wAny, err := dm.Resolve(di.TokenWalletService)
		if err != nil {
			return nil, err
		}
		walletSvc, _ := wAny.(*wallet.WalletService)
		return jws.NewJwsService(walletSvc), nil
	})
	return nil
}

// OnInitializeContext initializes all sub-modules
func (m *DidCommModule) OnInitializeContext(ctx *contextpkg.AgentContext) error {
	// Create and register transport services FIRST, before initializing sub-modules
	// This ensures the MessageHandlerRegistry is available for sub-modules to register handlers
	var dm di.DependencyManager
	if ctx != nil && ctx.DependencyManager != nil {
		if cast, ok := ctx.DependencyManager.(di.DependencyManager); ok {
			dm = cast
		}
	}
	if dm == nil {
		return fmt.Errorf("dependency manager not available on context")
	}
	// Resolve required services
	envelopeServiceAny, _ := dm.Resolve(di.TokenEnvelopeService)
	connectionServiceAny, _ := dm.Resolve(di.TokenConnectionService)
	envelopeService, _ := envelopeServiceAny.(*services.EnvelopeService)
	connectionService, _ := connectionServiceAny.(*connservices.ConnectionService)
	if envelopeService != nil && connectionService != nil {
		// Create dispatcher
		dispatcher := transport.NewDispatcher()
		// Create and register MessageHandlerRegistry
		messageHandlerRegistry := transport.NewMessageHandlerRegistry(dispatcher)
		dm.RegisterInstance(di.TokenMessageHandlerRegistry, messageHandlerRegistry)
		// Register all module handlers centrally
		registrations.RegisterAllModuleHandlers(messageHandlerRegistry)
		// Create message sender and receiver
		messageSender := transport.NewMessageSender(ctx, dm, envelopeService, connectionService)
		messageReceiver := transport.NewMessageReceiver(ctx, envelopeService, connectionService, dispatcher, dm)
		// Set message sender on dispatcher for handling responses
		dispatcher.SetMessageSender(messageSender)
		// Register default HTTP outbound transport directly
		messageSender.RegisterOutboundTransport(transport.NewHttpOutboundTransport())
		// Save instances for other modules
		dm.RegisterInstance(di.TokenMessageSender, messageSender)
		dm.RegisterInstance(di.TokenMessageReceiver, messageReceiver)
	}
	// Initialize sub-modules
	for _, module := range m.modules {
		if err := module.OnInitializeContext(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (m *DidCommModule) OnShutdown(ctx *contextpkg.AgentContext) error { return nil }
