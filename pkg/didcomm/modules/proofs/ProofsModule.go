package proofs

import (
	"fmt"
	"log"

	"github.com/ajna-inc/essi/pkg/anoncreds/registry"
	"github.com/ajna-inc/essi/pkg/anoncreds/services"
	"github.com/ajna-inc/essi/pkg/anoncreds/services/holder"
	"github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/core/di"
	"github.com/ajna-inc/essi/pkg/core/events"
	"github.com/ajna-inc/essi/pkg/core/storage"
	"github.com/ajna-inc/essi/pkg/didcomm/modules/proofs/formats"
	"github.com/ajna-inc/essi/pkg/didcomm/modules/proofs/handlers"
	"github.com/ajna-inc/essi/pkg/didcomm/modules/proofs/messages"
	"github.com/ajna-inc/essi/pkg/didcomm/modules/proofs/models"
	"github.com/ajna-inc/essi/pkg/didcomm/modules/proofs/protocol"
	v2 "github.com/ajna-inc/essi/pkg/didcomm/modules/proofs/protocol/v2"
	"github.com/ajna-inc/essi/pkg/didcomm/modules/proofs/records"
	"github.com/ajna-inc/essi/pkg/didcomm/modules/proofs/repository"
	proofsvc "github.com/ajna-inc/essi/pkg/didcomm/modules/proofs/services"
	"github.com/ajna-inc/essi/pkg/didcomm/transport"
)

// ProofsModuleConfig contains the configuration for the proofs module
type ProofsModuleConfig struct {
	// AutoAcceptProofs defines the auto-acceptance strategy for proofs
	AutoAcceptProofs models.AutoAcceptProof

	// ProofProtocols defines the proof protocols to use
	ProofProtocols []protocol.ProofProtocol
}

// NewProofsModuleConfig creates a new ProofsModuleConfig with defaults
func NewProofsModuleConfig() *ProofsModuleConfig {
	return &ProofsModuleConfig{AutoAcceptProofs: models.AutoAcceptNever, ProofProtocols: []protocol.ProofProtocol{}}
}

// ProofsModule is the main module for handling proof presentations
type ProofsModule struct {
	config          *ProofsModuleConfig
	api             *ProofsApi
	dm              di.DependencyManager
	proofService    *proofsvc.ProofService
	proofRepository records.Repository
	formatServices  map[string]formats.ProofFormatService
}

// NewProofsModule creates a new ProofsModule
func NewProofsModule(config *ProofsModuleConfig) *ProofsModule {
	if config == nil {
		config = NewProofsModuleConfig()
	}
	return &ProofsModule{config: config}
}

// Register registers the module with typed DI
func (m *ProofsModule) Register(dm di.DependencyManager) error {
	m.dm = dm

	// Register module config
	dm.RegisterInstance(di.TokenProofsModuleConfig, m.config)

	// Register repository as singleton -
	// The repository will get StorageService and EventBus injected when created
	dm.RegisterSingleton(di.TokenProofsRepository, func(deps di.DependencyManager) (interface{}, error) {
		// Resolve storage service (provided by Askar) - REQUIRED, no fallback
		storageService, err := deps.Resolve(di.TokenStorageService)
		if err != nil {
			return nil, fmt.Errorf("StorageService is required for ProofRepository: %w", err)
		}

		// Resolve event bus
		var eventBus events.Bus
		if eb, err := deps.Resolve(di.TokenEventBus); err == nil {
			eventBus, _ = eb.(events.Bus)
		}

		// Create repository with injected dependencies
		return repository.NewProofRepository(
			storageService.(storage.StorageService),
			eventBus,
		), nil
	})

	return nil
}

// OnInitializeContext wires the API and registers it in typed DI
func (m *ProofsModule) OnInitializeContext(ctx *context.AgentContext) error {
	// Resolve repository
	var repo records.Repository
	if any, err := m.dm.Resolve(di.TokenProofsRepository); err == nil {
		repo, _ = any.(records.Repository)
	}
	m.proofRepository = repo

	// Resolve AnonCreds services
	var holderSvc services.AnonCredsHolderService
	if any, err := m.dm.Resolve(services.TokenAnonCredsHolderService); err == nil {
		holderSvc, _ = any.(services.AnonCredsHolderService)
	}

	var issuerSvc services.AnonCredsIssuerService
	if any, err := m.dm.Resolve(services.TokenAnonCredsIssuerService); err == nil {
		issuerSvc, _ = any.(services.AnonCredsIssuerService)
	}

	var verifierSvc services.AnonCredsVerifierService
	if any, err := m.dm.Resolve(services.TokenAnonCredsVerifierService); err == nil {
		verifierSvc, _ = any.(services.AnonCredsVerifierService)
	}

	var registrySvc registry.RegistryService
	if any, err := m.dm.Resolve(di.TokenRegistryService); err == nil {
		if svc, ok := any.(*registry.Service); ok {
			registrySvc = svc
			log.Printf("📍 [ProofsModule] Registry service instance: %p (registries: %d)", svc, len(svc.GetRegistries()))
		} else {
			log.Printf("❌ [ProofsModule] Failed to cast registry service, type: %T", any)
		}
	} else {
		log.Printf("❌ [ProofsModule] Failed to resolve registry service: %v", err)
	}

	var credentialRepo holder.CredentialRepository
	if any, err := m.dm.Resolve(di.TokenCredentialRepository); err == nil {
		credentialRepo, _ = any.(holder.CredentialRepository)
	}

	// Create format service with injected dependencies
	anonCredsFormat := formats.NewAnonCredsProofFormatService(
		holderSvc,
		issuerSvc,
		verifierSvc,
		registrySvc,
		credentialRepo,
	)

	// Register format service
	m.dm.RegisterInstance(di.TokenAnonCredsProofFormatService, anonCredsFormat)

	// Create proof service with all dependencies
	service := proofsvc.NewProofService(
		ctx,
		holderSvc,
		verifierSvc,
		registrySvc,
		repo,
		credentialRepo,
	)
	m.proofService = service
	m.dm.RegisterInstance(di.TokenProofsService, service)

	// Store format services
	m.formatServices = map[string]formats.ProofFormatService{
		"anoncreds": anonCredsFormat,
	}

	// Create V2ProofProtocol with repository and format services
	v2Protocol := v2.NewV2ProofProtocol(ctx, repo)
	v2Protocol.AddFormatService(anonCredsFormat)

	// Update config with the protocol
	m.config.ProofProtocols = []protocol.ProofProtocol{v2Protocol}

	// Initialize API
	m.api = NewProofsApi(ctx, m.config)
	m.api.SetTypedDI(m.dm)
	m.api.Initialize()
	m.dm.RegisterInstance(di.TokenProofsApi, m.api)

	// Register proof protocol handlers with the message handler registry
	if ctx.DependencyManager != nil {
		if dm, ok := ctx.DependencyManager.(di.DependencyManager); ok {
			if registryAny, err := dm.Resolve(di.TokenMessageHandlerRegistry); err == nil {
				if registry, ok := registryAny.(*transport.MessageHandlerRegistry); ok {
					// Register all proof protocol message handlers
					// Present Proof Protocol 2.0 handlers
					registry.RegisterMessageHandler(messages.ProposePresentationV2Type, handlers.ProposePresentationV2Handler)
					registry.RegisterMessageHandler(messages.RequestPresentationV2Type, handlers.RequestPresentationV2Handler)
					registry.RegisterMessageHandler(messages.PresentationV2Type, handlers.PresentationV2Handler)
					registry.RegisterMessageHandler(messages.AckPresentationV2Type, handlers.PresentationAckV2Handler)

					// Present Proof Protocol 1.0 handlers (if needed)
					registry.RegisterMessageHandler(messages.RequestPresentationV1Type, handlers.RequestPresentationV2Handler)

					log.Printf("✅ Registered proof protocol handlers")
				}
			}
		}
	}

	return nil
}

func (m *ProofsModule) OnShutdown(ctx *context.AgentContext) error { return nil }

// GetApi returns the ProofsApi for this module
func (m *ProofsModule) GetApi(ctx *context.AgentContext) *ProofsApi {
	if m.api == nil {
		m.api = NewProofsApi(ctx, m.config)
	}
	return m.api
}

// GetConfig returns the module configuration
func (m *ProofsModule) GetConfig() *ProofsModuleConfig { return m.config }
