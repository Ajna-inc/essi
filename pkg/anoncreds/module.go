package anoncreds

import (
	"fmt"
	"log"

	"github.com/Ajna-inc/anoncreds-go/pkg/anoncreds"
	issuercore "github.com/ajna-inc/essi/pkg/anoncreds/issuer"
	regsvc "github.com/ajna-inc/essi/pkg/anoncreds/registry"
	"github.com/ajna-inc/essi/pkg/anoncreds/repository"
	"github.com/ajna-inc/essi/pkg/anoncreds/services"
	"github.com/ajna-inc/essi/pkg/anoncreds/services/holder"
	svcissuer "github.com/ajna-inc/essi/pkg/anoncreds/services/issuer"
	"github.com/ajna-inc/essi/pkg/anoncreds/services/verifier"
	"github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/core/di"
	"github.com/ajna-inc/essi/pkg/core/storage"
)

// AnonCredsModuleConfig holds configuration for the AnonCreds module
type AnonCredsModuleConfig struct {
	// AnonCreds library instance (from anoncreds-go)
	AnonCredsLib interface{}

	// Optional: Custom implementations
	HolderService   services.AnonCredsHolderService
	IssuerService   services.AnonCredsIssuerService
	VerifierService services.AnonCredsVerifierService
	// Optional: registries to register with the anoncreds router (TS-like)
	// Instances can be provided directly, and will be initialized with typed DI
	// if they implement an optional InitializeWithDI(di.DependencyManager) method.
	Registries []regsvc.Registry
}

// AnonCredsModule implements the module interface for AnonCreds functionality
type AnonCredsModule struct {
	config *AnonCredsModuleConfig
	api    *AnonCredsApi
	dm     di.DependencyManager
}

// NewAnonCredsModule creates a new AnonCreds module
func NewAnonCredsModule(config *AnonCredsModuleConfig) *AnonCredsModule {
	if config == nil {
		config = &AnonCredsModuleConfig{}
	}

	return &AnonCredsModule{
		config: config,
	}
}

// NO LONGER USING LEGACY DI - Removed RegisterLegacy method

// Register implements di.Module to support typed DI
func (m *AnonCredsModule) Register(dm di.DependencyManager) error {
	m.dm = dm

	// Initialize AnonCreds library if not provided
	if m.config.AnonCredsLib == nil {
		m.config.AnonCredsLib = anoncreds.New()
	}

	// Register holder service
	var holderSvc services.AnonCredsHolderService
	if m.config.HolderService != nil {
		holderSvc = m.config.HolderService
	} else {
		holderSvc = holder.NewAnonCredsRsHolderService(m.config.AnonCredsLib)
	}
	dm.RegisterInstance(services.TokenAnonCredsHolderService, holderSvc)

	// Register issuer service
	var issuerSvc services.AnonCredsIssuerService
	if m.config.IssuerService != nil {
		issuerSvc = m.config.IssuerService
	} else {
		issuerSvc = svcissuer.NewAnonCredsRsIssuerService(m.config.AnonCredsLib)
		if typed, ok := issuerSvc.(*svcissuer.AnonCredsRsIssuerService); ok {
			typed.SetTypedDI(dm)
		}
	}
	dm.RegisterInstance(services.TokenAnonCredsIssuerService, issuerSvc)

	// Register verifier service
	var verifierSvc services.AnonCredsVerifierService
	if m.config.VerifierService != nil {
		verifierSvc = m.config.VerifierService
	} else {
		verifierSvc = verifier.NewAnonCredsRsVerifierService(m.config.AnonCredsLib)
	}
	dm.RegisterInstance(services.TokenAnonCredsVerifierService, verifierSvc)

	// Register core issuer for CL keys
	coreIssuer := issuercore.NewIssuer()
	dm.RegisterInstance(di.TokenAnonCredsCoreIssuer, coreIssuer)

	// Create and register registry service
	registryRouter := regsvc.NewService()
	dm.RegisterInstance(di.TokenRegistryService, registryRouter)

	// Register credential repository for holder service
	dm.RegisterFactory(di.TokenCredentialRepository, func(deps di.DependencyManager) (interface{}, error) {
		if storageAny, err := deps.Resolve(di.TokenStorageService); err == nil {
			if storageSvc, ok := storageAny.(storage.StorageService); ok {
				return holder.NewAskarHolderCredentialRepository(storageSvc), nil
			}
		}
		return nil, nil
	})

	// Register repositories using typed DI (will be resolved when StorageService is available)
	dm.RegisterFactory(di.Token{Name: "CredentialDefinitionRepository"}, func(deps di.DependencyManager) (interface{}, error) {
		if storageAny, err := deps.Resolve(di.TokenStorageService); err == nil {
			if storageSvc, ok := storageAny.(storage.StorageService); ok {
				return repository.NewCredentialDefinitionRepository(storageSvc), nil
			}
		}
		return nil, nil
	})

	dm.RegisterFactory(di.Token{Name: "CredentialDefinitionPrivateRepository"}, func(deps di.DependencyManager) (interface{}, error) {
		if storageAny, err := deps.Resolve(di.TokenStorageService); err == nil {
			if storageSvc, ok := storageAny.(storage.StorageService); ok {
				return repository.NewCredentialDefinitionPrivateRepository(storageSvc), nil
			}
		}
		return nil, nil
	})

	dm.RegisterFactory(di.Token{Name: "KeyCorrectnessProofRepository"}, func(deps di.DependencyManager) (interface{}, error) {
		if storageAny, err := deps.Resolve(di.TokenStorageService); err == nil {
			if storageSvc, ok := storageAny.(storage.StorageService); ok {
				return repository.NewKeyCorrectnessProofRepository(storageSvc), nil
			}
		}
		return nil, nil
	})

	log.Println("✅ Registered AnonCreds repositories for credential definition persistence")

	return nil
}

// OnInitializeContext implements di.Module lifecycle
func (m *AnonCredsModule) OnInitializeContext(ctx *context.AgentContext) error {
	// Register high-level API in typed DI
	if m.dm != nil {
		api := NewAnonCredsApiWithDI(ctx, m.dm)
		m.dm.RegisterInstance(di.TokenAnonCredsApi, api)
	}

	// Register provided registries with the registry service
	if len(m.config.Registries) > 0 && m.dm != nil {
		log.Printf("🔍 [AnonCredsModule] Registering %d registries", len(m.config.Registries))
		if registryAny, err := m.dm.Resolve(di.TokenRegistryService); err == nil {
			if router, ok := registryAny.(*regsvc.Service); ok {
				log.Printf("📍 [AnonCredsModule] Registry service instance: %p", router)
				for i, reg := range m.config.Registries {
					if reg == nil {
						log.Printf("⚠️  [AnonCredsModule] Registry %d is nil, skipping", i)
						continue
					}
					// Optional DI initialization hook on registry
					if init, ok := reg.(interface {
						InitializeWithDI(di.DependencyManager) error
					}); ok {
						log.Printf("🔧 [AnonCredsModule] Initializing registry %d with DI", i)
						if err := init.InitializeWithDI(m.dm); err != nil {
							log.Printf("❌ [AnonCredsModule] Failed to initialize registry %d: %v", i, err)
						}
					}
					router.Register(reg)
					log.Printf("✅ [AnonCredsModule] Registered registry %d: %s", i, reg.MethodName())
				}
			} else {
				log.Printf("❌ [AnonCredsModule] Failed to cast registry service")
			}
		} else {
			log.Printf("❌ [AnonCredsModule] Failed to resolve TokenRegistryService: %v", err)
		}
	} else {
		log.Printf("⚠️  [AnonCredsModule] No registries to register or DM is nil")
	}

	// Wire holder repositories into the holder service
	if m.dm != nil {
		if any, err := m.dm.Resolve(services.TokenAnonCredsHolderService); err == nil {
			if holderSvc, ok := any.(*holder.AnonCredsRsHolderService); ok {
				// Resolve storage service and build repos
				var store storage.StorageService
				if sAny, err := m.dm.Resolve(di.TokenStorageService); err == nil {
					store, _ = sAny.(storage.StorageService)
				}
				var linkRepo holder.LinkSecretRepository
				var credRepo holder.CredentialRepository
				if store != nil {
					linkRepo = holder.NewAskarHolderLinkSecretRepository(store)
					credRepo = holder.NewAskarHolderCredentialRepository(store)
				}
				// Resolve registry service and wire router directly
				var regSvc holder.RegistryService
				if rAny, err := m.dm.Resolve(di.TokenRegistryService); err == nil {
					if router, ok := rAny.(*regsvc.Service); ok {
						regSvc = router
					}
				}
				holderSvc.SetRepositories(linkRepo, credRepo, regSvc)
			}
		}
	}
	return nil
}

// OnShutdown implements di.Module lifecycle
func (m *AnonCredsModule) OnShutdown(ctx *context.AgentContext) error {
	return nil
}

// GetApi returns the AnonCreds API instance
func (m *AnonCredsModule) GetApi(ctx *context.AgentContext) *AnonCredsApi {
	if m.api == nil {
		m.api = NewAnonCredsApi(ctx)
	}
	return m.api
}

// AnonCredsApi provides high-level API for AnonCreds operations
type AnonCredsApi struct {
	context         *context.AgentContext
	holderService   services.AnonCredsHolderService
	issuerService   services.AnonCredsIssuerService
	verifierService services.AnonCredsVerifierService
	typedDI         di.DependencyManager
}

// Constructors for AnonCredsApi
func NewAnonCredsApi(ctx *context.AgentContext) *AnonCredsApi {
	return &AnonCredsApi{context: ctx}
}

func NewAnonCredsApiWithDI(ctx *context.AgentContext, dm di.DependencyManager) *AnonCredsApi {
	api := &AnonCredsApi{context: ctx, typedDI: dm}
	if holderAny, err := dm.Resolve(services.TokenAnonCredsHolderService); err == nil {
		api.holderService, _ = holderAny.(services.AnonCredsHolderService)
	}
	if issuerAny, err := dm.Resolve(services.TokenAnonCredsIssuerService); err == nil {
		api.issuerService, _ = issuerAny.(services.AnonCredsIssuerService)
	}
	if verifierAny, err := dm.Resolve(services.TokenAnonCredsVerifierService); err == nil {
		api.verifierService, _ = verifierAny.(services.AnonCredsVerifierService)
	}
	return api
}

// API surface used by cmd/kanon-test
func (api *AnonCredsApi) GetCredentials(filter *services.CredentialFilter) ([]*services.AnonCredsCredentialInfo, error) {
	if api.holderService == nil {
		return nil, fmt.Errorf("holder service not available")
	}
	return api.holderService.GetCredentials(api.context, &services.GetCredentialsOptions{Filter: filter})
}

func (api *AnonCredsApi) RegisterSchema(opts regsvc.RegisterSchemaOptions) (regsvc.RegisterSchemaResult, error) {
	if api.typedDI == nil {
		return regsvc.RegisterSchemaResult{State: "failed", Reason: "di not available"}, nil
	}
	if any, err := api.typedDI.Resolve(di.TokenRegistryService); err == nil {
		if router, ok := any.(*regsvc.Service); ok {
			return router.RegisterSchema(opts)
		}
	}
	return regsvc.RegisterSchemaResult{State: "failed", Reason: "registry not available"}, nil
}

func (api *AnonCredsApi) RegisterCredentialDefinition(opts regsvc.RegisterCredentialDefinitionOptions) (regsvc.RegisterCredentialDefinitionResult, error) {
	if api.typedDI == nil {
		return regsvc.RegisterCredentialDefinitionResult{State: "failed", Reason: "di not available"}, nil
	}
	if any, err := api.typedDI.Resolve(di.TokenRegistryService); err == nil {
		if router, ok := any.(*regsvc.Service); ok {
			return router.RegisterCredentialDefinition(opts)
		}
	}
	return regsvc.RegisterCredentialDefinitionResult{State: "failed", Reason: "registry not available"}, nil
}

func (api *AnonCredsApi) GetHolderService() *holder.AnonCredsRsHolderService {
	if hs, ok := api.holderService.(*holder.AnonCredsRsHolderService); ok {
		return hs
	}
	return nil
}

func (api *AnonCredsApi) CreateCredential(opts *services.CreateCredentialOptions) (*services.CreateCredentialReturn, error) {
	if api.issuerService == nil {
		return nil, fmt.Errorf("issuer service not available")
	}
	return api.issuerService.CreateCredential(api.context, opts)
}
