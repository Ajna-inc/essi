package module

import (
	contextpkg "github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/core/di"
	"github.com/ajna-inc/essi/pkg/core/storage"
	dids "github.com/ajna-inc/essi/pkg/dids"
	"github.com/ajna-inc/essi/pkg/dids/api"
	keyresolver "github.com/ajna-inc/essi/pkg/dids/methods/key"
	peerresolver "github.com/ajna-inc/essi/pkg/dids/methods/peer"
	"github.com/ajna-inc/essi/pkg/dids/repository"
)

// DidsModuleConfig allows enabling built-in DID resolvers/registrars and adding custom ones.
type DidsModuleConfig struct {
	EnableDidKey  bool
	EnableDidPeer bool
	Resolvers     []dids.DidResolver
	Registrars    []dids.DidRegistrar
}

// DidsModule implements di.Module to register DID resolvers
type DidsModule struct {
	cfg DidsModuleConfig
	dm  di.DependencyManager
}

// NewDidsModule creates a new DID module with defaults (did:key and did:peer enabled)
func NewDidsModule(cfg *DidsModuleConfig) *DidsModule {
	defaultCfg := DidsModuleConfig{EnableDidKey: true, EnableDidPeer: true}
	if cfg != nil { defaultCfg = *cfg }
	return &DidsModule{cfg: defaultCfg}
}

func (m *DidsModule) Register(dm di.DependencyManager) error {
	m.dm = dm
	return nil
}

func (m *DidsModule) OnInitializeContext(ctx *contextpkg.AgentContext) error {
    resolver := dids.NewDidResolverService()
    registrar := dids.NewDidRegistrarService()
	if m.cfg.EnableDidKey { resolver.RegisterResolver(keyresolver.NewDidKeyResolver()) }
	if m.cfg.EnableDidPeer { 
		resolver.RegisterResolver(peerresolver.NewDidPeerResolver())
		registrar.RegisterRegistrar(peerresolver.NewPeerDidRegistrar())
	}
	for _, r := range m.cfg.Resolvers { if r != nil { resolver.RegisterResolver(r) } }
	for _, r := range m.cfg.Registrars { if r != nil { registrar.RegisterRegistrar(r) } }
	
	// Create DID repository if storage is available
	var didRepository repository.DidRepository
	if m.dm != nil {
		if storageAny, err := m.dm.Resolve(di.TokenStorageService); err == nil {
			if storageSvc, ok := storageAny.(storage.StorageService); ok {
				didRepository = repository.NewAskarDidRepository(storageSvc)
				// Register the repository in DI container for other modules to use
				m.dm.RegisterInstance(di.TokenDidRepository, didRepository)
			}
		}
	}
	
	// Register typed DidsApi with repository
	if m.dm != nil {
		didsApi := api.NewDidsApi(resolver, registrar, didRepository, ctx)
		m.dm.RegisterInstance(di.TokenDidsApi, didsApi)
		// Also register core DID services for other components (resolver/registrar)
		m.dm.RegisterInstance(di.TokenDidResolverService, resolver)
		m.dm.RegisterInstance(di.TokenDidRegistrarService, registrar)
	}
	return nil
}

func (m *DidsModule) OnShutdown(ctx *contextpkg.AgentContext) error { return nil }

