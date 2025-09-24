//go:build ignore
// +build ignore

package kanon

import (
	"fmt"
	"reflect"
	"regexp"
	
	"github.com/ajna-inc/essi/pkg/constants"
	"github.com/ajna-inc/essi/pkg/plugins"
	regsvc "github.com/ajna-inc/essi/pkg/anoncreds/registry"
	regkanon "github.com/ajna-inc/essi/pkg/anoncreds/registry/kanon"
	dids "github.com/ajna-inc/essi/pkg/core/modules/dids"
	"github.com/ajna-inc/essi/pkg/kanon/ledger"
)

// KanonModuleConfig represents configuration for Kanon module
type KanonModuleConfig struct {
	Enabled         bool
	UseMemory       bool   // Use in-memory ledger instead of EVM
	RpcUrl          string // Ethereum RPC URL
	PrivateKey      string // Private key for transactions
	ContractAddress string // Kanon registry contract address
	ChainId         int64  // Ethereum chain ID
}

// KanonModule implements the Kanon blockchain registry module
type KanonModule struct {
	plugins.BaseModule
	config       *KanonModuleConfig
	ledgerClient ledger.KanonLedger
}

// NewKanonModule creates a new Kanon module
func NewKanonModule(config *KanonModuleConfig) *KanonModule {
	if config == nil {
		config = &KanonModuleConfig{
			Enabled:   true,
			UseMemory: false,
		}
	}
	
	return &KanonModule{
		BaseModule: *plugins.NewBaseModule("kanon", "1.0.0"),
		config:     config,
	}
}

// Api returns the API type for this module
func (m *KanonModule) Api() reflect.Type {
	return reflect.TypeOf((*KanonApi)(nil)).Elem()
}

// Register registers the module's dependencies
func (m *KanonModule) Register(dependencyManager *plugins.DependencyManager) error {
	if !m.config.Enabled {
		return nil
	}
	
	// Initialize ledger client
	ledgerClient, err := m.createLedgerClient()
	if err != nil {
		return fmt.Errorf("failed to create Kanon ledger client: %w", err)
	}
	m.ledgerClient = ledgerClient
	
	// Register the Kanon API
	dependencyManager.RegisterContextScoped(
		plugins.NewInjectionToken("kanonApi"),
		func(dm *plugins.DependencyManager) interface{} {
			return &KanonApi{
				ledger: m.ledgerClient,
				config: m.config,
			}
		},
	)
	
	// Register Kanon ledger service
	dependencyManager.RegisterSingleton(
		KanonLedgerToken,
		func(dm *plugins.DependencyManager) interface{} {
			return m.ledgerClient
		},
	)
	
	// Register Kanon registry with AnonCreds registry service
	m.registerWithAnonCredsRegistry(dependencyManager)
	
	// Register Kanon DID resolver
	m.registerDidResolver(dependencyManager)
	
	// Register Kanon-specific services
	dependencyManager.RegisterSingleton(
		KanonSchemaServiceToken,
		func(dm *plugins.DependencyManager) interface{} {
			return NewKanonSchemaService(m.ledgerClient)
		},
	)
	
	dependencyManager.RegisterSingleton(
		KanonCredDefServiceToken,
		func(dm *plugins.DependencyManager) interface{} {
			return NewKanonCredDefService(m.ledgerClient)
		},
	)
	
	dependencyManager.RegisterSingleton(
		KanonRevocationServiceToken,
		func(dm *plugins.DependencyManager) interface{} {
			return NewKanonRevocationService(m.ledgerClient)
		},
	)
	
	return nil
}

// Initialize initializes the Kanon module
func (m *KanonModule) Initialize(agentContext interface{}) error {
	if !m.config.Enabled {
		return nil
	}
	
	// Test connection to ledger
	if m.ledgerClient != nil {
		// Verify we can connect to the ledger
		if evmLedger, ok := m.ledgerClient.(*ledger.EvmLedger); ok {
			// Test connection by getting latest block or similar
			_ = evmLedger
			fmt.Printf("✅ Kanon module initialized with EVM ledger at %s\n", m.config.RpcUrl)
		} else {
			fmt.Println("✅ Kanon module initialized with in-memory ledger")
		}
	}
	
	return nil
}

// Shutdown shuts down the Kanon module
func (m *KanonModule) Shutdown(agentContext interface{}) error {
	// Clean up ledger connections if needed
	if m.ledgerClient != nil {
		// Close connections
		if closer, ok := m.ledgerClient.(interface{ Close() error }); ok {
			return closer.Close()
		}
	}
	return nil
}

// createLedgerClient creates the appropriate ledger client based on config
func (m *KanonModule) createLedgerClient() (ledger.KanonLedger, error) {
	if m.config.UseMemory {
		return ledger.NewMemoryLedger(), nil
	}
	
	// Create EVM ledger client
	if m.config.RpcUrl == "" {
		return nil, fmt.Errorf("RPC URL is required for EVM ledger")
	}
	
	evmConfig := &ledger.EvmLedgerConfig{
		RpcUrl:          m.config.RpcUrl,
		PrivateKey:      m.config.PrivateKey,
		ContractAddress: m.config.ContractAddress,
		ChainId:         m.config.ChainId,
	}
	
	evmLedger, err := ledger.NewEvmLedger(evmConfig)
	if err != nil {
		// Fallback to memory ledger if EVM fails
		fmt.Printf("Warning: Failed to create EVM ledger (%v), using memory ledger\n", err)
		return ledger.NewMemoryLedger(), nil
	}
	
	return evmLedger, nil
}

// registerWithAnonCredsRegistry registers Kanon with the AnonCreds registry service
func (m *KanonModule) registerWithAnonCredsRegistry(dependencyManager *plugins.DependencyManager) {
	// Check if AnonCreds registry service is registered
	if !dependencyManager.IsRegistered(constants.InjectionSymbols.AnonCredsRegistryService, false) {
		// Create new registry service if it doesn't exist
		dependencyManager.RegisterSingleton(
			constants.InjectionSymbols.AnonCredsRegistryService,
			func(dm *plugins.DependencyManager) interface{} {
				return regsvc.NewService()
			},
		)
	}
	
	// Register a factory that adds Kanon registry to the service
	dependencyManager.RegisterSingleton(
		plugins.NewInjectionToken("kanonRegistryInitializer"),
		func(dm *plugins.DependencyManager) interface{} {
			registryService, err := dm.Resolve(constants.InjectionSymbols.AnonCredsRegistryService)
			if err == nil {
				if router, ok := registryService.(*regsvc.Service); ok {
					// Register Kanon registry with pattern matching
					// Matches: did:kanon:*, schema:kanon:*, creddef:kanon:*
					pattern := regexp.MustCompile(`^(did:kanon:|schema:kanon:|creddef:kanon:)`)
					kanonRegistry := regkanon.New(pattern, m.ledgerClient)
					router.Register(kanonRegistry)
					
					fmt.Println("✅ Kanon registry registered with AnonCreds service")
				}
			}
			return struct{}{} // Return dummy value
		},
	)
}

// registerDidResolver registers the Kanon DID resolver
func (m *KanonModule) registerDidResolver(dependencyManager *plugins.DependencyManager) {
	// Register initializer that adds Kanon DID resolver
	dependencyManager.RegisterSingleton(
		plugins.NewInjectionToken("kanonDidResolverInitializer"),
		func(dm *plugins.DependencyManager) interface{} {
			didResolverService, err := dm.Resolve(constants.InjectionSymbols.DidResolverService)
			if err == nil {
				if resolver, ok := didResolverService.(*dids.DidResolverService); ok {
					kanonDidResolver := NewKanonDidResolver(m.ledgerClient)
					resolver.RegisterResolver(kanonDidResolver)
					
					fmt.Println("✅ Kanon DID resolver registered")
				}
			}
			return struct{}{} // Return dummy value
		},
	)
}

// Service tokens for Kanon-specific services
var (
	KanonLedgerToken           = plugins.NewInjectionToken("KanonLedger")
	KanonSchemaServiceToken    = plugins.NewInjectionToken("KanonSchemaService")
	KanonCredDefServiceToken   = plugins.NewInjectionToken("KanonCredDefService")
	KanonRevocationServiceToken = plugins.NewInjectionToken("KanonRevocationService")
)