package operations

import (
	"fmt"
	"log"
	"time"

	"github.com/ajna-inc/essi/pkg/anoncreds"
	"github.com/ajna-inc/essi/pkg/anoncreds/registry"
	"github.com/ajna-inc/essi/pkg/askar"
	"github.com/ajna-inc/essi/pkg/core/agent"
	"github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/core/di"
	"github.com/ajna-inc/essi/pkg/didcomm"
	"github.com/ajna-inc/essi/pkg/didcomm/module"
	"github.com/ajna-inc/essi/pkg/didcomm/modules/credentials/formats"
	formatanoncreds "github.com/ajna-inc/essi/pkg/didcomm/modules/credentials/formats/anoncreds"
	"github.com/ajna-inc/essi/pkg/didcomm/modules/credentials/protocols"
	protocolv2 "github.com/ajna-inc/essi/pkg/didcomm/modules/credentials/protocols/v2"
	"github.com/ajna-inc/essi/pkg/dids"
	didsmodule "github.com/ajna-inc/essi/pkg/dids/module"
	kanonpkg "github.com/ajna-inc/essi/pkg/kanon"
	kandids "github.com/ajna-inc/essi/pkg/kanon/dids"
)

// AgentConfig holds configuration for agent setup
type AgentConfig struct {
	Label       string
	Host        string
	Port        int
	DBPath      string
	StoreID     string
	StoreKey    string
	KanonConfig kanonpkg.KanonModuleConfigOptions
}

// DefaultAgentConfig returns default configuration
func DefaultAgentConfig() *AgentConfig {
	return &AgentConfig{
		Label:    "e2e-issuer",
		Host:     "127.0.0.1",
		Port:     9002,
		DBPath:   "./kanon-test-askar.db",
		StoreID:  "kanon-test",
		StoreKey: "kanon-test-secure-key-123456",
		KanonConfig: kanonpkg.KanonModuleConfigOptions{
			Networks: []kanonpkg.NetworkConfig{{
				Network:         "testnet",
				RpcUrl:          "http://127.0.0.1:8545/",
				PrivateKey:      "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
				ChainId:         31337,
				ContractAddress: "0x5FbDB2315678afecb367f032d93F642f64180aa3",
			}},
		},
	}
}

// SetupAgent creates and initializes an agent with the given configuration
func SetupAgent(config *AgentConfig, metrics *Metrics) (*agent.Agent, error) {
	startTime := time.Now()
	defer func() {
		if metrics != nil {
			metrics.Record("agent_setup", time.Since(startTime))
		}
	}()

	endpoint := fmt.Sprintf("http://%s:%d", config.Host, config.Port)

	agentConfig := &context.AgentConfig{
		Label:       config.Label,
		InboundHost: config.Host,
		InboundPort: config.Port,
		Endpoints:   []string{endpoint},
	}

	modulesStart := time.Now()
	modules := createModules(config)
	if metrics != nil {
		metrics.Record("module_creation", time.Since(modulesStart))
	}
	log.Printf("  ⏱️  Module creation: %v", time.Since(modulesStart))

	agentCreateStart := time.Now()
	a, err := agent.NewAgent(&agent.AgentOptions{
		Config:  agentConfig,
		Modules: modules,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create agent: %w", err)
	}
	if metrics != nil {
		metrics.Record("agent_creation", time.Since(agentCreateStart))
	}
	log.Printf("  ⏱️  Agent creation: %v", time.Since(agentCreateStart))

	initStart := time.Now()
	if err := a.Initialize(); err != nil {
		return nil, fmt.Errorf("failed to initialize agent: %w", err)
	}
	if metrics != nil {
		metrics.Record("agent_initialization", time.Since(initStart))
	}
	log.Printf("  ⏱️  Agent initialization: %v", time.Since(initStart))

	return a, nil
}

func createModules(config *AgentConfig) []di.Module {
	askarModule := askar.NewAskarModuleBuilder().
		WithSQLiteDatabase(config.DBPath).
		WithStoreID(config.StoreID).
		WithStoreKey(config.StoreKey).
		Build()

	formatService := formatanoncreds.NewAnonCredsCredentialFormatService()
	v2Protocol := protocolv2.NewV2CredentialProtocol([]formats.CredentialFormatService{formatService})

	// Return modules in dependency order: Askar first, then Kanon (provides ledger), then others
	return []di.Module{
		askarModule,
		kanonpkg.KanonModule(config.KanonConfig),
		didsmodule.NewDidsModule(&didsmodule.DidsModuleConfig{
			EnableDidKey:  true,
			EnableDidPeer: true,
			Resolvers:     []dids.DidResolver{kandids.NewKanonDidResolver()},
			Registrars:    []dids.DidRegistrar{kandids.NewKanonDidRegistrar()},
		}),
		anoncreds.NewAnonCredsModule(&anoncreds.AnonCredsModuleConfig{
			Registries: []registry.Registry{kanonpkg.NewRegistry(nil)},
		}),
		didcomm.NewDidCommModule(nil),
		// ConnectionsModule and OobModule are already included in DidCommModule
		module.NewCredentialsModule(&module.CredentialsModuleConfig{
			AutoAcceptCredentials: "always",
			CredentialProtocols:   []protocols.CredentialProtocol{v2Protocol},
		}),
		module.NewProofsModule(&module.ProofsModuleConfig{
			AutoAcceptProofs: "always",
		}),
	}
}

// LogAgentStatus logs the current status of the agent (connections, credentials, etc.)
func LogAgentStatus(a *agent.Agent, metrics *Metrics) {
	startTime := time.Now()
	defer func() {
		if metrics != nil {
			metrics.Record("log_status", time.Since(startTime))
		}
	}()

	if conns, err := a.GetConnections(); err == nil {
		log.Printf("Existing connections: %d", len(conns))
		for _, c := range conns {
			log.Printf("  - ID: %s, State: %s, Their DID: %s, Endpoint: %s",
				c.ID, c.State, c.TheirDid, c.TheirEndpoint)
		}
	} else {
		log.Printf("Failed to list connections: %v", err)
	}

	if anonApi := a.AnonCreds(); anonApi != nil {
		if api, ok := anonApi.(*anoncreds.AnonCredsApi); ok {
			if creds, err := api.GetCredentials(nil); err == nil {
				log.Printf("Stored credentials: %d", len(creds))
				for _, ci := range creds {
					log.Printf("  - ID: %s, Schema: %s, CredDef: %s, Attrs: %v",
						ci.CredentialId, ci.SchemaId, ci.CredentialDefinitionId, ci.Attributes)
				}
			} else {
				log.Printf("Failed to list credentials: %v", err)
			}
		}
	}
}
