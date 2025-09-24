package kanon

import (
	"fmt"
	"log"

	"github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/core/di"
	"github.com/ajna-inc/essi/pkg/kanon/ledger"
)

// KanonModuleConfigOptions holds configuration for the Kanon module
type KanonModuleConfigOptions struct {
	Networks []NetworkConfig
}

// NetworkConfig represents a network configuration
type NetworkConfig struct {
	Network    string
	RpcUrl     string
	PrivateKey string
	ChainId    int64
	ContractAddress string
}

// KanonModuleConfig holds the module configuration
type KanonModuleConfig struct {
	options KanonModuleConfigOptions
}

// KanonModuleConfigCreate creates a new configuration
func KanonModuleConfigCreate(options KanonModuleConfigOptions) *KanonModuleConfig {
	return &KanonModuleConfig{options: options}
}

// Networks returns the configured networks
func (c *KanonModuleConfig) Networks() []NetworkConfig {
	return c.options.Networks
}

// Module implements the Module interface following Credo-TS pattern
type Module struct {
	config *KanonModuleConfig
}

// KanonModule creates a new Kanon module
func KanonModule(configOptions KanonModuleConfigOptions) *Module {
	return &Module{ config: KanonModuleConfigCreate(configOptions) }
}

// Register implements di.Module to participate in typed DI
func (m *Module) Register(dm di.DependencyManager) error {
	// Register config
	dm.RegisterInstance(di.Token{Name: "KanonModuleConfig"}, m.config)

	// Require EVM ledger when RPC + contract are provided
	var kanonLedger ledger.KanonLedger
	if len(m.config.Networks()) > 0 {
		n := m.config.Networks()[0]
		cfg := Config{ RpcUrl: n.RpcUrl, PrivateKey: n.PrivateKey, ChainID: n.ChainId, ContractAddress: n.ContractAddress, Enabled: true }
		if cfg.RpcUrl == "" || cfg.ContractAddress == "" {
			return fmt.Errorf("KanonModule: missing rpcUrl or contractAddress in network config")
		}
		l := newEvmLedger(cfg)
		if l == nil {
			return fmt.Errorf("KanonModule: failed to initialize EVM ledger (check RPC and contract address)")
		}
		kanonLedger = l
	} else {
		return fmt.Errorf("KanonModule: no networks configured")
	}

	// Register typed DI instances for Kanon
	dm.RegisterInstance(di.TokenKanonLedger, kanonLedger)
	ethereumLedgerService := EthereumLedgerServiceCreate(m.config, kanonLedger)
	dm.RegisterInstance(di.TokenKanonEthereumLedgerService, ethereumLedgerService)

	// Do not auto-register the Kanon anoncreds registry here. It will be
	// supplied via AnonCredsModuleConfig.Registries factory to honor module order.

	log.Printf("Kanon module registered with %d networks", len(m.config.Networks()))
	return nil
}

// OnInitializeContext performs any post-registration initialization
func (m *Module) OnInitializeContext(agentContext *context.AgentContext) error {
	log.Println("Kanon module initialized successfully")
	return nil
}

// OnShutdown implements di.Module lifecycle
func (m *Module) OnShutdown(ctx *context.AgentContext) error { return nil }

// EthereumLedgerService provides ledger access following Credo-TS pattern
type EthereumLedgerService struct {
	config *KanonModuleConfig
	ledger ledger.KanonLedger
}

// EthereumLedgerServiceCreate creates a new Ethereum ledger service
func EthereumLedgerServiceCreate(config *KanonModuleConfig, ledger ledger.KanonLedger) *EthereumLedgerService {
	return &EthereumLedgerService{ config: config, ledger: ledger }
}

// GetLedger returns the underlying ledger
func (s *EthereumLedgerService) GetLedger() ledger.KanonLedger { return s.ledger }
// GetConfig returns the module config
func (s *EthereumLedgerService) GetConfig() *KanonModuleConfig { return s.config }
// GetNetworkConfig returns config for a specific network
func (s *EthereumLedgerService) GetNetworkConfig(network string) *NetworkConfig {
	for _, n := range s.config.Networks() { if n.Network == network { return &n } }
	return nil
}