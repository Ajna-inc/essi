package connections

import (
	"fmt"

	"github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/core/di"
	"github.com/ajna-inc/essi/pkg/core/storage"
	"github.com/ajna-inc/essi/pkg/core/wallet"
	"github.com/ajna-inc/essi/pkg/didcomm/modules/connections/services"
	"github.com/ajna-inc/essi/pkg/dids/api"
)

// ConnectionsModuleConfig holds configuration for the connections module
type ConnectionsModuleConfig struct{}

// ConnectionsModule implements the connections protocol module
type ConnectionsModule struct{ dm di.DependencyManager }

func NewConnectionsModule(config *ConnectionsModuleConfig) *ConnectionsModule {
	return &ConnectionsModule{}
}

func (m *ConnectionsModule) Register(dm di.DependencyManager) error {
	m.dm = dm
	// Register ConnectionService with storage-backed repository and injected WalletService
	dm.RegisterSingleton(di.TokenConnectionService, func(dm di.DependencyManager) (any, error) {
		agentCtx, err := di.ResolveAs[*context.AgentContext](dm, di.TokenAgentContext)
		if err != nil {
			return nil, err
		}
		anyStore, err := dm.Resolve(di.TokenStorageService)
		if err != nil {
			return nil, err
		}
		store, ok := anyStore.(storage.StorageService)
		if !ok {
			return nil, fmt.Errorf("StorageService missing")
		}
		repo := services.NewStorageConnectionRepository(store)
		wAny, err := dm.Resolve(di.TokenWalletService)
		if err != nil {
			return nil, err
		}
		ws, _ := wAny.(*wallet.WalletService)
		connSvc := services.NewConnectionService(agentCtx, repo, ws)
		// Inject DidsApi
		if dAny, err := dm.Resolve(di.TokenDidsApi); err == nil {
			if da, ok := dAny.(*api.DidsApi); ok {
				connSvc.SetDidsApi(da)
			}
		}
		return connSvc, nil
	})
	// Register DidExchangeProtocol
	dm.RegisterSingleton(di.TokenDidExchangeProtocol, func(dm di.DependencyManager) (any, error) {
		cAny, err := dm.Resolve(di.TokenConnectionService)
		if err != nil {
			return nil, err
		}
		wAny, err := dm.Resolve(di.TokenWalletService)
		if err != nil {
			return nil, err
		}
		connSvc, _ := cAny.(*services.ConnectionService)
		ws, _ := wAny.(*wallet.WalletService)
		return services.NewDidExchangeProtocol(connSvc, ws), nil
	})
	return nil
}

func (m *ConnectionsModule) OnInitializeContext(ctx *context.AgentContext) error { return nil }

func (m *ConnectionsModule) OnShutdown(ctx *context.AgentContext) error { return nil }
