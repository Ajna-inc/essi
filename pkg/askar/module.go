package askar

import (
	"fmt"

	"github.com/Ajna-inc/askar-go"
	"github.com/ajna-inc/essi/pkg/askar/kms"
	"github.com/ajna-inc/essi/pkg/askar/storage"
	"github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/core/di"
)

// AskarModule provides Askar-based storage and key management
type AskarModule struct {
	config       *AskarModuleConfig
	storeManager *AskarStoreManager
	kms          *kms.AskarKeyManagementService
	storage      *storage.AskarStorageService
	initialized  bool
	dm           di.DependencyManager
}

// NewAskarModule creates a new AskarModule
func NewAskarModule(config *AskarModuleConfig) *AskarModule {
	if config == nil {
		config = &AskarModuleConfig{}
	}
	
	if config.Store == nil {
		config.Store = &AskarStoreConfig{
			ID:  "default",
			Key: "default-key",
		}
	}
	
	config.Store.SetDefaults()
	
	return &AskarModule{
		config:       config,
		storeManager: NewAskarStoreManager(),
	}
}

// Register implements di.Module. Store DI manager for later use and register config.
func (m *AskarModule) Register(dm di.DependencyManager) error {
	m.dm = dm
	dm.RegisterInstance(di.Token{Name: "AskarModuleConfig"}, m.config)
	// Eagerly set up storage so it is available at agent construction time
	if !m.initialized {
		if err := m.config.Store.Validate(); err == nil {
			_ = m.provisionStore()
			m.kms = kms.NewAskarKeyManagementService(m.storeManager, m.config.Store.ID)
			m.storage = storage.NewAskarStorageService(m.storeManager, m.config.Store.ID)
			m.initialized = true
		}
	}
	if m.kms != nil { dm.RegisterInstance(di.TokenKeyManagementService, m.kms) }
	if m.storage != nil { dm.RegisterInstance(di.TokenStorageService, m.storage) }
	dm.RegisterInstance(di.Token{Name: "AskarStoreManager"}, m.storeManager)
	return nil
}

// OnInitializeContext implements di.Module and delegates to Initialize.
func (m *AskarModule) OnInitializeContext(ctx *context.AgentContext) error {
	return m.Initialize(ctx)
}

// OnShutdown implements di.Module and delegates to Shutdown.
func (m *AskarModule) OnShutdown(ctx *context.AgentContext) error {
	return m.Shutdown()
}

// Initialize initializes the Askar module
func (m *AskarModule) Initialize(ctx *context.AgentContext) error {
	if m.initialized {
		return nil
	}
	
	// Validate configuration
	if err := m.config.Store.Validate(); err != nil {
		return fmt.Errorf("invalid Askar configuration: %w", err)
	}
	
	// Provision or open the store
	if err := m.provisionStore(); err != nil {
		return fmt.Errorf("failed to provision Askar store: %w", err)
	}
	
	m.kms = kms.NewAskarKeyManagementService(m.storeManager, m.config.Store.ID)
	
	m.storage = storage.NewAskarStorageService(m.storeManager, m.config.Store.ID)
	
	m.initialized = true
	
	// Register into typed DI if available
	if m.dm != nil {
		m.dm.RegisterInstance(di.TokenKeyManagementService, m.kms)
		m.dm.RegisterInstance(di.TokenStorageService, m.storage)
		m.dm.RegisterInstance(di.Token{Name: "AskarStoreManager"}, m.storeManager)
	}
	
	return nil
}

// provisionStore provisions or opens the Askar store
func (m *AskarModule) provisionStore() error {
	// Try to open existing store first
	store, err := m.storeManager.OpenStore(m.config.Store)
	if err != nil {
		// If opening fails, try to provision
		if err := m.storeManager.ProvisionStore(m.config.Store); err != nil {
			return err
		}
		
		// Get the provisioned store
		store, err = m.storeManager.GetStore(m.config.Store.ID)
		if err != nil {
			return err
		}
	}
	
	// Store is now open and ready
	_ = store
	
	return nil
}


// GetStoreManager returns the store manager
func (m *AskarModule) GetStoreManager() *AskarStoreManager {
	return m.storeManager
}

// GetKMS returns the key management service
func (m *AskarModule) GetKMS() *kms.AskarKeyManagementService {
	return m.kms
}

// GetStorageService returns the storage service
func (m *AskarModule) GetStorageService() *storage.AskarStorageService {
	return m.storage
}

// Shutdown shuts down the module
func (m *AskarModule) Shutdown() error {
	if !m.initialized {
		return nil
	}
	
	if err := m.storeManager.CloseAll(); err != nil {
		return fmt.Errorf("failed to close stores: %w", err)
	}
	
	m.initialized = false
	return nil
}

// IsInitialized returns whether the module is initialized
func (m *AskarModule) IsInitialized() bool {
	return m.initialized
}

// GetConfig returns the module configuration
func (m *AskarModule) GetConfig() *AskarModuleConfig {
	return m.config
}

// CreateProfile creates a new profile in the store
func (m *AskarModule) CreateProfile(profileName string) error {
	if !m.initialized {
		return fmt.Errorf("module not initialized")
	}
	
	return m.storeManager.CreateProfile(m.config.Store.ID, profileName)
}

// RemoveProfile removes a profile from the store
func (m *AskarModule) RemoveProfile(profileName string) error {
	if !m.initialized {
		return fmt.Errorf("module not initialized")
	}
	
	return m.storeManager.RemoveProfile(m.config.Store.ID, profileName)
}

// ListProfiles lists all profiles in the store
func (m *AskarModule) ListProfiles() ([]string, error) {
	if !m.initialized {
		return nil, fmt.Errorf("module not initialized")
	}
	
	return m.storeManager.ListProfiles(m.config.Store.ID)
}

// RotateStoreKey rotates the encryption key for the store
func (m *AskarModule) RotateStoreKey(newKey string, newKeyMethod askar.StoreKeyMethod) error {
	if !m.initialized {
		return fmt.Errorf("module not initialized")
	}
	
	return m.storeManager.RotateStoreKey(m.config.Store.ID, newKey, newKeyMethod)
}

// ExportStore exports the store to a new location
func (m *AskarModule) ExportStore(targetConfig *AskarStoreConfig) error {
	if !m.initialized {
		return fmt.Errorf("module not initialized")
	}
	
	// Get current store
	store, err := m.storeManager.GetStore(m.config.Store.ID)
	if err != nil {
		return err
	}
	
	// Copy to new location
	targetURI, err := targetConfig.Database.GetConnectionString(targetConfig.ID)
	if err != nil {
		return err
	}
	
	newStore, err := store.Copy(targetURI, targetConfig.KeyDerivationMethod, targetConfig.Key, false)
	if err != nil {
		return fmt.Errorf("failed to export store: %w", err)
	}
	
	return newStore.Close()
}

// ImportStore imports a store from another location
func (m *AskarModule) ImportStore(sourceConfig *AskarStoreConfig) error {
	// This would replace the current store with the imported one
	// Implementation depends on specific requirements
	
	if err := m.storeManager.CloseStore(m.config.Store.ID); err != nil {
		return err
	}
	
	// Open the source store
	sourceStore, err := m.storeManager.OpenStore(sourceConfig)
	if err != nil {
		return err
	}
	
	// Copy to current location
	targetURI, err := m.config.Store.Database.GetConnectionString(m.config.Store.ID)
	if err != nil {
		return err
	}
	
	newStore, err := sourceStore.Copy(
		targetURI,
		m.config.Store.KeyDerivationMethod,
		m.config.Store.Key,
		true, // Recreate
	)
	if err != nil {
		return fmt.Errorf("failed to import store: %w", err)
	}
	
	// Close source store
	m.storeManager.CloseStore(sourceConfig.ID)
	
	// Register the new store
	m.storeManager.stores[m.config.Store.ID] = &ManagedStore{
		Store:  newStore,
		Config: m.config.Store,
	}
	
	return nil
}

// GetStoreStatus returns the status of the store
func (m *AskarModule) GetStoreStatus() map[string]interface{} {
	status := map[string]interface{}{
		"initialized": m.initialized,
		"storeId":     m.config.Store.ID,
	}
	
	if m.initialized {
		status["storeOpen"] = m.storeManager.IsStoreOpen(m.config.Store.ID)
		
		// Try to get profiles
		if profiles, err := m.ListProfiles(); err == nil {
			status["profiles"] = profiles
			status["profileCount"] = len(profiles)
		}
	}
	
	return status
}

// AskarModuleBuilder provides a builder pattern for creating AskarModule
type AskarModuleBuilder struct {
	config *AskarModuleConfig
}

// NewAskarModuleBuilder creates a new builder
func NewAskarModuleBuilder() *AskarModuleBuilder {
	return &AskarModuleBuilder{
		config: &AskarModuleConfig{},
	}
}

// WithStore sets the store configuration
func (b *AskarModuleBuilder) WithStore(store *AskarStoreConfig) *AskarModuleBuilder {
	b.config.Store = store
	return b
}

// WithStoreID sets the store ID
func (b *AskarModuleBuilder) WithStoreID(id string) *AskarModuleBuilder {
	if b.config.Store == nil {
		b.config.Store = &AskarStoreConfig{}
	}
	b.config.Store.ID = id
	return b
}

// WithStoreKey sets the store encryption key
func (b *AskarModuleBuilder) WithStoreKey(key string) *AskarModuleBuilder {
	if b.config.Store == nil {
		b.config.Store = &AskarStoreConfig{}
	}
	b.config.Store.Key = key
	return b
}

// WithInMemoryDatabase sets the store to use in-memory SQLite
func (b *AskarModuleBuilder) WithInMemoryDatabase() *AskarModuleBuilder {
	if b.config.Store == nil {
		b.config.Store = &AskarStoreConfig{}
	}
	b.config.Store.Database = &AskarDatabaseConfig{
		Type: "sqlite",
		Config: map[string]interface{}{
			"inMemory": true,
		},
	}
	return b
}

// WithSQLiteDatabase sets the store to use file-based SQLite
func (b *AskarModuleBuilder) WithSQLiteDatabase(path string) *AskarModuleBuilder {
	if b.config.Store == nil {
		b.config.Store = &AskarStoreConfig{}
	}
	b.config.Store.Database = &AskarDatabaseConfig{
		Type: "sqlite",
		Config: map[string]interface{}{
			"path": path,
		},
	}
	return b
}

// WithPostgresDatabase sets the store to use PostgreSQL
func (b *AskarModuleBuilder) WithPostgresDatabase(host string, port int, user, password, dbName string) *AskarModuleBuilder {
	if b.config.Store == nil {
		b.config.Store = &AskarStoreConfig{}
	}
	b.config.Store.Database = &AskarDatabaseConfig{
		Type: "postgres",
		Config: map[string]interface{}{
			"host":         host,
			"port":         port,
			"user":         user,
			"password":     password,
			"databaseName": dbName,
		},
	}
	return b
}

// Build creates the AskarModule
func (b *AskarModuleBuilder) Build() *AskarModule {
	return NewAskarModule(b.config)
}