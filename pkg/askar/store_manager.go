package askar

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/Ajna-inc/askar-go"
	"github.com/ajna-inc/essi/pkg/askar/errors"
	"github.com/ajna-inc/essi/pkg/core/context"
)

// AskarStoreManager manages Askar store instances and their lifecycle
type AskarStoreManager struct {
	stores map[string]*ManagedStore
	mutex  sync.RWMutex
}

// ManagedStore represents a managed Askar store with its configuration
type ManagedStore struct {
	Store  *askar.Store
	Config *AskarStoreConfig
	mutex  sync.RWMutex
}

// NewAskarStoreManager creates a new AskarStoreManager
func NewAskarStoreManager() *AskarStoreManager {
	return &AskarStoreManager{
		stores: make(map[string]*ManagedStore),
	}
}

// ProvisionStore creates and opens a new Askar store
func (m *AskarStoreManager) ProvisionStore(config *AskarStoreConfig) error {
	if config == nil {
		return errors.NewAskarError(errors.ErrCodeInvalidConfig, "store config is required", nil)
	}
	
	// Set defaults and validate
	config.SetDefaults()
	if err := config.Validate(); err != nil {
		return errors.NewAskarError(errors.ErrCodeInvalidConfig, err.Error(), err)
	}
	
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	// Check if store already exists
	if _, exists := m.stores[config.ID]; exists {
		return errors.ErrStoreAlreadyExists
	}
	
	// Get connection string
	connStr, err := config.Database.GetConnectionString(config.ID)
	if err != nil {
		return errors.NewAskarError(errors.ErrCodeInvalidConfig, "failed to get connection string", err)
	}
	
	// Create directory if needed for file-based SQLite
	if config.Database.Type == "sqlite" && !isInMemory(config.Database) {
		if err := m.ensureDirectoryExists(config.Database); err != nil {
			return err
		}
	}
	
	// Provision the store
	store, err := askar.StoreProvision(
		connStr,
		config.KeyDerivationMethod,
		config.Key,
		"", // default profile
		false, // don't recreate if exists
	)
	if err != nil {
		return errors.WrapAskarError(err)
	}
	
	// Store the managed store
	m.stores[config.ID] = &ManagedStore{
		Store:  store,
		Config: config,
	}
	
	return nil
}

// OpenStore opens an existing Askar store
func (m *AskarStoreManager) OpenStore(config *AskarStoreConfig) (*askar.Store, error) {
	if config == nil {
		return nil, errors.NewAskarError(errors.ErrCodeInvalidConfig, "store config is required", nil)
	}
	
	// Set defaults and validate
	config.SetDefaults()
	if err := config.Validate(); err != nil {
		return nil, errors.NewAskarError(errors.ErrCodeInvalidConfig, err.Error(), err)
	}
	
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	// Check if store is already open
	if managed, exists := m.stores[config.ID]; exists {
		return managed.Store, nil
	}
	
	// Get connection string
	connStr, err := config.Database.GetConnectionString(config.ID)
	if err != nil {
		return nil, errors.NewAskarError(errors.ErrCodeInvalidConfig, "failed to get connection string", err)
	}
	
	// Open the store
	store, err := askar.StoreOpen(
		connStr,
		config.KeyDerivationMethod,
		config.Key,
		"", // default profile
	)
	if err != nil {
		return nil, errors.WrapAskarError(err)
	}
	
	// Store the managed store
	m.stores[config.ID] = &ManagedStore{
		Store:  store,
		Config: config,
	}
	
	return store, nil
}

// GetStore returns an open store by ID
func (m *AskarStoreManager) GetStore(storeID string) (*askar.Store, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	
	managed, exists := m.stores[storeID]
	if !exists {
		return nil, errors.ErrStoreNotFound
	}
	
	return managed.Store, nil
}

// CloseStore closes an open store
func (m *AskarStoreManager) CloseStore(storeID string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	managed, exists := m.stores[storeID]
	if !exists {
		return errors.ErrStoreNotFound
	}
	
	if err := managed.Store.Close(); err != nil {
		return errors.WrapAskarError(err)
	}
	
	delete(m.stores, storeID)
	return nil
}

// DeleteStore removes a store permanently
func (m *AskarStoreManager) DeleteStore(config *AskarStoreConfig) error {
	if config == nil {
		return errors.NewAskarError(errors.ErrCodeInvalidConfig, "store config is required", nil)
	}
	
	// Close the store if it's open
	m.mutex.Lock()
	if managed, exists := m.stores[config.ID]; exists {
		if err := managed.Store.Close(); err != nil {
			m.mutex.Unlock()
			return errors.WrapAskarError(err)
		}
		delete(m.stores, config.ID)
	}
	m.mutex.Unlock()
	
	// Get connection string
	connStr, err := config.Database.GetConnectionString(config.ID)
	if err != nil {
		return errors.NewAskarError(errors.ErrCodeInvalidConfig, "failed to get connection string", err)
	}
	
	// Remove the store
	if err := askar.StoreRemove(connStr); err != nil {
		return errors.WrapAskarError(err)
	}
	
	return nil
}

// WithSession executes a function within a session
func (m *AskarStoreManager) WithSession(ctx *context.AgentContext, storeID string, fn func(*askar.Session) error) error {
	store, err := m.GetStore(storeID)
	if err != nil {
		return err
	}
	
	session, err := store.Session("")
	if err != nil {
		return errors.WrapAskarError(err)
	}
	defer session.Close()
	
	return fn(session)
}

// WithTransaction executes a function within a transaction
func (m *AskarStoreManager) WithTransaction(ctx *context.AgentContext, storeID string, fn func(*askar.Session) error) error {
	store, err := m.GetStore(storeID)
	if err != nil {
		return err
	}
	
	session, err := store.Transaction("")
	if err != nil {
		return errors.WrapAskarError(err)
	}
	
	// Execute the function
	if err := fn(session); err != nil {
		// Rollback on error
		session.Close()
		return errors.NewAskarError(errors.ErrCodeTransactionFailed, "transaction failed", err)
	}
	
	// Commit the transaction
	if err := session.Commit(); err != nil {
		session.Close()
		return errors.WrapAskarError(err)
	}
	
	return nil
}

// IsStoreOpen checks if a store is currently open
func (m *AskarStoreManager) IsStoreOpen(storeID string) bool {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	
	_, exists := m.stores[storeID]
	return exists
}

// GetOpenStores returns a list of currently open store IDs
func (m *AskarStoreManager) GetOpenStores() []string {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	
	ids := make([]string, 0, len(m.stores))
	for id := range m.stores {
		ids = append(ids, id)
	}
	return ids
}

// CloseAll closes all open stores
func (m *AskarStoreManager) CloseAll() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	var lastErr error
	for id, managed := range m.stores {
		if err := managed.Store.Close(); err != nil {
			lastErr = errors.WrapAskarError(err)
		}
		delete(m.stores, id)
	}
	
	return lastErr
}

// RotateStoreKey changes the encryption key for a store
func (m *AskarStoreManager) RotateStoreKey(storeID string, newKey string, newKeyMethod askar.StoreKeyMethod) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	managed, exists := m.stores[storeID]
	if !exists {
		return errors.ErrStoreNotFound
	}
	
	if err := managed.Store.Rekey(newKeyMethod, newKey); err != nil {
		return errors.WrapAskarError(err)
	}
	
	// Update the stored configuration
	managed.Config.Key = newKey
	managed.Config.KeyDerivationMethod = newKeyMethod
	
	return nil
}

// ensureDirectoryExists creates the directory for SQLite database if needed
func (m *AskarStoreManager) ensureDirectoryExists(dbConfig *AskarDatabaseConfig) error {
	sqliteConfig := &AskarSqliteConfig{}
	if err := mapToStruct(dbConfig.Config, sqliteConfig); err != nil {
		return errors.NewAskarError(errors.ErrCodeInvalidConfig, "invalid sqlite config", err)
	}
	
	if sqliteConfig.Path != "" {
		dir := filepath.Dir(sqliteConfig.Path)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return errors.NewAskarError(errors.ErrCodeStorageOperation, 
				fmt.Sprintf("failed to create directory %s", dir), err)
		}
	}
	
	return nil
}

// isInMemory checks if the database configuration is for an in-memory database
func isInMemory(dbConfig *AskarDatabaseConfig) bool {
	if dbConfig.Type != "sqlite" {
		return false
	}
	
	sqliteConfig := &AskarSqliteConfig{}
	if err := mapToStruct(dbConfig.Config, sqliteConfig); err != nil {
		return false
	}
	
	return sqliteConfig.InMemory
}

// GetStoreConfig returns the configuration for a store
func (m *AskarStoreManager) GetStoreConfig(storeID string) (*AskarStoreConfig, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	
	managed, exists := m.stores[storeID]
	if !exists {
		return nil, errors.ErrStoreNotFound
	}
	
	return managed.Config, nil
}

// CreateProfile creates a new profile in the store
func (m *AskarStoreManager) CreateProfile(storeID string, profileName string) error {
	store, err := m.GetStore(storeID)
	if err != nil {
		return err
	}
	
	if err := store.CreateProfile(profileName); err != nil {
		return errors.WrapAskarError(err)
	}
	
	return nil
}

// RemoveProfile removes a profile from the store
func (m *AskarStoreManager) RemoveProfile(storeID string, profileName string) error {
	store, err := m.GetStore(storeID)
	if err != nil {
		return err
	}
	
	if err := store.RemoveProfile(profileName); err != nil {
		return errors.WrapAskarError(err)
	}
	
	return nil
}

// ListProfiles lists all profiles in the store
func (m *AskarStoreManager) ListProfiles(storeID string) ([]string, error) {
	store, err := m.GetStore(storeID)
	if err != nil {
		return nil, err
	}
	
	profiles, err := store.ListProfiles()
	if err != nil {
		return nil, errors.WrapAskarError(err)
	}
	
	return profiles, nil
}