package askar

import (
	"fmt"

	"github.com/Ajna-inc/askar-go"
)

// AskarModuleConfig represents the configuration for the Askar module
type AskarModuleConfig struct {
	Store *AskarStoreConfig `json:"store"`
}

// AskarStoreConfig represents the configuration for an Askar store
type AskarStoreConfig struct {
	ID                  string               `json:"id"`
	Key                 string               `json:"key"`
	KeyDerivationMethod askar.StoreKeyMethod `json:"keyDerivationMethod,omitempty"`
	Database            *AskarDatabaseConfig `json:"database,omitempty"`
}

// AskarDatabaseConfig represents database configuration
type AskarDatabaseConfig struct {
	Type   string                 `json:"type"` // "sqlite" or "postgres"
	Config map[string]interface{} `json:"config"`
}

// AskarSqliteConfig represents SQLite-specific configuration
type AskarSqliteConfig struct {
	Path     string `json:"path,omitempty"`
	InMemory bool   `json:"inMemory,omitempty"`
}

// AskarPostgresConfig represents PostgreSQL-specific configuration
type AskarPostgresConfig struct {
	Host         string `json:"host"`
	Port         int    `json:"port,omitempty"`
	User         string `json:"user"`
	Password     string `json:"password"`
	DatabaseName string `json:"databaseName"`
	Schema       string `json:"schema,omitempty"`
	AdminUser    string `json:"adminUser,omitempty"`
	AdminPass    string `json:"adminPassword,omitempty"`
}

// GetConnectionString returns the connection string for the database
func (c *AskarDatabaseConfig) GetConnectionString(storeID string) (string, error) {
	switch c.Type {
	case "sqlite":
		config := &AskarSqliteConfig{}
		if err := mapToStruct(c.Config, config); err != nil {
			return "", fmt.Errorf("invalid sqlite config: %w", err)
		}
		
		if config.InMemory {
			return fmt.Sprintf("sqlite://:memory:"), nil
		}
		
		if config.Path == "" {
			return "", fmt.Errorf("sqlite path is required when not using in-memory database")
		}
		
		return fmt.Sprintf("sqlite://%s", config.Path), nil
		
	case "postgres":
		config := &AskarPostgresConfig{}
		if err := mapToStruct(c.Config, config); err != nil {
			return "", fmt.Errorf("invalid postgres config: %w", err)
		}
		
		if config.Host == "" || config.User == "" || config.DatabaseName == "" {
			return "", fmt.Errorf("postgres host, user, and database name are required")
		}
		
		port := config.Port
		if port == 0 {
			port = 5432
		}
		
		connStr := fmt.Sprintf("postgres://%s:%s@%s:%d/%s",
			config.User, config.Password, config.Host, port, config.DatabaseName)
		
		if config.Schema != "" {
			connStr += fmt.Sprintf("?schema=%s", config.Schema)
		}
		
		return connStr, nil
		
	default:
		return "", fmt.Errorf("unsupported database type: %s", c.Type)
	}
}

// SetDefaults sets default values for the configuration
func (c *AskarStoreConfig) SetDefaults() {
	if c.KeyDerivationMethod == "" {
		c.KeyDerivationMethod = askar.KdfArgon2iMod
	}
	
	if c.Database == nil {
		c.Database = &AskarDatabaseConfig{
			Type: "sqlite",
			Config: map[string]interface{}{
				"inMemory": true,
			},
		}
	}
}

// Validate validates the configuration
func (c *AskarStoreConfig) Validate() error {
	if c.ID == "" {
		return fmt.Errorf("store ID is required")
	}
	
	if c.Key == "" {
		return fmt.Errorf("store key is required")
	}
	
	if c.Database == nil {
		return fmt.Errorf("database configuration is required")
	}
	
	// Validate key derivation method
	switch c.KeyDerivationMethod {
	case askar.KdfArgon2iMod, askar.KdfArgon2iInt, askar.KdfRaw, "":
		// Valid methods
	default:
		return fmt.Errorf("invalid key derivation method: %s", c.KeyDerivationMethod)
	}
	
	return nil
}

// mapToStruct is a helper to convert map to struct
func mapToStruct(m map[string]interface{}, v interface{}) error {
	// This is a simplified version. In production, use a library like mapstructure
	// For now, we'll handle basic cases manually
	switch target := v.(type) {
	case *AskarSqliteConfig:
		if path, ok := m["path"].(string); ok {
			target.Path = path
		}
		if inMemory, ok := m["inMemory"].(bool); ok {
			target.InMemory = inMemory
		}
		
	case *AskarPostgresConfig:
		if host, ok := m["host"].(string); ok {
			target.Host = host
		}
		if port, ok := m["port"].(float64); ok {
			target.Port = int(port)
		}
		if user, ok := m["user"].(string); ok {
			target.User = user
		}
		if password, ok := m["password"].(string); ok {
			target.Password = password
		}
		if dbName, ok := m["databaseName"].(string); ok {
			target.DatabaseName = dbName
		}
		if schema, ok := m["schema"].(string); ok {
			target.Schema = schema
		}
	}
	
	return nil
}