package operations

import (
	"fmt"
	"log"
	"time"

	"github.com/ajna-inc/essi/pkg/anoncreds"
	"github.com/ajna-inc/essi/pkg/anoncreds/registry"
)

// SchemaOperations handles schema-related operations
type SchemaOperations struct {
	api     *anoncreds.AnonCredsApi
	metrics *Metrics
}

// NewSchemaOperations creates a new schema operations handler
func NewSchemaOperations(api *anoncreds.AnonCredsApi, metrics *Metrics) *SchemaOperations {
	return &SchemaOperations{
		api:     api,
		metrics: metrics,
	}
}

// SchemaConfig represents configuration for creating a schema
type SchemaConfig struct {
	ID         string
	Name       string
	Version    string
	Attributes []string
	IssuerDID  string
}

// DefaultSchemaConfig returns a default schema configuration
func DefaultSchemaConfig(issuerDID string) *SchemaConfig {
	return &SchemaConfig{
		Name:       "example",
		Version:    "1.0",
		Attributes: []string{"name", "age"},
		IssuerDID:  issuerDID,
	}
}

// RegisterSchema registers a new schema on the ledger
func (s *SchemaOperations) RegisterSchema(config *SchemaConfig) (string, error) {
	startTime := time.Now()
	defer func() {
		if s.metrics != nil {
			s.metrics.Record("register_schema", time.Since(startTime))
			s.metrics.LogTiming("register_schema", time.Since(startTime), config.Name, config.Version)
		}
	}()

	// Generate schema ID if not provided
	schemaID := config.ID
	if schemaID == "" {
		schemaID = s.GenerateSchemaID(config.Name, config.Version)
	}

	log.Printf("📋 Registering schema: %s", schemaID)
	log.Printf("   Name: %s, Version: %s", config.Name, config.Version)
	log.Printf("   Attributes: %v", config.Attributes)
	log.Printf("   Issuer: %s", config.IssuerDID)

	res, err := s.api.RegisterSchema(registry.RegisterSchemaOptions{
		Schema: registry.Schema{
			Id:        schemaID,
			Name:      config.Name,
			Version:   config.Version,
			AttrNames: config.Attributes,
			IssuerId:  config.IssuerDID,
		},
	})

	if err != nil {
		return "", fmt.Errorf("failed to register schema: %w", err)
	}

	if res.State != "finished" {
		return "", fmt.Errorf("schema registration failed: state=%s, reason=%s", res.State, res.Reason)
	}

	log.Printf("✅ Schema registered successfully: %s", res.SchemaId)
	return res.SchemaId, nil
}

// GenerateSchemaID generates a unique schema ID
func (s *SchemaOperations) GenerateSchemaID(name, version string) string {
	timestamp := time.Now().UnixNano()
	return fmt.Sprintf("schema:kanon:testnet:%s:%s-%d", name, version, timestamp)
}

// GenerateSchemaIDFixed generates a fixed schema ID (for testing caching)
func (s *SchemaOperations) GenerateSchemaIDFixed(name, version string) string {
	return fmt.Sprintf("schema:kanon:testnet:%s:%s", name, version)
}

// GetSchema retrieves a schema from the ledger
func (s *SchemaOperations) GetSchema(schemaID string) (*registry.Schema, error) {
	startTime := time.Now()
	defer func() {
		if s.metrics != nil {
			s.metrics.Record("get_schema", time.Since(startTime))
		}
	}()

	// This would typically call the registry service to get the schema
	// For now, we'll return an error as it's not fully implemented
	return nil, fmt.Errorf("GetSchema not implemented yet")
}

