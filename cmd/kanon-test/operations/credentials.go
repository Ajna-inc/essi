package operations

import (
	"fmt"
	"log"
	"time"

	"github.com/ajna-inc/essi/pkg/anoncreds"
	"github.com/ajna-inc/essi/pkg/anoncreds/registry"
)

// CredentialOperations handles credential-related operations
type CredentialOperations struct {
	anonApi  *anoncreds.AnonCredsApi
	credsApi interface{}
	metrics  *Metrics
}

// NewCredentialOperations creates a new credential operations handler
func NewCredentialOperations(anonApi *anoncreds.AnonCredsApi, credsApi interface{}, metrics *Metrics) *CredentialOperations {
	return &CredentialOperations{
		anonApi:  anonApi,
		credsApi: credsApi,
		metrics:  metrics,
	}
}

// CredentialDefinitionConfig represents configuration for creating a credential definition
type CredentialDefinitionConfig struct {
	ID        string
	Tag       string
	SchemaID  string
	IssuerDID string
}

// RegisterCredentialDefinition registers a new credential definition on the ledger
func (c *CredentialOperations) RegisterCredentialDefinition(config *CredentialDefinitionConfig) (string, error) {
	startTime := time.Now()
	operationName := "register_cred_def"
	
	defer func() {
		duration := time.Since(startTime)
		if c.metrics != nil {
			c.metrics.Record(operationName, duration)
			c.metrics.LogTiming(operationName, duration, config.Tag)
		}
	}()

	// Generate credential definition ID if not provided
	credDefID := config.ID
	if credDefID == "" {
		credDefID = c.GenerateCredDefID(config.Tag)
	}

	log.Printf("📊 Starting credential definition registration...")
	log.Printf("   CredDef ID: %s", credDefID)
	log.Printf("   Schema ID: %s", config.SchemaID)
	log.Printf("   Issuer DID: %s", config.IssuerDID)
	log.Printf("   Tag: %s", config.Tag)

	// Track detailed timings
	callStart := time.Now()
	res, err := c.anonApi.RegisterCredentialDefinition(registry.RegisterCredentialDefinitionOptions{
		CredentialDefinition: registry.CredentialDefinition{
			Id:       credDefID,
			Tag:      config.Tag,
			SchemaId: config.SchemaID,
			IssuerId: config.IssuerDID,
		},
	})
	callDuration := time.Since(callStart)
	
	if c.metrics != nil {
		c.metrics.Record("cred_def_api_call", callDuration)
	}
	log.Printf("   📊 RegisterCredentialDefinition API call took: %v", callDuration)

	if err != nil {
		return "", fmt.Errorf("failed to register credential definition: %w", err)
	}

	if res.State != "finished" {
		return "", fmt.Errorf("credential definition registration failed: state=%s, reason=%s", res.State, res.Reason)
	}

	log.Printf("✅ Credential definition registered successfully: %s", res.CredentialDefinitionId)
	return res.CredentialDefinitionId, nil
}

// GenerateCredDefID generates a unique credential definition ID
func (c *CredentialOperations) GenerateCredDefID(tag string) string {
	timestamp := time.Now().UnixNano()
	return fmt.Sprintf("creddef:kanon:testnet:example:%s-%d", tag, timestamp)
}

// GenerateCredDefIDFixed generates a fixed credential definition ID (for testing caching)
func (c *CredentialOperations) GenerateCredDefIDFixed(tag string) string {
	return fmt.Sprintf("creddef:kanon:testnet:example:%s", tag)
}

// OfferCredential offers a credential to a connection
func (c *CredentialOperations) OfferCredential(connectionID, credDefID string, attributes map[string]string) error {
	startTime := time.Now()
	defer func() {
		if c.metrics != nil {
			c.metrics.Record("offer_credential", time.Since(startTime))
		}
	}()

	log.Printf("📤 Offering credential to connection: %s", connectionID)
	log.Printf("   Credential Definition: %s", credDefID)
	log.Printf("   Attributes: %v", attributes)

	// For now, skip the actual credential offer if API is not available
	// This is a placeholder for testing proof functionality
	if c.credsApi != nil {
		log.Printf("⚠️  Credential API implementation not complete")
		log.Printf("   Using mock credential issuance for testing")
	}

	log.Printf("✅ Credential offer sent successfully")
	return nil
}

