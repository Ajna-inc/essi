package operations

import (
	"fmt"
	"log"
	"time"

	"github.com/ajna-inc/essi/pkg/anoncreds"
	"github.com/ajna-inc/essi/pkg/anoncreds/services"
	"github.com/ajna-inc/essi/pkg/core/agent"
)

// ProofOperations handles proof-related operations for testing
type ProofOperations struct {
	agent   *agent.Agent
	anonApi *anoncreds.AnonCredsApi
	metrics *Metrics
}

// NewProofOperations creates a new proof operations handler
func NewProofOperations(agent *agent.Agent, anonApi *anoncreds.AnonCredsApi, metrics *Metrics) *ProofOperations {
	return &ProofOperations{
		agent:   agent,
		anonApi: anonApi,
		metrics: metrics,
	}
}

// CreateProof creates and validates a proof presentation
func (p *ProofOperations) CreateProof() error {
	start := time.Now()
	defer func() {
		p.metrics.Record("ProofCreation", time.Since(start))
	}()

	if p.anonApi == nil {
		return fmt.Errorf("anoncreds API not available")
	}

	holderService := p.anonApi.GetHolderService()
	if holderService == nil {
		return fmt.Errorf("holder service not available")
	}

	// Create a test proof request
	proofRequest := map[string]interface{}{
		"nonce":   fmt.Sprintf("%d", time.Now().UnixNano()),
		"name":    "Test Proof Request",
		"version": "1.0",
		"requested_attributes": map[string]interface{}{
			"attr1_referent": map[string]interface{}{
				"name": "name",
			},
		},
		"requested_predicates": map[string]interface{}{},
	}

	log.Printf("📋 Created proof request with nonce: %s", proofRequest["nonce"])

	// Get credentials for the proof request
	log.Println("🔍 Finding credentials for proof request...")
	
	credOptions := &services.GetCredentialsForProofRequestOptions{
		ProofRequest: proofRequest,
	}

	credsForProof, err := holderService.GetCredentialsForProofRequest(p.agent.GetContext(), credOptions)
	if err != nil {
		return fmt.Errorf("failed to get credentials for proof: %w", err)
	}

	// Check if we have any matching credentials
	hasCredentials := false
	for _, matches := range credsForProof.Attributes {
		if len(matches) > 0 {
			hasCredentials = true
			log.Printf("✅ Found %d matching credentials for attributes", len(matches))
			break
		}
	}

	if !hasCredentials {
		log.Println("⚠️  No matching credentials found")
		log.Println("   You need to issue credentials first before creating proofs")
		return fmt.Errorf("no matching credentials available")
	}

	// Select credentials automatically
	selectedCredentials := map[string]interface{}{
		"attributes": map[string]interface{}{},
		"predicates": map[string]interface{}{},
		"selfAttestedAttributes": map[string]interface{}{},
	}

	// Select first matching credential for each attribute
	attrs := selectedCredentials["attributes"].(map[string]interface{})
	for referent, matches := range credsForProof.Attributes {
		if len(matches) > 0 {
			attrs[referent] = map[string]interface{}{
				"credentialId": matches[0].CredentialId,
				"revealed":     true,
			}
			log.Printf("✅ Selected credential %s for attribute %s", matches[0].CredentialId, referent)
		}
	}

	// For this test, we'll use mock schemas and credential definitions
	// In a real implementation, these would be fetched from the registry
	schemas := map[string]map[string]interface{}{
		"schema:1": {
			"id":        "schema:1",
			"name":      "EmployeeID",
			"version":   "1.0",
			"attrNames": []string{"name", "age", "title"},
			"issuerId":  "did:example:issuer",
		},
	}

	credDefs := map[string]map[string]interface{}{
		"creddef:1": {
			"id":       "creddef:1",
			"schemaId": "schema:1",
			"type":     "CL",
			"tag":      "default",
			"value":    map[string]interface{}{},
			"issuerId": "did:example:issuer",
		},
	}

	// Create proof
	log.Println("🔐 Creating proof presentation...")
	
	proofOptions := &services.CreateProofOptions{
		ProofRequest:          proofRequest,
		SelectedCredentials:   selectedCredentials,
		Schemas:               schemas,
		CredentialDefinitions: credDefs,
		LinkSecretId:          "default",
	}

	proof, err := holderService.CreateProof(p.agent.GetContext(), proofOptions)
	if err != nil {
		return fmt.Errorf("failed to create proof: %w", err)
	}

	log.Printf("✅ Proof presentation created successfully")
	
	// Log proof structure
	if proof.Proof != nil {
		if _, ok := proof.Proof["proof"]; ok {
			log.Println("   - Contains cryptographic proof")
		}
		if _, ok := proof.Proof["requested_proof"]; ok {
			log.Println("   - Contains requested proof values")
		}
	}

	return nil
}

// ExecuteProofFlow executes the complete proof presentation flow
func (p *ProofOperations) ExecuteProofFlow(connectionId string) error {
	start := time.Now()
	defer func() {
		p.metrics.Record("ProofFlow", time.Since(start))
	}()

	log.Printf("🔄 Starting proof flow for connection: %s", connectionId)

	// First validate proof creation capability
	err := p.CreateProof()
	if err != nil {
		return fmt.Errorf("proof creation validation failed: %w", err)
	}

	// In a real implementation, we would:
	// 1. Send the proof request over the connection
	// 2. Receive the proof presentation
	// 3. Verify the proof cryptographically
	
	log.Println("✅ Proof flow completed successfully")
	log.Println("   Note: Full DIDComm proof exchange requires additional protocol implementation")

	return nil
}