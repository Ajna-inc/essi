package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/ajna-inc/essi/cmd/kanon-test/operations"
	"github.com/ajna-inc/essi/pkg/anoncreds"
	"github.com/ajna-inc/essi/pkg/core/agent"
	"github.com/ajna-inc/essi/pkg/didcomm/modules/proofs"
	"github.com/ajna-inc/essi/pkg/didcomm/modules/proofs/models"
	"github.com/ajna-inc/essi/pkg/dids/api"
	"github.com/google/uuid"
)

// IntegrationScenario represents a complete integration test scenario
type IntegrationScenario struct {
	agent        *agent.Agent
	metrics      *operations.Metrics
	connectionID string // Persist connection ID across operations
	issuerDID    string
	schemaID     string
	credDefID    string
}

// NewIntegrationScenario creates a new integration scenario
func NewIntegrationScenario(agent *agent.Agent, metrics *operations.Metrics) *IntegrationScenario {
	return &IntegrationScenario{
		agent:   agent,
		metrics: metrics,
	}
}

// EstablishConnection establishes a connection with another agent
func (ts *IntegrationScenario) EstablishConnection(invitationURL string) error {
	log.Println("📱 Establishing connection...")
	
	connOps := operations.NewConnectionOperations(ts.agent, ts.metrics)
	connection, err := connOps.ProcessOOBInvitation(invitationURL)
	if err != nil {
		return fmt.Errorf("failed to process invitation: %w", err)
	}
	
	// Store the connection ID for later use
	ts.connectionID = connection.ID
	
	// Wait for connection to be complete
	err = connOps.WaitForConnectionComplete(ts.connectionID, 30*time.Second)
	if err != nil {
		return fmt.Errorf("failed waiting for connection: %w", err)
	}
	
	log.Printf("✅ Connection established: %s", ts.connectionID)
	return nil
}

// IssueCredential issues a credential to the connected agent
func (ts *IntegrationScenario) IssueCredential() error {
	if ts.connectionID == "" {
		return fmt.Errorf("no connection established")
	}
	
	log.Printf("📜 Issuing credential to connection: %s", ts.connectionID)
	
	anonApi, credsApi, didsApi := ts.getAPIs()
	if anonApi == nil || didsApi == nil {
		return fmt.Errorf("required APIs not available")
	}
	
	didOps := operations.NewDIDOperations(didsApi, ts.metrics)
	issuerDID, err := didOps.CreateKanonIssuerDIDWithTimestamp()
	if err != nil {
		return fmt.Errorf("failed to create issuer DID: %w", err)
	}
	ts.issuerDID = issuerDID
	
	// Register schema
	schemaOps := operations.NewSchemaOperations(anonApi, ts.metrics)
	schemaConfig := &operations.SchemaConfig{
		Name:       "EmployeeID",
		Version:    "1.0",
		Attributes: []string{"name", "age", "title"},
		IssuerDID:  issuerDID,
	}
	
	schemaID, err := schemaOps.RegisterSchema(schemaConfig)
	if err != nil {
		return fmt.Errorf("failed to register schema: %w", err)
	}
	ts.schemaID = schemaID
	
	// Register credential definition
	credOps := operations.NewCredentialOperations(anonApi, credsApi, ts.metrics)
	credDefConfig := &operations.CredentialDefinitionConfig{
		Tag:       "default",
		SchemaID:  schemaID,
		IssuerDID: issuerDID,
	}
	
	credDefID, err := credOps.RegisterCredentialDefinition(credDefConfig)
	if err != nil {
		return fmt.Errorf("failed to register credential definition: %w", err)
	}
	ts.credDefID = credDefID
	
	// Offer real credential using proper DIDComm protocol
	attributes := map[string]string{
		"name":  "Alice",
		"age":   "30",
		"title": "Developer",
	}
	
	// Use real credential operations
	credService := operations.NewCredentialService(ts.agent, anonApi, ts.metrics)
	err = credService.OfferCredentialToConnection(ts.connectionID, credDefID, attributes)
	if err != nil {
		return fmt.Errorf("failed to offer credential: %w", err)
	}
	
	// Wait for credential exchange to complete
	log.Println("⏳ Waiting for credential exchange to complete...")
	err = credService.WaitForCredentialExchangeComplete(ts.connectionID, 30*time.Second)
	if err != nil {
		return fmt.Errorf("failed waiting for credential exchange: %w", err)
	}
	
	log.Println("✅ Credential issued and exchange completed successfully")
	return nil
}

// RequestProof requests a proof from the connected agent (as verifier)
func (ts *IntegrationScenario) RequestProof() error {
	if ts.connectionID == "" {
		return fmt.Errorf("no connection established")
	}
	
	if ts.credDefID == "" {
		return fmt.Errorf("no credential definition available - credential must be issued first")
	}
	
	// Add a small delay to ensure the holder has processed the credential
	log.Println("⏱️  Waiting briefly to ensure credential is stored by holder...")
	time.Sleep(2 * time.Second)
	
	log.Printf("🔍 Requesting proof from connection: %s", ts.connectionID)
	log.Printf("   Using Credential Definition: %s", ts.credDefID)
	
	// Get the Proofs API
	proofsApi := ts.agent.Proofs()
	if proofsApi == nil {
		return fmt.Errorf("proofs API not available")
	}
	
	// Type assert to ProofsApi
	proofsTyped, ok := proofsApi.(*proofs.ProofsApi)
	if !ok {
		return fmt.Errorf("invalid proofs API type")
	}
	
	// Create proof request data for AnonCreds format
	proofRequestData := ts.createProofRequestData()
	
	// Request proof using the API
	proofRecord, err := proofsTyped.RequestProof(proofs.RequestProofOptions{
		ConnectionId: ts.connectionID,
		ProofFormats: map[string]interface{}{
			"anoncreds": map[string]interface{}{
				"name":    "Employee Verification",
				"version": "1.0",
				"nonce":   fmt.Sprintf("%d", time.Now().UnixNano()),
				"requested_attributes": proofRequestData["requested_attributes"],
				"requested_predicates": proofRequestData["requested_predicates"],
			},
		},
		Comment:         "Please provide proof of your employee credentials",
		AutoAcceptProof: models.AutoAcceptAlways,
		WillConfirm:     true,
	})
	
	if err != nil {
		return fmt.Errorf("failed to request proof: %w", err)
	}
	
	log.Printf("✅ Proof request sent successfully, record ID: %s", proofRecord.ID)
	log.Println("⏳ Waiting for proof presentation from holder...")
	
	// Wait for proof presentation
	time.Sleep(10 * time.Second)
	
	// Check proof record status
	updatedRecord, err := proofsTyped.GetById(proofRecord.ID)
	if err != nil {
		log.Printf("⚠️ Failed to get proof record: %v", err)
	} else {
		log.Printf("📊 Proof record status: %s", updatedRecord.State)
		if updatedRecord.IsVerified {
			log.Println("✅ Proof verified successfully!")
		}
	}
	
	log.Println("✅ Proof request flow completed")
	return nil
}

// createProofRequestData creates the proof request data structure
func (ts *IntegrationScenario) createProofRequestData() map[string]interface{} {
	return map[string]interface{}{
		"requested_attributes": map[string]interface{}{
			"attr1_referent": map[string]interface{}{
				"name": "name",
				"restrictions": []map[string]interface{}{
					{
						"cred_def_id": ts.credDefID,
					},
				},
			},
			"attr2_referent": map[string]interface{}{
				"name": "title",
				"restrictions": []map[string]interface{}{
					{
						"cred_def_id": ts.credDefID,
					},
				},
			},
		},
		"requested_predicates": map[string]interface{}{
			"predicate1_referent": map[string]interface{}{
				"name":    "age",
				"p_type":  ">=",
				"p_value": 18,
				"restrictions": []map[string]interface{}{
					{
						"cred_def_id": ts.credDefID,
					},
				},
			},
		},
	}
}


// createProofRequestMessage creates a proof request message with proper encoding
func (ts *IntegrationScenario) createProofRequestMessage() map[string]interface{} {
	// Create an Aries RFC 0037 proof request
	proofRequestData := map[string]interface{}{
		"name":    "Employee Verification",
		"version": "1.0",
		"nonce":   fmt.Sprintf("%d", time.Now().UnixNano()),
		"requested_attributes": map[string]interface{}{
			"attr1_referent": map[string]interface{}{
				"name": "name",
				"restrictions": []map[string]interface{}{
					{
						"cred_def_id": ts.credDefID,
					},
				},
			},
			"attr2_referent": map[string]interface{}{
				"name": "age",
				"restrictions": []map[string]interface{}{
					{
						"cred_def_id": ts.credDefID,
					},
				},
			},
		},
		"requested_predicates": map[string]interface{}{
			"predicate1_referent": map[string]interface{}{
				"name":    "age",
				"p_type":  ">=",
				"p_value": 18,
				"restrictions": []map[string]interface{}{
					{
						"cred_def_id": ts.credDefID,
					},
				},
			},
		},
	}
	
	// Encode the proof request as base64
	proofRequestJSON, _ := json.Marshal(proofRequestData)
	encodedProofRequest := base64.StdEncoding.EncodeToString(proofRequestJSON)
	
	// Package as DIDComm message with proper attachment format
	return map[string]interface{}{
		"@type":   "https://didcomm.org/present-proof/1.0/request-presentation",
		"@id":     uuid.New().String(),
		"comment": "Please provide proof of your employee credentials",
		"request_presentations~attach": []map[string]interface{}{
			{
				"@id":       "libindy-request-presentation-0",
				"mime-type": "application/json",
				"data": map[string]interface{}{
					"base64": encodedProofRequest,
				},
			},
		},
	}
}


// RunFullFlow runs the complete flow
func (ts *IntegrationScenario) RunFullFlow(invitationURL string) error {
	log.Println("🚀 Starting full E2E flow...")
	log.Println("=" + strings.Repeat("=", 50))
	
	// Step 1: Establish connection
	log.Println("\n📱 STEP 1: Establishing Connection")
	log.Println("-" + strings.Repeat("-", 40))
	err := ts.EstablishConnection(invitationURL)
	if err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}
	
	// Step 2: Issue credential
	log.Println("\n📜 STEP 2: Issuing Credential")
	log.Println("-" + strings.Repeat("-", 40))
	err = ts.IssueCredential()
	if err != nil {
		return fmt.Errorf("credential issuance failed: %w", err)
	}
	
	// Step 3: Request proof (as verifier)
	log.Println("\n🔍 STEP 3: Requesting Proof")
	log.Println("-" + strings.Repeat("-", 40))
	err = ts.RequestProof()
	if err != nil {
		return fmt.Errorf("proof request failed: %w", err)
	}
	
	log.Println("\n" + strings.Repeat("=", 50))
	log.Println("✅ Full E2E flow completed successfully!")
	log.Printf("   - Connection ID: %s", ts.connectionID)
	log.Printf("   - Issuer DID: %s", ts.issuerDID)
	log.Printf("   - Schema ID: %s", ts.schemaID)
	log.Printf("   - CredDef ID: %s", ts.credDefID)
	log.Println(strings.Repeat("=", 50))
	
	return nil
}

// getAPIs retrieves the necessary APIs from the agent
func (ts *IntegrationScenario) getAPIs() (*anoncreds.AnonCredsApi, interface{}, *api.DidsApi) {
	var anonApi *anoncreds.AnonCredsApi
	var credsApi interface{}
	var didsApi *api.DidsApi
	
	if api := ts.agent.AnonCreds(); api != nil {
		anonApi, _ = api.(*anoncreds.AnonCredsApi)
	}
	
	credsApi = ts.agent.Credentials()
	
	if didsInterface := ts.agent.Dids(); didsInterface != nil {
		didsApi, _ = didsInterface.(*api.DidsApi)
	}
	
	return anonApi, credsApi, didsApi
}