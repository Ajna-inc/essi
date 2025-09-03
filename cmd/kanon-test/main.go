package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ajna-inc/essi/cmd/kanon-test/operations"
	"github.com/ajna-inc/essi/pkg/anoncreds"
	"github.com/ajna-inc/essi/pkg/core/agent"
	coreevents "github.com/ajna-inc/essi/pkg/core/events"
	oob "github.com/ajna-inc/essi/pkg/didcomm/modules/oob"
	"github.com/ajna-inc/essi/pkg/dids/api"
)

const (
	defaultHost       = "127.0.0.1"
	defaultPort       = 9002
	connectionTimeout = 60 * time.Second
)

var testOOBInvitation = "http://localhost:3000?oob=eyJAdHlwZSI6Imh0dHBzOi8vZGlkY29tbS5vcmcvb3V0LW9mLWJhbmQvMS4xL2ludml0YXRpb24iLCJAaWQiOiJiMmIwYWM4NC0zMWIyLTQyYTItOTdiZC1jMzg5NWQ1Yjc1ZmIiLCJsYWJlbCI6IkNyZWRvIHJyZXJkZmtqaGdycmVyYiIsImFjY2VwdCI6WyJkaWRjb21tL2FpcDEiLCJkaWRjb21tL2FpcDI7ZW52PXJmYzE5Il0sImhhbmRzaGFrZV9wcm90b2NvbHMiOlsiaHR0cHM6Ly9kaWRjb21tLm9yZy9kaWRleGNoYW5nZS8xLjEiLCJodHRwczovL2RpZGNvbW0ub3JnL2Nvbm5lY3Rpb25zLzEuMCJdLCJzZXJ2aWNlcyI6W3siaWQiOiIjaW5saW5lLTAiLCJzZXJ2aWNlRW5kcG9pbnQiOiJodHRwOi8vbG9jYWxob3N0OjMwMDAiLCJ0eXBlIjoiZGlkLWNvbW11bmljYXRpb24iLCJyZWNpcGllbnRLZXlzIjpbImRpZDprZXk6ejZNa3FVSFdQR3ZRcDJaNFp3N2tlWlByVHk3bVdKUDRIS1FOMllidW9FdTI0aDNUIl0sInJvdXRpbmdLZXlzIjpbXX1dfQ"

var (
	action   = flag.String("action", "e2eIssue", "Action to perform: e2eIssue, testCache, testConnections, testDIDs")
	host     = flag.String("host", defaultHost, "Agent host")
	port     = flag.Int("port", defaultPort, "Agent port")
	useCache = flag.Bool("cache", false, "Use fixed IDs to test caching")
)

func main() {
	flag.Parse()

	metrics := operations.NewMetrics()

	config := operations.DefaultAgentConfig()
	config.Host = *host
	config.Port = *port

	log.Println("🚀 Setting up agent...")
	a, err := operations.SetupAgent(config, metrics)
	if err != nil {
		log.Fatalf("Failed to setup agent: %v", err)
	}
	defer a.Shutdown()

	subscribeOobEvents(a)

	operations.LogAgentStatus(a, metrics)

	switch *action {
	case "e2eIssue":
		runE2EIssuance(a, metrics)
	case "e2eProof":
		runE2EProof(a, metrics)
	case "e2eFullFlow":
		runE2EFullFlow(a, metrics)
	case "testCache":
		runCacheTest(a, metrics)
	case "testConnections":
		runConnectionTest(a, metrics)
	case "testDIDs":
		runDIDTest(a, metrics)
	case "testSchema":
		runSchemaTest(a, metrics)
	case "testCredDef":
		runCredDefTest(a, metrics)
	default:
		log.Fatalf("Unknown action: %s", *action)
	}

	metrics.PrintSummary()

	waitForShutdown()
}

// runE2EIssuance runs the complete end-to-end credential issuance flow
func runE2EIssuance(a *agent.Agent, metrics *operations.Metrics) string {
	log.Println("🔄 Running E2E credential issuance flow...")

	anonApi, credsApi, didsApi := getAPIs(a)
	if anonApi == nil || credsApi == nil || didsApi == nil {
		log.Fatal("Required APIs not available")
	}

	connOps := operations.NewConnectionOperations(a, metrics)
	didOps := operations.NewDIDOperations(didsApi, metrics)
	schemaOps := operations.NewSchemaOperations(anonApi, metrics)
	credOps := operations.NewCredentialOperations(anonApi, credsApi, metrics)

	conn, err := connOps.ProcessOOBInvitation(testOOBInvitation)
	if err != nil {
		log.Fatalf("Failed to process OOB invitation: %v", err)
	}

	var establishedConnectionID string

	err = connOps.WaitForConnectionAndExecute(conn.ID, connectionTimeout, func(connectionID string) error {
		establishedConnectionID = connectionID
		defer metrics.Start("credential_operations")()

		issuerDID, err := didOps.CreateKanonIssuerDIDWithTimestamp()
		if err != nil {
			return fmt.Errorf("failed to create issuer DID: %w", err)
		}

		schemaID := ""
		if *useCache {
			schemaID = schemaOps.GenerateSchemaIDFixed("example", "1.0")
		} else {
			schemaID = schemaOps.GenerateSchemaID("example", "1.0")
		}

		schemaConfig := &operations.SchemaConfig{
			ID:         schemaID,
			Name:       "example",
			Version:    "1.0",
			Attributes: []string{"name", "age"},
			IssuerDID:  issuerDID,
		}

		registeredSchemaID, err := schemaOps.RegisterSchema(schemaConfig)
		if err != nil {
			return fmt.Errorf("failed to register schema: %w", err)
		}

		// Register credential definition
		credDefID := ""
		if *useCache {
			credDefID = credOps.GenerateCredDefIDFixed("tag1")
		} else {
			credDefID = credOps.GenerateCredDefID("tag1")
		}

		credDefConfig := &operations.CredentialDefinitionConfig{
			ID:        credDefID,
			Tag:       "tag1",
			SchemaID:  registeredSchemaID,
			IssuerDID: issuerDID,
		}

		registeredCredDefID, err := credOps.RegisterCredentialDefinition(credDefConfig)
		if err != nil {
			return fmt.Errorf("failed to register credential definition: %w", err)
		}

		// Offer credential using real credential operations
		attributes := map[string]string{
			"name": "Alice",
			"age":  "42",
		}

		// Use real credential operations instead of mock
		credService := operations.NewCredentialService(a, anonApi, metrics)
		err = credService.OfferCredentialToConnection(connectionID, registeredCredDefID, attributes)
		if err != nil {
			return fmt.Errorf("failed to offer credential: %w", err)
		}

		// Wait for credential exchange to complete
		log.Println("⏳ Waiting for credential exchange to complete...")
		err = credService.WaitForCredentialExchangeComplete(connectionID, 30*time.Second)
		if err != nil {
			return fmt.Errorf("failed waiting for credential exchange: %w", err)
		}

		log.Println("✅ Credential issuance flow completed")
		return nil
	})

	if err != nil {
		log.Fatalf("Failed to complete issuance: %v", err)
	}

	// Print operation breakdown
	metrics.PrintOperationBreakdown("CREDENTIAL OPERATION BREAKDOWN", []string{
		"create_did_kanon",
		"register_schema",
		"register_cred_def",
		"offer_credential",
	}, "credential_operations")

	return establishedConnectionID
}

// runCacheTest tests the caching of credential definitions
func runCacheTest(a *agent.Agent, metrics *operations.Metrics) {
	log.Println("🔄 Running credential definition cache test...")

	anonApi, _, didsApi := getAPIs(a)
	if anonApi == nil || didsApi == nil {
		log.Fatal("Required APIs not available")
	}

	didOps := operations.NewDIDOperations(didsApi, metrics)
	schemaOps := operations.NewSchemaOperations(anonApi, metrics)
	credOps := operations.NewCredentialOperations(anonApi, nil, metrics)

	issuerDID, err := didOps.CreateKanonIssuerDID("test-issuer")
	if err != nil {
		log.Fatalf("Failed to create issuer DID: %v", err)
	}

	// Use fixed IDs for caching
	schemaID := "schema:kanon:testnet:cache-test:1.0"
	credDefID := "creddef:kanon:testnet:cache-test:tag1"

	// Register schema
	schemaConfig := &operations.SchemaConfig{
		ID:         schemaID,
		Name:       "cache-test",
		Version:    "1.0",
		Attributes: []string{"name", "age", "email"},
		IssuerDID:  issuerDID,
	}

	_, err = schemaOps.RegisterSchema(schemaConfig)
	if err != nil {
		log.Fatalf("Failed to register schema: %v", err)
	}

	// First credential definition registration (should be slow)
	log.Println("\n📊 First credential definition registration (creating new)...")
	start1 := time.Now()
	credDefConfig := &operations.CredentialDefinitionConfig{
		ID:        credDefID,
		Tag:       "tag1",
		SchemaID:  schemaID,
		IssuerDID: issuerDID,
	}
	_, err = credOps.RegisterCredentialDefinition(credDefConfig)
	duration1 := time.Since(start1)
	if err != nil {
		log.Fatalf("Failed to register credential definition: %v", err)
	}
	log.Printf("⏱️  First registration took: %v", duration1)

	// Second credential definition registration (should be cached)
	log.Println("\n📊 Second credential definition registration (should use cache)...")
	start2 := time.Now()
	_, err = credOps.RegisterCredentialDefinition(credDefConfig)
	duration2 := time.Since(start2)
	if err != nil {
		log.Fatalf("Failed to register credential definition: %v", err)
	}
	log.Printf("⏱️  Second registration took: %v", duration2)

	// Calculate improvement
	if duration1 > 0 {
		improvement := float64(duration1-duration2) / float64(duration1) * 100
		speedup := float64(duration1) / float64(duration2)
		log.Printf("\n✨ Cache Performance:")
		log.Printf("   First run:  %v", duration1)
		log.Printf("   Second run: %v", duration2)
		log.Printf("   Improvement: %.1f%%", improvement)
		log.Printf("   Speedup: %.1fx faster", speedup)
	}
}

// runConnectionTest tests connection operations
func runConnectionTest(a *agent.Agent, metrics *operations.Metrics) {
	log.Println("🔄 Running connection test...")

	connOps := operations.NewConnectionOperations(a, metrics)

	// List existing connections
	conns, err := connOps.GetConnections()
	if err != nil {
		log.Fatalf("Failed to get connections: %v", err)
	}
	log.Printf("Found %d existing connections", len(conns))

	// Process new OOB invitation
	conn, err := connOps.ProcessOOBInvitation(testOOBInvitation)
	if err != nil {
		log.Fatalf("Failed to process OOB invitation: %v", err)
	}

	// Wait for connection to complete
	err = connOps.WaitForConnection(conn.ID, connectionTimeout)
	if err != nil {
		log.Fatalf("Failed waiting for connection: %v", err)
	}

	log.Println("✅ Connection test completed")
}

// runDIDTest tests DID operations
func runDIDTest(a *agent.Agent, metrics *operations.Metrics) {
	log.Println("🔄 Running DID test...")

	_, _, didsApi := getAPIs(a)
	if didsApi == nil {
		log.Fatal("DIDs API not available")
	}

	didOps := operations.NewDIDOperations(didsApi, metrics)

	// Test Kanon DID creation
	kanonDID, err := didOps.CreateKanonIssuerDID("test")
	if err != nil {
		log.Fatalf("Failed to create Kanon DID: %v", err)
	}
	log.Printf("✅ Created Kanon DID: %s", kanonDID)

	// Test Peer DID creation
	peerDID, err := didOps.CreatePeerDID()
	if err != nil {
		log.Fatalf("Failed to create Peer DID: %v", err)
	}
	log.Printf("✅ Created Peer DID: %s", peerDID.Did)

	// Test Key DID creation
	keyDID, err := didOps.CreateKeyDID()
	if err != nil {
		log.Fatalf("Failed to create Key DID: %v", err)
	}
	log.Printf("✅ Created Key DID: %s", keyDID.Did)

	log.Println("✅ DID test completed")
}

// runSchemaTest tests schema operations
func runSchemaTest(a *agent.Agent, metrics *operations.Metrics) {
	log.Println("🔄 Running schema test...")

	anonApi, _, didsApi := getAPIs(a)
	if anonApi == nil || didsApi == nil {
		log.Fatal("Required APIs not available")
	}

	didOps := operations.NewDIDOperations(didsApi, metrics)
	schemaOps := operations.NewSchemaOperations(anonApi, metrics)

	issuerDID, err := didOps.CreateKanonIssuerDID("schema-test")
	if err != nil {
		log.Fatalf("Failed to create issuer DID: %v", err)
	}

	// Test schema registration with different configurations
	schemas := []operations.SchemaConfig{
		{
			Name:       "person",
			Version:    "1.0",
			Attributes: []string{"firstName", "lastName", "age"},
			IssuerDID:  issuerDID,
		},
		{
			Name:       "credential",
			Version:    "2.0",
			Attributes: []string{"type", "issuedDate", "expiryDate", "status"},
			IssuerDID:  issuerDID,
		},
		{
			Name:       "address",
			Version:    "1.0",
			Attributes: []string{"street", "city", "state", "zipCode", "country"},
			IssuerDID:  issuerDID,
		},
	}

	for _, schema := range schemas {
		schemaID, err := schemaOps.RegisterSchema(&schema)
		if err != nil {
			log.Printf("Failed to register schema %s: %v", schema.Name, err)
			continue
		}
		log.Printf("✅ Registered schema: %s", schemaID)
	}

	log.Println("✅ Schema test completed")
}

// runCredDefTest tests credential definition operations
func runCredDefTest(a *agent.Agent, metrics *operations.Metrics) {
	log.Println("🔄 Running credential definition test...")

	anonApi, _, didsApi := getAPIs(a)
	if anonApi == nil || didsApi == nil {
		log.Fatal("Required APIs not available")
	}

	didOps := operations.NewDIDOperations(didsApi, metrics)
	schemaOps := operations.NewSchemaOperations(anonApi, metrics)
	credOps := operations.NewCredentialOperations(anonApi, nil, metrics)

	issuerDID, err := didOps.CreateKanonIssuerDID("creddef-test")
	if err != nil {
		log.Fatalf("Failed to create issuer DID: %v", err)
	}

	// Register a schema first
	schemaConfig := &operations.SchemaConfig{
		Name:       "test-credential",
		Version:    "1.0",
		Attributes: []string{"field1", "field2", "field3"},
		IssuerDID:  issuerDID,
	}

	schemaID, err := schemaOps.RegisterSchema(schemaConfig)
	if err != nil {
		log.Fatalf("Failed to register schema: %v", err)
	}

	// Test credential definition registration with different tags
	tags := []string{"default", "revocable", "non-revocable", "test"}

	for _, tag := range tags {
		credDefConfig := &operations.CredentialDefinitionConfig{
			Tag:       tag,
			SchemaID:  schemaID,
			IssuerDID: issuerDID,
		}

		credDefID, err := credOps.RegisterCredentialDefinition(credDefConfig)
		if err != nil {
			log.Printf("Failed to register credential definition with tag %s: %v", tag, err)
			continue
		}
		log.Printf("✅ Registered credential definition: %s (tag: %s)", credDefID, tag)
	}

	log.Println("✅ Credential definition test completed")
}

// runE2EProof runs the proof request and verification flow
func runE2EProof(a *agent.Agent, metrics *operations.Metrics) {
	log.Println("🔄 Running E2E proof flow (as verifier)...")

	// Get APIs
	anonApi, _, _ := getAPIs(a)
	if anonApi == nil {
		log.Fatal("AnonCreds API not available")
	}

	// Get connection to request proof from
	connectionID := "test-connection-1" // This should be from a real connection

	// Create proof request operations handler (as verifier)
	proofReqOps := operations.NewProofRequestOperations(a, metrics)

	// Send proof request to the connected agent
	log.Println("📋 Sending proof request to connected agent...")
	err := proofReqOps.SendProofRequest(connectionID)
	if err != nil {
		log.Printf("⚠️  Failed to send proof request: %v", err)
		log.Println("   Make sure you have an established connection first")
		return
	}

	// Wait for proof presentation from the other agent
	err = proofReqOps.WaitForProofPresentation(connectionID, 30*time.Second)
	if err != nil {
		log.Printf("⚠️  Failed waiting for proof presentation: %v", err)
		return
	}

	log.Println("✅ Proof request flow completed successfully!")
}

// runE2EFullFlow runs the complete flow: connection, issuance, and proof
func runE2EFullFlow(a *agent.Agent, metrics *operations.Metrics) {
	log.Println("🔄 Running complete E2E flow (connection + issuance + proof request)...")

	// Create a test scenario to maintain state
	scenario := NewIntegrationScenario(a, metrics)

	// Use the test OOB invitation
	err := scenario.RunFullFlow(testOOBInvitation)
	if err != nil {
		log.Printf("❌ E2E flow failed: %v", err)
		return
	}
}

// getAPIs retrieves the necessary APIs from the agent
func getAPIs(a *agent.Agent) (*anoncreds.AnonCredsApi, interface{}, *api.DidsApi) {
	var anonApi *anoncreds.AnonCredsApi
	var credsApi interface{}
	var didsApi *api.DidsApi

	if api := a.AnonCreds(); api != nil {
		anonApi, _ = api.(*anoncreds.AnonCredsApi)
	}

	credsApi = a.Credentials()

	if didsInterface := a.Dids(); didsInterface != nil {
		didsApi, _ = didsInterface.(*api.DidsApi)
	}

	return anonApi, credsApi, didsApi
}

func waitForShutdown() {
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
	<-sigc
}

// subscribeOobEvents registers simple loggers for OOB events
func subscribeOobEvents(a *agent.Agent) {
	di := a.GetDependencyManager()
	if di == nil {
		return
	}
	// Try EventBus first
	if any, err := di.Resolve(struct{ Name string }{Name: "EventBus"}); err == nil {
		if bus, ok := any.(coreevents.Bus); ok {
			_ = bus.Subscribe(oob.OutOfBandEventHandshakeReused, func(ev coreevents.Event) { log.Printf("🔁 OOB handshake reused: %+v", ev.Data) })
			_ = bus.Subscribe(oob.OutOfBandEventStateChanged, func(ev coreevents.Event) { log.Printf("📣 OOB state changed: %+v", ev.Data) })
			return
		}
	}
	// Fallback to EventBusService
	if any, err := di.Resolve(struct{ Name string }{Name: "EventBusService"}); err == nil {
		if bus, ok := any.(coreevents.Bus); ok {
			_ = bus.Subscribe(oob.OutOfBandEventHandshakeReused, func(ev coreevents.Event) { log.Printf("🔁 OOB handshake reused: %+v", ev.Data) })
			_ = bus.Subscribe(oob.OutOfBandEventStateChanged, func(ev coreevents.Event) { log.Printf("📣 OOB state changed: %+v", ev.Data) })
		}
	}
}
