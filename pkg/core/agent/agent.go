package agent

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/core/di"
	"github.com/ajna-inc/essi/pkg/core/encoding"
	"github.com/ajna-inc/essi/pkg/core/events"
	"github.com/ajna-inc/essi/pkg/core/wallet"
	didcommmodule "github.com/ajna-inc/essi/pkg/didcomm"
	"github.com/ajna-inc/essi/pkg/didcomm/messages"
	"github.com/ajna-inc/essi/pkg/didcomm/models"
	"github.com/ajna-inc/essi/pkg/didcomm/module"
	conmsg "github.com/ajna-inc/essi/pkg/didcomm/modules/connections/messages"
	"github.com/ajna-inc/essi/pkg/didcomm/modules/connections/services"
	mpv1 "github.com/ajna-inc/essi/pkg/didcomm/modules/messagepickup/v1"
	oob "github.com/ajna-inc/essi/pkg/didcomm/modules/oob"
	oobMessages "github.com/ajna-inc/essi/pkg/didcomm/modules/oob/messages"
	routingmessages "github.com/ajna-inc/essi/pkg/didcomm/modules/routing/messages"
	envelopeservices "github.com/ajna-inc/essi/pkg/didcomm/services"
	transport "github.com/ajna-inc/essi/pkg/didcomm/transport"
	didsmodule "github.com/ajna-inc/essi/pkg/dids/module"
)

// Agent represents the main agent that orchestrates all components
type Agent struct {
	config            *context.AgentConfig
	context           *context.AgentContext
	events            events.Bus
	walletService     *wallet.WalletService
	connectionService *services.ConnectionService
	messageSender     *transport.MessageSender
	messageReceiver   *transport.MessageReceiver
	envelopeService   *envelopeservices.EnvelopeService
	isInitialized     bool
	// diManager provides typed DI and module lifecycle management
	diManager di.DependencyManager
}

// AgentOptions contains the options for creating an agent
type AgentOptions struct {
	Config       *context.AgentConfig
	Dependencies *AgentDependencies
	// Modules in dependency order
	Modules []di.Module
}

type AgentDependencies struct{}

// NewAgent creates a new Agent instance
func NewAgent(options *AgentOptions) (*Agent, error) {
	if options == nil {
		return nil, fmt.Errorf("agent options are required")
	}
	if options.Config == nil {
		return nil, fmt.Errorf("agent config is required")
	}

	// Populate default endpoints from inbound host/port if none provided
	if len(options.Config.Endpoints) == 0 && options.Config.InboundPort > 0 {
		host := options.Config.InboundHost
		if host == "" {
			host = "localhost"
		}
		endpoint := fmt.Sprintf("http://%s:%d", host, options.Config.InboundPort)
		options.Config.Endpoints = []string{endpoint}
	}

	// Create typed DI manager first
	dm := di.NewDependencyManager()

	// Register AgentConfig and AgentContextProvider before creating AgentContext
	provider := di.DefaultAgentContextProvider{}
	dm.RegisterInstance(di.TokenAgentConfig, options.Config)
	dm.RegisterInstance(di.TokenAgentContextProvider, provider)

	// Create agent context bound to dm's legacy dependency manager
	agentContext, _ := provider.NewRootContext(dm, "default")

	// Create and register event bus
	evtBus := events.NewSimpleBus()
	dm.RegisterInstance(di.TokenEventBus, evtBus)
	dm.RegisterInstance(di.TokenEventBusService, evtBus)

	// Register AgentContext (typed)
	dm.RegisterInstance(di.TokenAgentContext, agentContext)

	// StorageService will be registered by storage modules (e.g., Askar) during initialization

	// Register modules
	if len(options.Modules) > 0 {
		// Modules are already in dependency order
		_ = dm.RegisterModules(options.Modules)
	} else {
		_ = dm.RegisterModules([]di.Module{
			didsmodule.NewDidsModule(nil),
			didcommmodule.NewDidCommModule(nil),
			// ConnectionsModule and OobModule are included in DidCommModule
			module.NewCredentialsModule(),
		})
	}

	// Core services will be provided by modules via DI. Do not construct services here.

	agent := &Agent{
		config:            options.Config,
		context:           agentContext,
		events:            evtBus,
		walletService:     nil,
		connectionService: nil,
		messageSender:     nil,
		messageReceiver:   nil,
		envelopeService:   nil,
		isInitialized:     false,
		diManager:         dm,
	}

	return agent, nil
}

// Initialize initializes the agent and all its components
func (a *Agent) Initialize() error {
	if a.isInitialized {
		return fmt.Errorf("agent already initialized. currently it is not supported to re-initialize an already initialized agent")
	}

	log.Printf("🚀 Initializing Essi-Go Agent...")

	// Initialize DI-registered modules first
	if a.diManager != nil {
		if err := a.diManager.InitializeModules(a.context); err != nil {
			return fmt.Errorf("failed to initialize modules: %w", err)
		}
	}

	// Resolve transports from typed DI (populated by DidCommModule)
	if a.diManager != nil {
		// Resolve core services for convenience getters
		if any, err := a.diManager.Resolve(di.TokenWalletService); err == nil {
			if ws, ok := any.(*wallet.WalletService); ok {
				a.walletService = ws
			}
		}
		if any, err := a.diManager.Resolve(di.TokenConnectionService); err == nil {
			if cs, ok := any.(*services.ConnectionService); ok {
				a.connectionService = cs
			}
		}
		if any, err := a.diManager.Resolve(di.TokenEnvelopeService); err == nil {
			if es, ok := any.(*envelopeservices.EnvelopeService); ok {
				a.envelopeService = es
			}
		}
		if msAny, err := a.diManager.Resolve(di.TokenMessageSender); err == nil {
			if ms, ok := msAny.(*transport.MessageSender); ok {
				a.messageSender = ms
			}
		}
		if mrAny, err := a.diManager.Resolve(di.TokenMessageReceiver); err == nil {
			if mr, ok := mrAny.(*transport.MessageReceiver); ok {
				a.messageReceiver = mr
			}
		}
	}

	// Initialize wallet
	if err := a.initializeWallet(); err != nil {
		return fmt.Errorf("failed to initialize wallet: %w", err)
	}

	// Start inbound message receiver if configured via DidComm module/agent config
	if a.config != nil && a.config.InboundPort > 0 && a.messageReceiver != nil && !a.messageReceiver.IsRunning() {
		if err := a.messageReceiver.StartHTTPServer(a.config.InboundHost, a.config.InboundPort); err != nil {
			return fmt.Errorf("failed to start inbound message receiver: %w", err)
		}
	}

	a.isInitialized = true
	log.Printf("✅ Agent initialized successfully")
	return nil
}

// ProvisionMediatorIfConfigured connects to the configured mediator and requests mediation.
func (a *Agent) ProvisionMediatorIfConfigured() {
	if a.config == nil || a.config.MediatorInvitationUrl == "" {
		return
	}
	log.Printf("🔗 Mediator invitation configured. Connecting: %s", a.config.MediatorInvitationUrl)
	conn, err := a.ProcessOOBInvitation(a.config.MediatorInvitationUrl)
	if err != nil {
		log.Printf("⚠️ Failed to process mediator invitation: %v", err)
		return
	}
	if err := a.RequestMediation(conn.ID); err != nil {
		log.Printf("⚠️ Failed to request mediation: %v", err)
	} else {
		log.Printf("✅ Mediation request sent to mediator connection %s", conn.ID)
	}

	// Start pickup loop (v1) to retrieve queued messages from mediator
	go a.startPickupV1(conn.ID, 10, 2)
}

// startPickupV1 polls mediator for messages using RFC 0212 batch-pickup
func (a *Agent) startPickupV1(connectionId string, batchSize int, intervalSeconds int) {
	ticker := time.NewTicker(time.Duration(intervalSeconds) * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		rec, err := a.connectionService.FindById(connectionId)
		if err != nil {
			continue
		}
		// Build batch-pickup message with correct field naming
		req := mpv1.NewV1BatchPickup(batchSize)
		// enable return-route so mediator returns messages in same HTTP response
		req.SetReturnRoute(messages.ReturnRouteAll)
		if a.messageSender != nil {
			outboundCtx := models.NewOutboundMessageContext(req, models.OutboundMessageContextParams{
				AgentContext:     a.context,
				Connection:       rec,
				AssociatedRecord: nil,
			})
			_ = a.messageSender.SendMessage(outboundCtx)
		}
	}
}

// Shutdown gracefully shuts down the agent
func (a *Agent) Shutdown() error {
	if !a.isInitialized {
		return fmt.Errorf("agent is not initialized")
	}

	log.Printf("🛑 Shutting down agent...")

	// Stop inbound message receiver if running
	if a.messageReceiver != nil && a.messageReceiver.IsRunning() {
		if err := a.messageReceiver.StopHTTPServer(); err != nil {
			log.Printf("⚠️ Failed to stop message receiver: %v", err)
		}
	}

	// Shutdown DI modules (new flow)
	if a.diManager != nil {
		if err := a.diManager.ShutdownModules(a.context); err != nil {
			log.Printf("⚠️ Failed to shutdown modules: %v", err)
		}
	}

	a.isInitialized = false
	log.Printf("✅ Agent shutdown complete")

	return nil
}

// waitForHandshakeReuseAccepted waits for a reuse-accepted event matching thread and connection
func (a *Agent) waitForHandshakeReuseAccepted(reuseThreadId string, connectionId string, timeout time.Duration) bool {
	if a.events == nil {
		return false
	}
	acceptedCh := make(chan bool, 1)
	corr := a.context.GetCorrelationId()
	unsubscribe := a.events.Subscribe("oob.handshakeReused", func(ev events.Event) {
		if payload, ok := ev.Data.(map[string]interface{}); ok {
			if cid, ok := payload["contextCorrelationId"].(string); ok && cid != "" && cid != corr {
				return
			}
			if thid, ok := payload["reuseThreadId"].(string); ok && thid == reuseThreadId {
				if conn, ok := payload["connectionId"].(string); ok {
					if conn != connectionId {
						return
					}
				}
				acceptedCh <- true
			}
		}
	})
	defer unsubscribe()
	select {
	case <-acceptedCh:
		return true
	case <-time.After(timeout):
		return false
	}
}

// ProcessOOBInvitation processes an out-of-band invitation and establishes a connection
func (a *Agent) ProcessOOBInvitation(invitationURL string) (*services.ConnectionRecord, error) {
	if !a.isInitialized {
		return nil, fmt.Errorf("agent must be initialized before processing invitations")
	}

	// Ensure we have an endpoint configured for DID document generation
	if len(a.config.Endpoints) == 0 && a.config.InboundPort > 0 {
		host := a.config.InboundHost
		if host == "" {
			host = "localhost"
		}
		endpoint := fmt.Sprintf("http://%s:%d", host, a.config.InboundPort)
		a.config.Endpoints = []string{endpoint}
	}

	log.Printf("📨 Processing OOB invitation: %s", invitationURL)

	// Parse the OOB invitation from URL
	invitation, err := oobMessages.ParseOutOfBandInvitationFromUrl(invitationURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse OOB invitation URL: %w", err)
	}

	log.Printf("✅ OOB invitation parsed successfully")
	log.Printf("   Label: %s", invitation.GetLabel())
	log.Printf("   ID: %s", invitation.GetId())

	// Create process invitation config
	config := services.ProcessInvitationConfig{
		Label:                "Essi-Go-agent",
		Alias:                invitation.GetLabel(),
		AutoAcceptConnection: true,
	}

	// Persist OOB record and move to prepare-response (Credo-TS parity)
	var oobRecord *oob.OutOfBandRecord
	if a.diManager != nil {
		// Resolve the OOB API from DI and use it to create/update the receiver record state
		if any, err := a.diManager.Resolve(di.TokenOobApi); err == nil {
			if api, ok := any.(*oob.OutOfBandApi); ok && api != nil {
				autoInvite := true
				autoConn := true
				if rec, err := api.ReceiveInvitation(invitation, oob.ReceiveOutOfBandInvitationConfig{
					Alias:                invitation.GetLabel(),
					AutoAcceptInvitation: &autoInvite,
					AutoAcceptConnection: &autoConn,
				}); err == nil {
					oobRecord = rec
					if oobRecord != nil {
						_, _ = api.AcceptInvitation(oobRecord.ID, oob.AcceptInvitationConfig{
							Alias:                invitation.GetLabel(),
							AutoAcceptConnection: true,
						})
					}
				}
			}
		}
	}

	// Process the invitation through the connection service (build request + connection)
	connectionRecord, connectionRequest, _, err := a.connectionService.ProcessOOBInvitation(invitation, config)
	if err != nil {
		return nil, fmt.Errorf("failed to process OOB invitation: %w", err)
	}

	log.Printf("✅ Connection record created successfully")
	log.Printf("   Connection ID: %s", connectionRecord.ID)
	log.Printf("   State: %s", connectionRecord.State)

	// Now we need to send the connection request to the invitation endpoint
	if connectionRequest != nil {
		if a.messageSender == nil {
			return nil, fmt.Errorf("MessageSender not initialized. Ensure DidComm module is registered and initialized before sending")
		}
		log.Printf("📤 Sending connection request to invitation endpoint...")

		// The connection service already extracted the endpoint and keys correctly
		// We just need to verify they exist
		if connectionRecord.TheirEndpoint == "" {
			// Try to extract endpoint as a fallback
			connectionRecord.TheirEndpoint = extractEndpointFromInvitation(invitation)
			if connectionRecord.TheirEndpoint == "" {
				return nil, fmt.Errorf("no endpoint found to send connection request")
			}
		}
		// Don't override InvitationKey or TheirRecipientKey - connection service already set them correctly
		if connectionRecord.TheirRecipientKey == "" && connectionRecord.InvitationKey == "" {
			return nil, fmt.Errorf("no recipient key found to send connection request")
		}

		log.Printf("📋 Connection details for sending request:")
		log.Printf("   Endpoint: %s", connectionRecord.TheirEndpoint)
		log.Printf("   TheirRecipientKey: %s", connectionRecord.TheirRecipientKey)
		log.Printf("   InvitationKey: %s", connectionRecord.InvitationKey)

		// Send the connection request using authcrypt with the per-connection key
		// connectionRequest can be either ConnectionRequestMessage or DidExchangeRequestMessage
		var message messages.AgentMessage
		switch req := connectionRequest.(type) {
		case *conmsg.ConnectionRequestMessage:
			message = req
		case *services.DidExchangeRequestMessage:
			message = req
		default:
			return nil, fmt.Errorf("unknown connection request type")
		}

		outboundCtx := models.NewOutboundMessageContext(message, models.OutboundMessageContextParams{
			AgentContext:     a.context,
			Connection:       connectionRecord,
			AssociatedRecord: connectionRecord,
			OutOfBand:        oobRecord,
		})
		err = a.messageSender.SendMessage(outboundCtx)
		if err != nil {
			log.Printf("❌ Failed to send connection request: %v", err)
			return nil, fmt.Errorf("failed to send connection request: %w", err)
		}

		log.Printf("✅ Connection request sent successfully")

		// Update connection state to "requested" only if it hasn't already advanced
		if latest, lerr := a.connectionService.FindById(connectionRecord.ID); lerr == nil && latest != nil {
			if latest.State == services.ConnectionStateInvited {
				if err := a.connectionService.UpdateConnectionState(connectionRecord.ID, services.ConnectionStateRequested); err != nil {
					log.Printf("⚠️ Warning: Failed to update connection state: %v", err)
				}
			} else {
				log.Printf("ℹ️ Skipping state update to 'requested' (current state: %s)", latest.State)
			}
		}
	} else {
		// Reuse path: send handshake-reuse and wait up to 15s for accepted
		if connectionRecord != nil && oobRecord != nil && a.messageSender != nil {
			if inv, ok := oobRecord.OutOfBandInvitation.(*oobMessages.OutOfBandInvitationMessage); ok && inv != nil {
				reuse := oobMessages.NewHandshakeReuseMessage(inv.GetId())
				// wait for accepted event (filtered)
				// send reuse message on existing connection
				outboundCtx := models.NewOutboundMessageContext(reuse, models.OutboundMessageContextParams{
					AgentContext:     a.context,
					Connection:       connectionRecord,
					AssociatedRecord: connectionRecord,
				})
				_ = a.messageSender.SendMessage(outboundCtx)
				if a.waitForHandshakeReuseAccepted(reuse.GetThreadId(), connectionRecord.ID, 15*time.Second) {
					log.Printf("🔁 Handshake reuse accepted for connection %s", connectionRecord.ID)
				} else {
					log.Printf("⏱️ Handshake reuse accepted timeout for connection %s", connectionRecord.ID)
				}
			} else {
				log.Printf("⚠️ No connection request generated and no valid OOB invitation found for reuse")
			}
		} else {
			log.Printf("⚠️ No connection request generated - this might indicate an issue")
		}
	}

	return connectionRecord, nil
}

// RequestMediation sends a mediate-request to a given connection (recipient role)
func (a *Agent) RequestMediation(connectionId string) error {
	if !a.isInitialized {
		return fmt.Errorf("agent must be initialized")
	}
	rec, err := a.connectionService.FindById(connectionId)
	if err != nil {
		return err
	}
	req := routingmessages.NewMediationRequest()
	// Thread it to connection thread if known
	if thid, ok := rec.Tags["threadId"]; ok && thid != "" {
		req.SetThreadId(thid)
	}
	outboundCtx := models.NewOutboundMessageContext(req, models.OutboundMessageContextParams{
		AgentContext:     a.context,
		Connection:       rec,
		AssociatedRecord: nil,
	})
	return a.messageSender.SendMessage(outboundCtx)
}

// SendKeylistUpdate notifies mediator of a new recipient key (recipient role)
func (a *Agent) SendKeylistUpdate(connectionId string, recipientKey string, action routingmessages.KeylistUpdateAction) error {
	rec, err := a.connectionService.FindById(connectionId)
	if err != nil {
		return err
	}
	upd := routingmessages.NewKeylistUpdate([]routingmessages.KeylistUpdateItem{{RecipientKey: recipientKey, Action: action}})
	if thid, ok := rec.Tags["threadId"]; ok && thid != "" {
		upd.SetThreadId(thid)
	}
	outboundCtx := models.NewOutboundMessageContext(upd, models.OutboundMessageContextParams{
		AgentContext:     a.context,
		Connection:       rec,
		AssociatedRecord: nil,
	})
	return a.messageSender.SendMessage(outboundCtx)
}

// SendMessage sends a message to a connection
func (a *Agent) SendMessage(message interface{}, connectionId string) error {
	if !a.isInitialized {
		return fmt.Errorf("agent must be initialized before sending messages")
	}

	log.Printf("📤 Sending message to connection: %s", connectionId)

	// Get the connection record
	connection, err := a.connectionService.FindById(connectionId)
	if err != nil {
		return fmt.Errorf("failed to get connection: %w", err)
	}

	// Convert the message to AgentMessage
	var agentMessage messages.AgentMessage
	if msg, ok := message.(messages.AgentMessage); ok {
		agentMessage = msg
	} else {
		// Create a BaseMessage wrapper for non-AgentMessage types
		baseMsg := messages.NewBaseMessage("generic-message")
		if msgWithType, ok := message.(interface{ GetType() string }); ok {
			baseMsg.SetType(msgWithType.GetType())
		}
		// Store the original message in the body
		baseMsg.Body = map[string]interface{}{
			"content": message,
		}
		agentMessage = baseMsg
	}

	// Send the message
	outboundCtx := models.NewOutboundMessageContext(agentMessage, models.OutboundMessageContextParams{
		AgentContext:     a.context,
		Connection:       connection,
		AssociatedRecord: nil,
	})
	err = a.messageSender.SendMessage(outboundCtx)
	if err != nil {
		return fmt.Errorf("failed to send message: %w", err)
	}

	log.Printf("✅ Message sent successfully")
	return nil
}

// extractEndpointFromConnection extracts endpoint from connection record
func extractEndpointFromConnection(ctx *context.AgentContext, connection *services.ConnectionRecord) string {
	if connection == nil {
		return ""
	}

	// Prefer endpoint already on the connection record
	if connection.TheirEndpoint != "" {
		return connection.TheirEndpoint
	}

	return ""
}

// GetConnection retrieves a connection by ID
func (a *Agent) GetConnection(connectionId string) (*services.ConnectionRecord, error) {
	if !a.isInitialized {
		return nil, fmt.Errorf("agent must be initialized")
	}

	return a.connectionService.FindById(connectionId)
}

// GetConnections retrieves all connections
func (a *Agent) GetConnections() ([]*services.ConnectionRecord, error) {
	if !a.isInitialized {
		return nil, fmt.Errorf("agent must be initialized")
	}

	return a.connectionService.GetAllConnections()
}

// CreateKey creates a new cryptographic key
func (a *Agent) CreateKey(keyType wallet.KeyType) (*wallet.Key, error) {
	if !a.isInitialized {
		return nil, fmt.Errorf("agent must be initialized")
	}

	return a.walletService.CreateKey(keyType)
}

// Sign signs data with a key
func (a *Agent) Sign(keyId string, data []byte) ([]byte, error) {
	if !a.isInitialized {
		return nil, fmt.Errorf("agent must be initialized")
	}

	return a.walletService.Sign(keyId, data)
}

// Verify verifies a signature
func (a *Agent) Verify(keyId string, data []byte, signature []byte) (bool, error) {
	if !a.isInitialized {
		return false, fmt.Errorf("agent must be initialized")
	}

	return a.walletService.Verify(keyId, data, signature)
}

// IsInitialized returns whether the agent is initialized
func (a *Agent) IsInitialized() bool {
	return a.isInitialized
}

// GetConfig returns the agent configuration
func (a *Agent) GetConfig() *context.AgentConfig {
	return a.config
}

// GetContext returns the agent context
func (a *Agent) GetContext() *context.AgentContext { return a.context }

// GetDependencyManager exposes the DI manager (preferred)
func (a *Agent) GetDependencyManager() di.DependencyManager { return a.diManager }

// Dids returns the high-level DidsApi from typed DI
func (a *Agent) Dids() interface{} {
	if a.diManager == nil {
		return nil
	}
	if any, err := a.diManager.Resolve(di.TokenDidsApi); err == nil {
		return any
	}
	return nil
}

// Credentials returns the high-level CredentialsApi from typed DI
func (a *Agent) Credentials() interface{} {
	if a.diManager == nil {
		return nil
	}
	if any, err := a.diManager.Resolve(di.TokenCredentialsApi); err == nil {
		return any
	}
	return nil
}

// AnonCreds returns the high-level AnonCredsApi from typed DI
func (a *Agent) AnonCreds() interface{} {
	if a.diManager == nil {
		return nil
	}
	if any, err := a.diManager.Resolve(di.TokenAnonCredsApi); err == nil {
		return any
	}
	return nil
}

// Proofs returns the Proofs API
func (a *Agent) Proofs() interface{} {
	if a.diManager == nil {
		return nil
	}
	if any, err := a.diManager.Resolve(di.TokenProofsApi); err == nil {
		return any
	}
	return nil
}

// GetWalletService returns the wallet service
func (a *Agent) GetWalletService() *wallet.WalletService {
	return a.walletService
}

// initializeWallet initializes the wallet service
func (a *Agent) initializeWallet() error {
	log.Printf("🔐 Initializing wallet service...")

	// Create an initial key if none exist
	keys, err := a.walletService.ListKeys()
	if err != nil {
		return fmt.Errorf("failed to list keys: %w", err)
	}

	if len(keys) == 0 {
		log.Printf("📱 Creating initial Ed25519 key...")
		key, err := a.walletService.CreateKey(wallet.KeyTypeEd25519)
		if err != nil {
			return fmt.Errorf("failed to create initial key: %w", err)
		}
		log.Printf("✅ Created initial key: %s", key.Id)
	}

	// Re-fetch after possible creation to log the correct count
	keys, err = a.walletService.ListKeys()
	if err != nil {
		return fmt.Errorf("failed to list keys after init: %w", err)
	}
	log.Printf("✅ Wallet service initialized with %d keys", len(keys))
	return nil
}

// extractEndpointFromInvitation extracts endpoint from invitation
func extractEndpointFromInvitation(invitation *oobMessages.OutOfBandInvitationMessage) string {
	services := invitation.GetServices()
	if len(services) > 0 {
		service := services[0] // Use first service
		if endpoint, ok := service.ServiceEndpoint.(string); ok {
			return endpoint
		}
	}
	return "http://localhost:3000" // Fallback
}

// extractRecipientKeysFromInvitation extracts recipient keys from invitation
func extractRecipientKeysFromInvitation(invitation *oobMessages.OutOfBandInvitationMessage) []string {
	services := invitation.GetServices()
	if len(services) > 0 {
		service := services[0] // Use first service

		// Convert did:key format to base58 public keys (for Credo compatibility)
		var base58Keys []string
		for _, didKey := range service.RecipientKeys {
			if strings.HasPrefix(didKey, "did:key:") {
				// Extract Base58 public key from did:key
				if publicKeyBase58, err := extractBase58KeyFromDidKey(didKey); err == nil {
					base58Keys = append(base58Keys, publicKeyBase58)
				} else {
					log.Printf("⚠️ Warning: Could not extract public key from did:key %s: %v", didKey, err)
				}
			} else {
				// Already in base58 format
				base58Keys = append(base58Keys, didKey)
			}
		}
		return base58Keys
	}
	return []string{}
}

// extractBase58KeyFromDidKey extracts the Base58 public key from a did:key DID
func extractBase58KeyFromDidKey(didKey string) (string, error) {
	// Extract the method-specific ID (everything after "did:key:")
	if !strings.HasPrefix(didKey, "did:key:") {
		return "", fmt.Errorf("not a valid did:key: %s", didKey)
	}

	methodSpecificId := strings.TrimPrefix(didKey, "did:key:")

	// The method-specific ID is base58btc encoded (z prefix)
	if !strings.HasPrefix(methodSpecificId, "z") {
		return "", fmt.Errorf("did:key must use base58btc encoding (z prefix)")
	}

	// Decode the base58btc part (remove 'z' prefix and decode)
	keyBytes, err := encoding.DecodeBase58(methodSpecificId[1:])
	if err != nil {
		return "", fmt.Errorf("failed to decode base58: %w", err)
	}

	log.Printf("🔍 Debug: did:key %s decoded to %d bytes: %x", didKey, len(keyBytes), keyBytes)

	// Parse multicodec prefix to get raw key bytes
	if len(keyBytes) < 2 {
		return "", fmt.Errorf("key data too short")
	}

	// Check for Ed25519 multicodec prefix (0xed = 237)
	// The multicodec might be encoded as a varint, let's handle both cases
	var rawPublicKey []byte
	if keyBytes[0] == 0xed {
		if len(keyBytes) >= 2 && keyBytes[1] == 0x01 {
			// Two-byte varint encoding: 0xed (codec) + 0x01 (length) + key data
			rawPublicKey = keyBytes[2:]
			log.Printf("🔍 Debug: found varint Ed25519 prefix (ed01), raw key length: %d", len(rawPublicKey))
		} else {
			// Simple case: single byte prefix
			rawPublicKey = keyBytes[1:]
			log.Printf("🔍 Debug: found single-byte Ed25519 prefix, raw key length: %d", len(rawPublicKey))
		}
	} else {
		return "", fmt.Errorf("unsupported key type, expected Ed25519 multicodec, got bytes: %x", keyBytes[:2])
	}

	if len(rawPublicKey) != 32 { // Ed25519 public key is 32 bytes
		return "", fmt.Errorf("invalid Ed25519 key length: expected 32, got %d", len(rawPublicKey))
	}

	base58Key := encoding.EncodeBase58(rawPublicKey)
	log.Printf("🔍 Debug: extracted Base58 key: %s", base58Key)
	return base58Key, nil
}

// getSenderKeyForConnection gets the sender key for a connection
func (a *Agent) getSenderKeyForConnection(connection *services.ConnectionRecord) (*wallet.Key, error) {
	// For now, return the first key we have
	keys, err := a.walletService.ListKeys()
	if err != nil {
		return nil, fmt.Errorf("failed to list keys: %w", err)
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("no keys available")
	}

	return keys[0], nil
}

// Run blocks until interrupted, keeping inbound transports alive (Credo-TS style)
func (a *Agent) Run() error {
	if !a.isInitialized {
		return fmt.Errorf("agent must be initialized before running")
	}
	// Block on SIGINT/SIGTERM
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
	<-sigc
	return a.Shutdown()
}
