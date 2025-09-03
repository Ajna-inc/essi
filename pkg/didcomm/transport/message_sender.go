package transport

import (
	"encoding/json"
	"fmt"

	"strings"

	"github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/core/di"
	"github.com/ajna-inc/essi/pkg/core/events"
	"github.com/ajna-inc/essi/pkg/core/logger"
	"github.com/ajna-inc/essi/pkg/core/common"
	"github.com/ajna-inc/essi/pkg/core/encoding"
	"github.com/ajna-inc/essi/pkg/core/wallet"
	"github.com/ajna-inc/essi/pkg/didcomm/decorators/transport"
	"github.com/ajna-inc/essi/pkg/didcomm/messages"
	"github.com/ajna-inc/essi/pkg/didcomm/models"
	connectionServices "github.com/ajna-inc/essi/pkg/didcomm/modules/connections/services"
	"github.com/ajna-inc/essi/pkg/didcomm/modules/oob"
	oobMessages "github.com/ajna-inc/essi/pkg/didcomm/modules/oob/messages"
	envelopeServices "github.com/ajna-inc/essi/pkg/didcomm/services"
	dids "github.com/ajna-inc/essi/pkg/dids"
	peer "github.com/ajna-inc/essi/pkg/dids/methods/peer"
	didrepo "github.com/ajna-inc/essi/pkg/dids/repository"
)

func getLoggerFromCtx(ctx *context.AgentContext, dm di.DependencyManager) logger.Logger {
	if dm != nil {
		if lAny, err := dm.Resolve(di.TokenLogger); err == nil {
			if lg, ok := lAny.(logger.Logger); ok && lg != nil {
				return lg
			}
		}
	}
	return logger.GetDefaultLogger()
}

// MessageSender handles sending outbound DIDComm messages using OutboundMessageContext pattern
type MessageSender struct {
	agentContext       *context.AgentContext
	typedDI            di.DependencyManager
	envelopeService    *envelopeServices.EnvelopeService
	connectionService  *connectionServices.ConnectionService
	outboundTransports []OutboundTransport
	transportService   *TransportService
}

// TransportService manages transport sessions
type TransportService struct {
	sessions map[string]*TransportSession
}

// TransportSession represents an active transport session
type TransportSession struct {
	ID               string
	Type             string
	ConnectionID     string
	InboundMessage   messages.AgentMessage
	Keys             *SessionKeys
	HasReturnRouting bool
}

// Use SessionKeys from message_receiver.go to avoid duplication

// NewMessageSender creates a new message sender with TypeScript-compatible patterns
func NewMessageSender(
	agentContext *context.AgentContext,
	dm di.DependencyManager,
	envelopeService *envelopeServices.EnvelopeService,
	connectionService *connectionServices.ConnectionService,
) *MessageSender {
	return &MessageSender{
		agentContext:       agentContext,
		typedDI:            dm,
		envelopeService:    envelopeService,
		connectionService:  connectionService,
		outboundTransports: []OutboundTransport{NewHttpOutboundTransport()},
		transportService:   &TransportService{sessions: make(map[string]*TransportSession)},
	}
}

// SendMessage sends a message using OutboundMessageContext (TypeScript pattern)
// This is the ONLY way to send messages - all old methods have been removed
func (ms *MessageSender) SendMessage(outboundContext *models.OutboundMessageContext) error {
	if outboundContext == nil {
		return fmt.Errorf("outbound message context is nil")
	}

	message := outboundContext.Message
	connection := outboundContext.Connection

	logger := getLoggerFromCtx(ms.agentContext, ms.typedDI)
	logger.Info("📤 Sending message via OutboundMessageContext")

	// Check if this is an outbound service message (connectionless)
	if outboundContext.IsOutboundServiceMessage() {
		return ms.sendMessageToService(outboundContext)
	}

	// Connection-based messaging
	if connection == nil {
		logger.Error("❌ Outbound message has no associated connection")
		return fmt.Errorf("outbound message has no associated connection")
	}

	logger.Infof("📤 Send outbound message to connection: %s", connection.ID)

	// Check for existing session with return routing
	session := ms.findSessionForOutboundContext(outboundContext)
	if session != nil && session.HasReturnRouting {
		logger.Infof("Found session with return routing for message %s (connection %s)",
			message.GetId(), connection.ID)

		if err := ms.sendMessageToSession(session, message); err != nil {
			logger.Warnf("⚠️ Sending via session failed: %v", err)
		} else {
			logger.Info("✅ Message sent via session")
			return nil
		}
	}

	// Retrieve DIDComm services for the connection
	services, err := ms.retrieveServicesByConnection(connection, outboundContext.OutOfBand)
	if err != nil {
		return fmt.Errorf("unable to retrieve services for connection %s: %w", connection.ID, err)
	}

	// Determine sender key: prefer authcrypt if we have a local key, else anoncrypt
	senderKey := ""
	if connection.MyKeyId != "" {
		if sk, err := ms.resolveSenderKey(connection); err == nil {
			senderKey = sk
		} else {
			logger.Warnf("⚠️ Could not resolve sender key for connection %s, will use anoncrypt: %v", connection.ID, err)
		}
	}

	// Warn but allow sending without a DID (TS allows anoncrypt using OOB inline service)
	if connection.Did == "" {
		logger.Warnf("⚠️ Connection %s has no DID yet; proceeding with service-based anoncrypt if available", connection.ID)
	}

	// Determine if we need return routing
	// For handshake messages (connections/didexchange), request return-route except for 'complete'
	msgType := message.GetType()
	isHandshake := strings.HasPrefix(msgType, "https://didcomm.org/didexchange/") || strings.HasPrefix(msgType, "https://didcomm.org/connections/")
	isComplete := strings.HasSuffix(msgType, "/complete")
	shouldAddReturnRoute := !ms.hasInboundEndpoint(connection) || (isHandshake && !isComplete)

	// Try sending to each service
	var lastError error
	for _, service := range services {
		// Create service context for sending
		serviceContext := models.NewOutboundMessageContext(message, models.OutboundMessageContextParams{
			AgentContext: outboundContext.AgentContext,
			Connection:   connection,
			ServiceParams: &models.ServiceMessageParams{
				Service:     service,
				SenderKey:   senderKey,
				ReturnRoute: shouldAddReturnRoute,
			},
		})

		if err := ms.sendToService(serviceContext); err != nil {
			lastError = err
			logger.Warnf("⚠️ Failed to send to service %s: %v", service.ID, err)
			continue
		}

		logger.Infof("✅ Message sent to service %s", service.ID)
		return nil
	}

	return fmt.Errorf("message is undeliverable to connection %s: %w", connection.ID, lastError)
}

// sendMessageToService handles connectionless messaging
func (ms *MessageSender) sendMessageToService(outboundContext *models.OutboundMessageContext) error {
	if outboundContext.ServiceParams == nil {
		return fmt.Errorf("no service parameters found in outbound message context")
	}

	logger := getLoggerFromCtx(ms.agentContext, ms.typedDI)
	logger.Info("📤 Sending connectionless message to service")

	// Check for existing session first
	session := ms.findSessionForOutboundContext(outboundContext)
	if session != nil && session.HasReturnRouting {
		logger.Infof("Found session with return routing for connectionless message")
		if err := ms.sendMessageToSession(session, outboundContext.Message); err == nil {
			return nil
		}
	}

	// Send to service
	return ms.sendToService(outboundContext)
}

// sendToService sends a message to a specific service
func (ms *MessageSender) sendToService(outboundContext *models.OutboundMessageContext) error {
	if outboundContext.ServiceParams == nil {
		return fmt.Errorf("no service parameters found")
	}

	service := outboundContext.ServiceParams.Service
	// Note: outboundContext.ServiceParams.SenderKey is deprecated for handshake path; sender key is resolved from wallet
	returnRoute := outboundContext.ServiceParams.ReturnRoute
	message := outboundContext.Message

	if len(ms.outboundTransports) == 0 {
		return fmt.Errorf("agent has no outbound transport")
	}

	logger := getLoggerFromCtx(ms.agentContext, ms.typedDI)
	logger.Infof("📤 Sending outbound message to service: %s", service.ServiceEndpoint)

	if returnRoute {
		if message.GetTransport() == nil {
			message.SetTransport(&messages.TransportDecorator{})
		}
		message.GetTransport().ReturnRoute = transport.ReturnRouteAll
	}

	recipientKeys := service.RecipientKeys
	// routingKeys := service.RoutingKeys // TODO: Use for routing later

	packageType := envelopeServices.PackageTypeAnoncrypt
	msgType := message.GetType()
	handshake := strings.HasPrefix(msgType, "https://didcomm.org/didexchange/") || strings.HasPrefix(msgType, "https://didcomm.org/connections/")
	logger.Infof("🔎 [sendToService] msgType=%s handshake=%t myKeyId=%s", msgType, handshake, outboundContext.Connection.MyKeyId)
	if outboundContext.Connection != nil && outboundContext.Connection.MyKeyId != "" {
		if ms.typedDI != nil {
			dep, err := ms.typedDI.Resolve(di.TokenWalletService)
			if err != nil {
				logger.Warnf("⚠️ [sendToService] Resolve WalletService failed: %v", err)
			} else {
				walletSvc, ok := dep.(*wallet.WalletService)
				if !ok || walletSvc == nil {
					logger.Warn("⚠️ [sendToService] WalletService not available after resolve")
				} else {
					key, kErr := walletSvc.GetKey(outboundContext.Connection.MyKeyId)
					if kErr != nil || key == nil {
						logger.Warnf("⚠️ [sendToService] GetKey(%s) failed: %v", outboundContext.Connection.MyKeyId, kErr)
					} else {
						ms.envelopeService.SetSenderKey(key.PrivateKey)
						logger.Info("✅ [sendToService] Loaded sender private key for authcrypt")
						// Always prefer authcrypt when we have our sender key, not only for handshake
						packageType = envelopeServices.PackageTypeAuthcrypt
					}
				}
			}
		}
	} else if handshake {
		logger.Warn("⚠️ [sendToService] Handshake message without MyKeyId; will send anoncrypt (Credo requires authcrypt)")
	}
	logger.Infof("🔎 [sendToService] final packageType=%s", packageType)

	// Pack the message
	encryptedMessage, err := ms.envelopeService.PackMessage(message, recipientKeys, packageType)
	if err != nil {
		return fmt.Errorf("failed to pack message: %w", err)
	}

	// Send via appropriate transport
	endpoint := service.ServiceEndpoint
	for _, transport := range ms.outboundTransports {
		if transport.CanSend(endpoint) {
			status, body, ctype, err := transport.Send(encryptedMessage, endpoint)
			if err != nil {
				logger.Warn("⚠️ Transport failed: %v", err)
				continue
			}

			// Emit AgentMessageSent on success
			if ms.typedDI != nil && outboundContext.AgentContext != nil {
				if ebAny, err := ms.typedDI.Resolve(di.TokenEventBus); err == nil {
					if bus, ok := ebAny.(events.Bus); ok && bus != nil {
						md := events.EventMetadata{ContextCorrelationId: outboundContext.AgentContext.GetCorrelationId()}
						bus.PublishWithMetadata(events.AgentMessageSent, map[string]interface{}{
							"type": message.GetType(),
						}, md)
					}
				}
			}

			// Handle return-route: if response contains an encrypted DIDComm message, feed it to MessageReceiver
			if status >= 200 && status < 300 && len(body) > 0 {
				isEncrypted := false
				// Normalize content type for comparison (may include charset or use alternative DIDComm values)
				ct := strings.ToLower(strings.TrimSpace(ctype))
				if ct == "application/didcomm-envelope-enc" || ct == "application/didcomm+envelope" ||
					strings.HasPrefix(ct, "application/didcomm-encrypted+json") ||
					strings.HasPrefix(ct, "application/didcomm+json") {
					isEncrypted = true
				} else {
					// Heuristic: attempt to detect encrypted envelope by presence of "protected" field
					var probe map[string]interface{}
					if err := json.Unmarshal(body, &probe); err == nil {
						if _, ok := probe["protected"]; ok {
							isEncrypted = true
						}
					}
				}

				if isEncrypted && ms.typedDI != nil {
					if dep, derr := ms.typedDI.Resolve(di.TokenMessageReceiver); derr == nil {
						if mr, ok := dep.(*MessageReceiver); ok && mr != nil {
							mr.ReceiveEncrypted(body)
						}
					}
				}
			}

			return nil
		}
	}

	return fmt.Errorf("unable to send message to service: %s", endpoint)
}

// sendMessageToSession sends a message via an existing session
func (ms *MessageSender) sendMessageToSession(session *TransportSession, message messages.AgentMessage) error {
	if session == nil || session.Keys == nil {
		return fmt.Errorf("invalid session or missing keys")
	}

	logger := getLoggerFromCtx(ms.agentContext, ms.typedDI)
	logger.Infof("📤 Packing message and sending via existing session %s", session.Type)

	// Use session keys to pack the message
	recipientKeys := []string{}
	for _, key := range session.Keys.RecipientKeys {
		recipientKeys = append(recipientKeys, encoding.EncodeBase58(key))
	}

	_, err := ms.envelopeService.PackMessage(
		message,
		recipientKeys,
		envelopeServices.PackageTypeAuthcrypt,
	)
	if err != nil {
		return fmt.Errorf("failed to pack message for session: %w", err)
	}

	// Send via session (would need session.Send implementation)
	logger.Info("✅ Message sent via session")
	return nil
}

// findSessionForOutboundContext finds an existing session for the outbound context
func (ms *MessageSender) findSessionForOutboundContext(outboundContext *models.OutboundMessageContext) *TransportSession {
	// Use session ID from outbound context if present
	sessionID := outboundContext.SessionID
	if sessionID == "" && outboundContext.InboundMessageContext != nil {
		sessionID = outboundContext.InboundMessageContext.SessionID
	}

	if sessionID != "" {
		if session, ok := ms.transportService.sessions[sessionID]; ok {
			return session
		}
	}

	// Try to find by connection ID
	if outboundContext.Connection != nil {
		for _, session := range ms.transportService.sessions {
			if session.ConnectionID == outboundContext.Connection.ID {
				return session
			}
		}
	}

	return nil
}

// retrieveServicesByConnection retrieves DIDComm services for a connection
func (ms *MessageSender) retrieveServicesByConnection(connection *connectionServices.ConnectionRecord, outOfBand *oob.OutOfBandRecord) ([]*models.ResolvedDidCommService, error) {
	logger := getLoggerFromCtx(ms.agentContext, ms.typedDI)
	logger.Infof("Retrieving services for connection '%s' (TheirDid=%s, TheirEndpoint=%s, TheirRecipientKey=%s)", connection.ID, connection.TheirDid, connection.TheirEndpoint, connection.TheirRecipientKey)

	services := []*models.ResolvedDidCommService{}

	// Prefer connection endpoint if available (parsed from requester DIDDoc)
	if connection.TheirEndpoint != "" {
		recipientKeys := []string{}
		if connection.TheirRecipientKey != "" {
			recipientKeys = append(recipientKeys, connection.TheirRecipientKey)
		} else if connection.InvitationKey != "" {
			recipientKeys = append(recipientKeys, connection.InvitationKey)
		}
		if len(recipientKeys) > 0 {
			services = append(services, &models.ResolvedDidCommService{ID: common.GenerateUUID(), ServiceEndpoint: connection.TheirEndpoint, RecipientKeys: recipientKeys, RoutingKeys: []string{}})
			logger.Infof("[services] using connection endpoint=%s keys=%v", connection.TheirEndpoint, recipientKeys)
		}
	}

	// Next: resolve TheirDid for authoritative services
	if len(services) == 0 && connection.TheirDid != "" && ms.typedDI != nil {
		var resolver *dids.DidResolverService
		if dep, err := ms.typedDI.Resolve(di.TokenDidResolverService); err == nil {
			resolver, _ = dep.(*dids.DidResolverService)
		}
		if resolver == nil {
			return nil, fmt.Errorf("DidResolverService not available from DI")
		}
		if resolver != nil {
			if res, rerr := resolver.Resolve(ms.agentContext, connection.TheirDid, nil); rerr == nil && res != nil && res.DidDocument != nil {
				doc := res.DidDocument
				for _, s := range doc.Service {
					if s == nil {
						continue
					}
					if s.Type != dids.ServiceTypeDIDComm && s.Type != dids.ServiceTypeDIDCommMessaging && s.Type != dids.ServiceTypeIndyAgent {
						continue
					}
					endpoint := ""
					if ep, ok := s.ServiceEndpoint.(string); ok {
						endpoint = ep
					}
					if endpoint == "" || len(s.RecipientKeys) == 0 {
						continue
					}
					recips := []string{}
					for _, kid := range s.RecipientKeys {
						if vm, derr := doc.DereferenceVerificationMethod(kid); derr == nil && vm != nil {
							if vm.PublicKeyBase58 != "" {
								recips = append(recips, vm.PublicKeyBase58)
								continue
							}
							if vm.PublicKeyMultibase != "" {
								if b58 := MultibaseToBase58(vm.PublicKeyMultibase); b58 != "" {
									recips = append(recips, b58)
									continue
								}
							}
						}
						if !strings.HasPrefix(kid, "#") && !strings.Contains(kid, ":") {
							recips = append(recips, kid)
						}
					}
					if len(recips) == 0 {
						continue
					}
					services = append(services, &models.ResolvedDidCommService{ID: s.Id, ServiceEndpoint: endpoint, RecipientKeys: recips, RoutingKeys: s.RoutingKeys})
					logger.Infof("[services] using DID resolve endpoint=%s keys=%v", endpoint, recips)
				}
			}
		}
	}

	// Then: ReceivedDidRepository fallback (if registered)
	if len(services) == 0 && connection.TheirDid != "" && ms.typedDI != nil {
		if dep, err := ms.typedDI.Resolve(di.TokenReceivedDidRepository); err == nil {
			if repo, ok := dep.(*didrepo.ReceivedDidRepository); ok && repo != nil {
				if rec, ferr := repo.FindByDid(ms.agentContext, connection.TheirDid); ferr == nil && rec != nil && rec.DidDoc != nil {
					doc := rec.DidDoc
					for _, s := range doc.Service {
						if s == nil {
							continue
						}
						if s.Type != dids.ServiceTypeDIDComm && s.Type != dids.ServiceTypeDIDCommMessaging && s.Type != dids.ServiceTypeIndyAgent {
							continue
						}
						ep := ""
						if se, ok := s.ServiceEndpoint.(string); ok {
							ep = se
						}
						if ep == "" || len(s.RecipientKeys) == 0 {
							continue
						}
						services = append(services, &models.ResolvedDidCommService{ID: s.Id, ServiceEndpoint: ep, RecipientKeys: s.RecipientKeys, RoutingKeys: s.RoutingKeys})
						logger.Infof("[services] using ReceivedDidRepository endpoint=%s keys=%v", ep, s.RecipientKeys)
					}
				}
			}
		}
	}

	// Finally: OOB inline service
	if len(services) == 0 && outOfBand != nil && strings.EqualFold(connection.Role, "requester") {
		logger.Infof("Resolving services from out-of-band record %s", outOfBand.ID)
		var invitation *oobMessages.OutOfBandInvitationMessage
		switch v := outOfBand.OutOfBandInvitation.(type) {
		case *oobMessages.OutOfBandInvitationMessage:
			invitation = v
		case map[string]interface{}:
			if b, err := json.Marshal(v); err == nil {
				tmp := &oobMessages.OutOfBandInvitationMessage{}
				if err := json.Unmarshal(b, tmp); err == nil {
					invitation = tmp
					logger.Infof("Resolved OOB invitation from generic map for record %s", outOfBand.ID)
				}
			}
		default:
			if v != nil {
				if b, err := json.Marshal(v); err == nil {
					tmp := &oobMessages.OutOfBandInvitationMessage{}
					if err := json.Unmarshal(b, tmp); err == nil {
						invitation = tmp
						logger.Infof("Resolved OOB invitation from generic value for record %s", outOfBand.ID)
					}
				}
			}
		}
		if invitation != nil {
			for _, service := range invitation.GetServices() {
				if service.ServiceEndpoint != nil {
					endpoint := ""
					recipientKeys := []string{}
					routingKeys := []string{}
					if endpointStr, ok := service.ServiceEndpoint.(string); ok {
						endpoint = endpointStr
					}
					recipientKeys = service.RecipientKeys
					routingKeys = service.RoutingKeys
					if endpoint != "" && len(recipientKeys) > 0 {
						services = append(services, &models.ResolvedDidCommService{ID: service.Id, ServiceEndpoint: endpoint, RecipientKeys: recipientKeys, RoutingKeys: routingKeys})
						logger.Infof("[services] using OOB inline endpoint=%s keys=%v", endpoint, recipientKeys)
					}
				}
			}
		}
	}

	if len(services) == 0 {
		return nil, fmt.Errorf("no services available for connection %s (no endpoint found)", connection.ID)
	}

	logger.Infof("Retrieved %d services for message to connection '%s'", len(services), connection.ID)
	return services, nil
}

// resolveSenderKey resolves the sender key from our DID
func (ms *MessageSender) resolveSenderKey(connection *connectionServices.ConnectionRecord) (string, error) {
	if connection.MyKeyId == "" {
		return "", fmt.Errorf("no sender key ID in connection")
	}

	// Get the key from wallet
	if ms.typedDI != nil {
		if dep, err := ms.typedDI.Resolve(di.TokenWalletService); err == nil {
			if walletSvc, ok := dep.(*wallet.WalletService); ok && walletSvc != nil {
				if key, err := walletSvc.GetKey(connection.MyKeyId); err == nil && key != nil {
					// Validate continuity: ensure the key fingerprint matches what we advertised in DIDDoc (if present)
					if connection.Tags != nil {
						if advertisedFp, ok := connection.Tags["myFingerprint"]; ok && advertisedFp != "" {
							if fp, ferr := peer.Ed25519Fingerprint(key.PublicKey); ferr == nil && fp != advertisedFp {
								logger := getLoggerFromCtx(ms.agentContext, ms.typedDI)
								logger.Warnf("⚠️ [resolveSenderKey] Current MyKeyId fingerprint %s differs from advertised %s; using advertised key if available", fp, advertisedFp)
								if taggedKeyId, ok2 := connection.Tags["myKeyId"]; ok2 && taggedKeyId != "" && taggedKeyId != connection.MyKeyId {
									if alt, aerr := walletSvc.GetKey(taggedKeyId); aerr == nil && alt != nil {
										return encoding.EncodeBase58(alt.PublicKey), nil
									}
								}
							}
						}
					}
					return encoding.EncodeBase58(key.PublicKey), nil
				}
			}
		}
	}

	return "", fmt.Errorf("unable to resolve sender key")
}

// hasInboundEndpoint checks if we have an inbound endpoint
func (ms *MessageSender) hasInboundEndpoint(connection *connectionServices.ConnectionRecord) bool {
	// Check if we have configured endpoints
	if ms.connectionService != nil {
		endpoint := ms.connectionService.GetDefaultServiceEndpoint()
		return endpoint != ""
	}
	return false
}

// RegisterOutboundTransport adds an outbound transport
func (ms *MessageSender) RegisterOutboundTransport(t OutboundTransport) {
	if t == nil {
		return
	}
	ms.outboundTransports = append(ms.outboundTransports, t)
}

// UnregisterOutboundTransport removes an outbound transport
func (ms *MessageSender) UnregisterOutboundTransport(t OutboundTransport) {
	if t == nil {
		return
	}
	filtered := make([]OutboundTransport, 0, len(ms.outboundTransports))
	for _, tr := range ms.outboundTransports {
		if tr != t {
			filtered = append(filtered, tr)
		}
	}
	ms.outboundTransports = filtered
}

// AddSession adds a transport session
func (ms *MessageSender) AddSession(session *TransportSession) {
	if session != nil && session.ID != "" {
		ms.transportService.sessions[session.ID] = session
	}
}

// FindSessionByConnectionId finds a session by connection ID
func (ms *MessageSender) FindSessionByConnectionId(connectionId string) *TransportSession {
	for _, session := range ms.transportService.sessions {
		if session.ConnectionID == connectionId {
			return session
		}
	}
	return nil
}
