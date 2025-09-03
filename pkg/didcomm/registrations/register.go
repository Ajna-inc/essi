package registrations

import (
	"log"

	"github.com/ajna-inc/essi/pkg/core/logger"
	basicHandlers "github.com/ajna-inc/essi/pkg/didcomm/modules/basic/handlers"
	connectionHandlers "github.com/ajna-inc/essi/pkg/didcomm/modules/connections/handlers"
	credentialHandlers "github.com/ajna-inc/essi/pkg/didcomm/modules/credentials/handlers"
	messagepickupHandlers "github.com/ajna-inc/essi/pkg/didcomm/modules/messagepickup/handlers"
	oobHandlers "github.com/ajna-inc/essi/pkg/didcomm/modules/oob/handlers"
	routingHandlers "github.com/ajna-inc/essi/pkg/didcomm/modules/routing/handlers"
	"github.com/ajna-inc/essi/pkg/didcomm/transport"
)

func RegisterAllModuleHandlers(registry *transport.MessageHandlerRegistry) {
	log.Printf("🔧 Registering handlers from all modules (registrations)...")

	// OOB
	registry.RegisterMessageHandler("https://didcomm.org/out-of-band/1.1/handshake-reuse", oobHandlers.OobHandshakeReuseHandlerFunc)
	registry.RegisterMessageHandler("https://didcomm.org/out-of-band/1.1/handshake-reuse-accepted", oobHandlers.OobHandshakeReuseAcceptedHandlerFunc)

	// Connections 1.0
	registry.RegisterMessageHandler("https://didcomm.org/connections/1.0/request", connectionHandlers.ConnectionRequestHandlerFunc)
	registry.RegisterMessageHandler("https://didcomm.org/connections/1.0/response", connectionHandlers.ConnectionResponseHandlerFunc)
	registry.RegisterMessageHandler("https://didcomm.org/connections/1.0/ack", connectionHandlers.ConnectionAckHandlerFunc)
	registry.RegisterMessageHandler("did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/connections/1.0/request", connectionHandlers.ConnectionRequestHandlerFunc)
	registry.RegisterMessageHandler("did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/connections/1.0/response", connectionHandlers.ConnectionResponseHandlerFunc)

	// Trust Ping
	registry.RegisterMessageHandler("https://didcomm.org/trust_ping/1.0/ping", connectionHandlers.TrustPingHandlerFunc)
	registry.RegisterMessageHandler("https://didcomm.org/trust_ping/1.0/ping_response", connectionHandlers.TrustPingResponseHandlerFunc)
	registry.RegisterMessageHandler("https://didcomm.org/trust-ping/1.0/ping", connectionHandlers.TrustPingHandlerFunc)
	registry.RegisterMessageHandler("https://didcomm.org/trust-ping/1.0/ping_response", connectionHandlers.TrustPingResponseHandlerFunc)

	// DidExchange 1.1
	registry.RegisterMessageHandler("https://didcomm.org/didexchange/1.1/request", connectionHandlers.DidExchangeRequestHandlerFunc)
	registry.RegisterMessageHandler("https://didcomm.org/didexchange/1.1/response", connectionHandlers.DidExchangeResponseHandlerFunc)
	registry.RegisterMessageHandler("https://didcomm.org/didexchange/1.1/complete", connectionHandlers.DidExchangeCompleteHandlerFunc)
	// Problem report (temporary: reuse basic problem report handler)
	registry.RegisterMessageHandler("https://didcomm.org/didexchange/1.1/problem-report", basicHandlers.ProblemReportHandlerFunc)

	// Did-Rotate 1.0
	registry.RegisterMessageHandler("https://didcomm.org/did-rotate/1.0/rotate", connectionHandlers.DidRotateHandlerFunc)
	registry.RegisterMessageHandler("https://didcomm.org/did-rotate/1.0/ack", connectionHandlers.DidRotateAckHandlerFunc)
	registry.RegisterMessageHandler("https://didcomm.org/did-rotate/1.0/hangup", connectionHandlers.DidRotateHangupHandlerFunc)

	// Credentials v1
	registry.RegisterMessageHandler("https://didcomm.org/issue-credential/1.0/propose-credential", credentialHandlers.CredentialsProposeV1HandlerFunc)
	registry.RegisterMessageHandler("https://didcomm.org/issue-credential/1.0/offer-credential", credentialHandlers.CredentialsOfferV1HandlerFunc)
	registry.RegisterMessageHandler("https://didcomm.org/issue-credential/1.0/request-credential", credentialHandlers.CredentialsRequestV1HandlerFunc)
	registry.RegisterMessageHandler("https://didcomm.org/issue-credential/1.0/issue-credential", credentialHandlers.CredentialsIssueV1HandlerFunc)
	registry.RegisterMessageHandler("https://didcomm.org/issue-credential/1.0/ack", credentialHandlers.CredentialsAckHandlerFunc)

	// Credentials v2
	registry.RegisterMessageHandler("https://didcomm.org/issue-credential/2.0/propose-credential", credentialHandlers.CredentialsProposeV2HandlerFunc)
	registry.RegisterMessageHandler("https://didcomm.org/issue-credential/2.0/offer-credential", credentialHandlers.CredentialsOfferHandlerFunc)
	registry.RegisterMessageHandler("https://didcomm.org/issue-credential/2.0/request-credential", credentialHandlers.CredentialsRequestHandlerFunc)
	registry.RegisterMessageHandler("https://didcomm.org/issue-credential/2.0/issue-credential", credentialHandlers.CredentialsIssueHandlerFunc)
	registry.RegisterMessageHandler("https://didcomm.org/issue-credential/2.0/ack", credentialHandlers.CredentialsAckV2HandlerFunc)
	registry.RegisterMessageHandler("https://didcomm.org/issue-credential/2.0/problem-report", credentialHandlers.CredentialsProblemReportV2HandlerFunc)
	registry.RegisterMessageHandler("https://didcomm.org/revocation_notification/2.0/revoke", credentialHandlers.V2RevocationNotificationHandlerFunc)

	// Routing
	registry.RegisterMessageHandler("https://didcomm.org/routing/1.0/forward", routingHandlers.ForwardHandlerFunc)
	registry.RegisterMessageHandler("https://didcomm.org/coordinate-mediation/1.0/mediate-request", routingHandlers.MediationRequestHandlerFunc)
	registry.RegisterMessageHandler("https://didcomm.org/coordinate-mediation/1.0/mediate-grant", routingHandlers.MediationGrantHandlerFunc)
	registry.RegisterMessageHandler("https://didcomm.org/coordinate-mediation/1.0/mediate-deny", routingHandlers.MediationDenyHandlerFunc)
	registry.RegisterMessageHandler("https://didcomm.org/coordinate-mediation/1.0/keylist-update", routingHandlers.KeylistUpdateHandlerFunc)
	// No specific inbound handler for keylist-update-response in this codebase

	// Message Pickup
	registry.RegisterMessageHandler("https://didcomm.org/messagepickup/1.0/batch", messagepickupHandlers.V1BatchHandlerFunc)
	registry.RegisterMessageHandler("https://didcomm.org/messagepickup/2.0/delivery", messagepickupHandlers.V2DeliveryHandlerFunc)

	// Basic messages and problem report
	registry.RegisterMessageHandler(basicHandlers.BasicMessageType, basicHandlers.BasicMessageHandlerFunc)
	registry.RegisterMessageHandler(basicHandlers.ProblemReportType, basicHandlers.ProblemReportHandlerFunc)

	logger.GetDefaultLogger().Info("✅ All module handlers registered (registrations)")
}
