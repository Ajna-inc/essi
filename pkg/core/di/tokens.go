package di

import (
	"errors"
	"fmt"

	contextpkg "github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/core/wallet"
)

var ErrDependencyNotFound = errors.New("dependency not found")

// Token is an identifier for dependencies
type Token struct {
	Name string
}

// Common tokens used across the agent
var (
	TokenLogger               = Token{Name: "Logger"}
	TokenEventBus             = Token{Name: "EventBus"}
	TokenStorageService       = Token{Name: "StorageService"}
	TokenKeyManagementService = Token{Name: "KeyManagementService"}
	TokenAgentConfig          = Token{Name: "AgentConfig"}
	TokenAgentContext         = Token{Name: "AgentContext"}
	TokenAgentContextProvider = Token{Name: "AgentContextProvider"}
	// Transport / messaging tokens
	TokenDispatcher             = Token{Name: "Dispatcher"}
	TokenMessageSender          = Token{Name: "MessageSender"}
	TokenMessageReceiver        = Token{Name: "MessageReceiver"}
	TokenMessageHandlerRegistry = Token{Name: "MessageHandlerRegistry"}
	// High-level module APIs
	TokenAnonCredsApi     = Token{Name: "AnonCredsApi"}
	TokenProofsApi        = Token{Name: "ProofsApi"}
	TokenProofsRepository = Token{Name: "Proofs.Repository"}
	TokenOobApi           = Token{Name: "OobApi"}
	// Legacy ConnectionsApi token removed (obsolete public API)
	// TokenConnectionsApi   = Token{Name: "ConnectionsApi"}
	TokenCredentialsApi = Token{Name: "CredentialsApi"}
	TokenDidsApi        = Token{Name: "DidsApi"}
	TokenDidRepository  = Token{Name: "DidRepository"}

	// Module configuration tokens (TS-like)
	TokenAutoAcceptCredentials = Token{Name: "AutoAcceptCredentials"}
	TokenAutoAcceptConnections = Token{Name: "AutoAcceptConnections"}
	// DID module extension points removed; modules own their methods (Credo-TS style)
	// Credentials module extension points
	TokenCredentialProtocols      = Token{Name: "Credentials.Protocols"}
	TokenCredentialFormatServices = Token{Name: "Credentials.FormatServices"}

	// Core service tokens (single DI system)
	TokenConnectionService           = Token{Name: "ConnectionService"}
	TokenWalletService               = Token{Name: "WalletService"}
	TokenEnvelopeService             = Token{Name: "EnvelopeService"}
	TokenEventBusService             = Token{Name: "EventBusService"}
	TokenCredentialsService          = Token{Name: "CredentialsService"}
	TokenCredentialsRepository       = Token{Name: "Credentials.Repository"}
	TokenCredentialAutoAcceptService = Token{Name: "Credentials.AutoAcceptService"}
	TokenMediatorService             = Token{Name: "MediatorService"}
	TokenProofsService               = Token{Name: "Proofs.Service"}

	// AnonCreds typed services
	TokenAnonCredsHolderService   = Token{Name: "AnonCreds.HolderService"}
	TokenAnonCredsIssuerService   = Token{Name: "AnonCreds.IssuerService"}
	TokenAnonCredsVerifierService = Token{Name: "AnonCreds.VerifierService"}
	TokenAnonCredsRegistryService = Token{Name: "AnonCreds.RegistryService"}
	TokenLinkSecretRepository     = Token{Name: "AnonCreds.LinkSecretRepository"}

	// Higher-level issuer used by DIDComm credential service for offers/issue
	TokenAnonCredsIssuer = Token{Name: "AnonCreds.Issuer"}
	// Core issuer that holds CL secrets for generating offers/credentials
	TokenAnonCredsCoreIssuer = Token{Name: "AnonCreds.CoreIssuer"}

	// Kanon typed services
	TokenKanonLedger                = Token{Name: "Kanon.Ledger"}
	TokenKanonEthereumLedgerService = Token{Name: "Kanon.EthereumLedgerService"}

	// Additional tokens for proof module
	TokenRegistryService             = Token{Name: "RegistryService"}
	TokenCredentialRepository        = Token{Name: "CredentialRepository"}
	TokenAnonCredsProofFormatService = Token{Name: "AnonCredsProofFormatService"}
	TokenProofsModuleConfig          = Token{Name: "ProofsModuleConfig"}

	// Message and routing tokens
	TokenDidCommMessageRepository = Token{Name: "DidCommMessageRepository"}
	TokenOutOfBandRepository      = Token{Name: "OutOfBandRepository"}
	TokenOutOfBandService         = Token{Name: "OutOfBandService"}
	TokenRoutingService           = Token{Name: "RoutingService"}

	// Connection module specific tokens
	TokenConnectionRepository  = Token{Name: "ConnectionRepository"}
	TokenDidExchangeProtocol   = Token{Name: "DidExchangeProtocol"}
	TokenTrustPingService      = Token{Name: "TrustPingService"}
	TokenDidRotateService      = Token{Name: "DidRotateService"}
	TokenHandshakeReuseService = Token{Name: "HandshakeReuseService"}

	// Feature registry
	TokenFeatureRegistry = Token{Name: "FeatureRegistry"}

	// DID services
	TokenDidResolverService     = Token{Name: "DidResolverService"}
	TokenDidRegistrarService    = Token{Name: "DidRegistrarService"}
	TokenDidCommDocumentService = Token{Name: "DidCommDocumentService"}
	TokenReceivedDidRepository  = Token{Name: "ReceivedDidRepository"}

	// Crypto
	TokenJwsService = Token{Name: "JwsService"}
)

// TypedToken is a type-safe token with generic type information
type TypedToken[T any] struct {
	Name string
}

// NewTypedToken creates a new type-safe token
func NewTypedToken[T any](name string) TypedToken[T] {
	return TypedToken[T]{Name: name}
}

// ToToken converts a typed token to a regular token
func (tt TypedToken[T]) ToToken() Token {
	return Token{Name: tt.Name}
}

// Type-safe tokens for common services
var (
	TypedTokenWalletService = NewTypedToken[*wallet.WalletService]("WalletService")
	TypedTokenAgentContext  = NewTypedToken[*contextpkg.AgentContext]("AgentContext")
	// Add more typed tokens as needed when services are imported
)

// ResolveAs is a helper to cast resolved dependencies
func ResolveAs[T any](dm DependencyManager, token Token) (T, error) {
	var zero T
	v, err := dm.Resolve(token)
	if err != nil {
		return zero, err
	}
	if typed, ok := v.(T); ok {
		return typed, nil
	}
	return zero, fmt.Errorf("dependency '%s' has unexpected type", token.Name)
}

// ResolveTyped resolves a type-safe token
func ResolveTyped[T any](dm DependencyManager, token TypedToken[T]) (T, error) {
	return ResolveAs[T](dm, token.ToToken())
}
