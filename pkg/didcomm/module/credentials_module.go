package module

import (
	"fmt"

	contextpkg "github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/core/di"
	coreevents "github.com/ajna-inc/essi/pkg/core/events"
	corestorage "github.com/ajna-inc/essi/pkg/core/storage"
	"github.com/ajna-inc/essi/pkg/didcomm/messages"
	"github.com/ajna-inc/essi/pkg/didcomm/models"
	connservices "github.com/ajna-inc/essi/pkg/didcomm/modules/connections/services"
	formats "github.com/ajna-inc/essi/pkg/didcomm/modules/credentials/formats"
	handlers "github.com/ajna-inc/essi/pkg/didcomm/modules/credentials/handlers"
	credmsgs "github.com/ajna-inc/essi/pkg/didcomm/modules/credentials/messages"
	protocols "github.com/ajna-inc/essi/pkg/didcomm/modules/credentials/protocols"
	credrecs "github.com/ajna-inc/essi/pkg/didcomm/modules/credentials/records"
	credrepo "github.com/ajna-inc/essi/pkg/didcomm/modules/credentials/repository"
	credsvc "github.com/ajna-inc/essi/pkg/didcomm/modules/credentials/services"
	outboundServices "github.com/ajna-inc/essi/pkg/didcomm/services"
	"github.com/ajna-inc/essi/pkg/didcomm/transport"
)

// CredentialsModule exposes an API over the CredentialService via DI
type CredentialsModule struct {
	dm  di.DependencyManager
	cfg *CredentialsModuleConfig
}

type CredentialsModuleConfig struct {
	AutoAcceptCredentials    string // "always", "contentApproved", or "never"
	CredentialProtocols      []protocols.CredentialProtocol
	CredentialFormatServices []formats.CredentialFormatService
}

func NewCredentialsModule(opts ...*CredentialsModuleConfig) *CredentialsModule {
	var cfg *CredentialsModuleConfig
	if len(opts) > 0 {
		cfg = opts[0]
	}
	return &CredentialsModule{cfg: cfg}
}

func (m *CredentialsModule) Register(dm di.DependencyManager) error {
	m.dm = dm
	if m.cfg != nil {
		dm.RegisterInstance(di.TokenAutoAcceptCredentials, m.cfg.AutoAcceptCredentials)
		if len(m.cfg.CredentialProtocols) > 0 {
			dm.RegisterInstance(di.TokenCredentialProtocols, m.cfg.CredentialProtocols)
		}
		if len(m.cfg.CredentialFormatServices) > 0 {
			dm.RegisterInstance(di.TokenCredentialFormatServices, m.cfg.CredentialFormatServices)
		}
	}

	// Register repository as singleton -
	// The repository will get StorageService and EventBus injected when created
	dm.RegisterSingleton(di.TokenCredentialsRepository, func(deps di.DependencyManager) (interface{}, error) {
		// Resolve storage service (provided by Askar) - REQUIRED, no fallback
		storageService, err := deps.Resolve(di.TokenStorageService)
		if err != nil {
			return nil, fmt.Errorf("StorageService is required for CredentialRepository: %w", err)
		}

		// Resolve event bus
		var eventBus coreevents.Bus
		if eb, err := deps.Resolve(di.TokenEventBus); err == nil {
			eventBus, _ = eb.(coreevents.Bus)
		}

		// Create repository with injected dependencies
		return credrepo.NewCredentialRepository(
			storageService.(corestorage.StorageService),
			eventBus,
		), nil
	})

	return nil
}

func (m *CredentialsModule) OnInitializeContext(ctx *contextpkg.AgentContext) error {
	// Set auto-accept configuration on agent context
	if m.cfg != nil && m.cfg.AutoAcceptCredentials != "" && ctx.Config != nil {
		ctx.Config.AutoAcceptCredentials = m.cfg.AutoAcceptCredentials
	}

	// Register credential handlers via typed registry
	if m.dm != nil {
		if any, err := m.dm.Resolve(di.TokenMessageHandlerRegistry); err == nil {
			if reg, ok := any.(*transport.MessageHandlerRegistry); ok {
				// V1.0 protocol handlers (RFC 0036)
				reg.RegisterMessageHandler("https://didcomm.org/issue-credential/1.0/propose-credential", handlers.CredentialsProposeV1HandlerFunc)
				reg.RegisterMessageHandler("https://didcomm.org/issue-credential/1.0/offer-credential", handlers.CredentialsOfferV1HandlerFunc)
				reg.RegisterMessageHandler("https://didcomm.org/issue-credential/1.0/request-credential", handlers.CredentialsRequestV1HandlerFunc)
				reg.RegisterMessageHandler("https://didcomm.org/issue-credential/1.0/issue-credential", handlers.CredentialsIssueV1HandlerFunc)
				reg.RegisterMessageHandler("https://didcomm.org/issue-credential/1.0/ack", handlers.CredentialsAckHandlerFunc)

				// V2.0 protocol handlers (RFC 0453)
				reg.RegisterMessageHandler("https://didcomm.org/issue-credential/2.0/propose-credential", handlers.CredentialsProposeV2HandlerFunc)
				reg.RegisterMessageHandler("https://didcomm.org/issue-credential/2.0/offer-credential", handlers.CredentialsOfferHandlerFunc)
				reg.RegisterMessageHandler("https://didcomm.org/issue-credential/2.0/request-credential", handlers.CredentialsRequestHandlerFunc)
				reg.RegisterMessageHandler("https://didcomm.org/issue-credential/2.0/issue-credential", handlers.CredentialsIssueHandlerFunc)
				reg.RegisterMessageHandler("https://didcomm.org/issue-credential/2.0/ack", handlers.CredentialsAckV2HandlerFunc)
				reg.RegisterMessageHandler("https://didcomm.org/issue-credential/2.0/problem-report", handlers.CredentialsProblemReportV2HandlerFunc)

				// Common handlers
				reg.RegisterMessageHandler("https://didcomm.org/notification/1.0/ack", handlers.CredentialsAckHandlerFunc)
				// Revocation notification v2
				reg.RegisterMessageHandler("https://didcomm.org/revocation_notification/2.0/revoke", handlers.V2RevocationNotificationHandlerFunc)
			}
		}
	}
	// Resolve repository to create credential service
	var repo credrecs.Repository
	if m.dm != nil {
		if any, err := m.dm.Resolve(di.TokenCredentialsRepository); err == nil {
			repo, _ = any.(credrecs.Repository)
		}
	}
	if repo == nil {
		return fmt.Errorf("CredentialRepository is required for CredentialService")
	}

	// Create credential service with repository
	service := credsvc.NewCredentialService(ctx, m.dm, repo)

	// Register the service
	if m.dm != nil {
		m.dm.RegisterInstance(di.TokenCredentialsService, service)
		// Register auto-accept service for DI consumers
		m.dm.RegisterInstance(di.TokenCredentialAutoAcceptService, credsvc.NewCredentialAutoAcceptService(ctx, service))
	}

	// Resolve helpers from typed DI
	var (
		sender *transport.MessageSender
		conns  *connservices.ConnectionService
	)
	if any, err := m.dm.Resolve(di.TokenMessageSender); err == nil {
		sender, _ = any.(*transport.MessageSender)
	}
	if any, err := m.dm.Resolve(di.TokenConnectionService); err == nil {
		conns, _ = any.(*connservices.ConnectionService)
	}

	api := &CredentialsApi{ctx: ctx, svc: service, sender: sender, conns: conns}
	if m.dm != nil {
		m.dm.RegisterInstance(di.TokenCredentialsApi, api)
	}
	return nil
}

func (m *CredentialsModule) OnShutdown(ctx *contextpkg.AgentContext) error { return nil }

// CredentialsApi provides convenience methods for the credential exchange
type CredentialsApi struct {
	ctx    *contextpkg.AgentContext
	svc    *credsvc.CredentialService
	sender *transport.MessageSender
	conns  *connservices.ConnectionService
}

// AcceptOffer processes an offer and sends a request
func (a *CredentialsApi) AcceptOffer(threadId string, connectionId string, offer *credmsgs.OfferCredentialV2) error {
	if a.svc == nil || a.sender == nil || a.conns == nil {
		return fmt.Errorf("credentials api not fully configured")
	}
	req, _, err := a.svc.ProcessOffer(threadId, connectionId, offer)
	if err != nil {
		return err
	}
	rec, err := a.conns.FindById(connectionId)
	if err != nil {
		return err
	}
	outboundCtx, err := outboundServices.GetOutboundMessageContext(
		a.ctx,
		outboundServices.GetOutboundMessageContextParams{
			Message:             req,
			ConnectionRecord:    rec,
			AssociatedRecord:    nil,
			LastReceivedMessage: offer,
		},
	)
	if err != nil {
		return err
	}
	return a.sender.SendMessage(outboundCtx)
}

// AcceptRequest (issuer) processes a request and sends an issue-credential
func (a *CredentialsApi) AcceptRequest(threadId string, connectionId string, request *credmsgs.RequestCredentialV2) error {
	if a.svc == nil || a.sender == nil || a.conns == nil {
		return fmt.Errorf("credentials api not fully configured")
	}
	issue, err := a.svc.ProcessRequest(threadId, connectionId, request)
	if err != nil {
		return err
	}
	rec, err := a.conns.FindById(connectionId)
	if err != nil {
		return err
	}
	outboundCtx, err := outboundServices.GetOutboundMessageContext(
		a.ctx,
		outboundServices.GetOutboundMessageContextParams{
			Message:             issue,
			ConnectionRecord:    rec,
			AssociatedRecord:    nil,
			LastReceivedMessage: request,
		},
	)
	if err != nil {
		return err
	}
	return a.sender.SendMessage(outboundCtx)
}

// AckIssue processes an issue-credential and sends ack
func (a *CredentialsApi) AckIssue(threadId string, connectionId string, issued *credmsgs.IssueCredentialV2Credential) error {
	if a.svc == nil || a.sender == nil || a.conns == nil {
		return fmt.Errorf("credentials api not fully configured")
	}
	ack, err := a.svc.ProcessIssue(threadId, connectionId, issued)
	if err != nil {
		return err
	}
	rec, err := a.conns.FindById(connectionId)
	if err != nil {
		return err
	}
	outboundCtx, err := outboundServices.GetOutboundMessageContext(
		a.ctx,
		outboundServices.GetOutboundMessageContextParams{
			Message:             ack,
			ConnectionRecord:    rec,
			AssociatedRecord:    nil,
			LastReceivedMessage: issued,
		},
	)
	if err != nil {
		return err
	}
	return a.sender.SendMessage(outboundCtx)
}

// OfferCredentialV2 builds and sends a v2 offer for the given cred def and attributes
func (a *CredentialsApi) OfferCredentialV2(connectionId string, credentialDefinitionId string, attributes map[string]string) error {
	if a.svc == nil || a.sender == nil || a.conns == nil {
		return fmt.Errorf("credentials api not fully configured")
	}
	thid := "thid-" + connectionId
	offer, _, err := a.svc.CreateOffer(thid, connectionId, credentialDefinitionId, attributes)
	if err != nil {
		return err
	}
	rec, err := a.conns.FindById(connectionId)
	if err != nil {
		return err
	}
	outboundCtx := models.NewOutboundMessageContext(offer, models.OutboundMessageContextParams{
		AgentContext:     a.ctx,
		Connection:       rec,
		AssociatedRecord: nil,
	})
	return a.sender.SendMessage(outboundCtx)
}

// SendRevocationNotificationV2 sends a revocation notification (v2) for anoncreds
func (a *CredentialsApi) SendRevocationNotificationV2(connectionId string, revocationRegistryId string, credentialRevocationId string, comment string) error {
	if a.sender == nil || a.conns == nil {
		return fmt.Errorf("credentials api not fully configured")
	}
	rec, err := a.conns.FindById(connectionId)
	if err != nil {
		return err
	}
	msg := &handlers.V2RevocationNotification{
		BaseMessage:      messages.NewBaseMessage(handlers.V2RevocationNotificationType),
		Comment:          comment,
		RevocationFormat: "anoncreds",
		CredentialId:     fmt.Sprintf("%s::%s", revocationRegistryId, credentialRevocationId),
	}
	outboundCtx := models.NewOutboundMessageContext(msg, models.OutboundMessageContextParams{
		AgentContext:     a.ctx,
		Connection:       rec,
		AssociatedRecord: nil,
	})
	return a.sender.SendMessage(outboundCtx)
}
