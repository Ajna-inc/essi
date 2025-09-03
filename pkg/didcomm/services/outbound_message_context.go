package services

import (
	"fmt"
	"log"
	"strings"

	"github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/core/di"
	"github.com/ajna-inc/essi/pkg/core/common"
	"github.com/ajna-inc/essi/pkg/core/utils"
	"github.com/ajna-inc/essi/pkg/didcomm/decorators/service"
	"github.com/ajna-inc/essi/pkg/didcomm/messages"
	"github.com/ajna-inc/essi/pkg/didcomm/models"
	"github.com/ajna-inc/essi/pkg/didcomm/modules/connections/services"
	"github.com/ajna-inc/essi/pkg/didcomm/modules/oob"
	oobpkg "github.com/ajna-inc/essi/pkg/didcomm/modules/oob"
	oobmessages "github.com/ajna-inc/essi/pkg/didcomm/modules/oob/messages"
	"github.com/ajna-inc/essi/pkg/didcomm/modules/routing"
	"github.com/ajna-inc/essi/pkg/didcomm/repository"
	"github.com/ajna-inc/essi/pkg/dids"
)

// GetOutboundMessageContextParams contains parameters for getting outbound context
type GetOutboundMessageContextParams struct {
	Message             messages.AgentMessage
	ConnectionRecord    *services.ConnectionRecord
	AssociatedRecord    interface{}
	LastReceivedMessage messages.AgentMessage
	LastSentMessage     messages.AgentMessage
}

// GetOutboundMessageContext gets the outbound message context for a message
// Will use the connection record if available, otherwise try to create a connectionless message context
func GetOutboundMessageContext(
	agentContext *context.AgentContext,
	params GetOutboundMessageContextParams,
) (*models.OutboundMessageContext, error) {

	// If we have a connection record, use it
	if params.ConnectionRecord != nil {
		log.Printf("Creating outbound message context for message %s with connection %s",
			params.Message.GetId(), params.ConnectionRecord.ID)

		// Sanity: for connection-based credential and proof messages, ensure no connection-less decorators leak in
		msgType := params.Message.GetType()
		if strings.HasPrefix(msgType, "https://didcomm.org/issue-credential/") || strings.HasPrefix(msgType, "https://didcomm.org/present-proof/") {
			if th := params.Message.GetThread(); th != nil {
				// Clear any parent thread id/pthid that could make receivers treat it as connection-less
				th.ParentThreadId = ""
				th.Pthid = ""
				params.Message.SetThread(th)
			}
		}

		return models.NewOutboundMessageContext(params.Message, models.OutboundMessageContextParams{
			AgentContext:     agentContext,
			AssociatedRecord: params.AssociatedRecord,
			Connection:       params.ConnectionRecord,
		}), nil
	}

	// For connectionless, we need last received message
	if params.LastReceivedMessage == nil {
		return nil, fmt.Errorf("no connection record and no lastReceivedMessage was supplied. For connection-less exchanges the lastReceivedMessage is required")
	}

	if params.AssociatedRecord == nil {
		return nil, fmt.Errorf("no associated record was supplied. This is required for connection-less exchanges to store the associated ~service decorator on the message")
	}

	// Create connectionless context
	return GetConnectionlessOutboundMessageContext(agentContext, ConnectionlessParams{
		Message:             params.Message,
		AssociatedRecord:    params.AssociatedRecord,
		LastReceivedMessage: params.LastReceivedMessage,
		LastSentMessage:     params.LastSentMessage,
	})
}

// ConnectionlessParams contains parameters for connectionless message context
type ConnectionlessParams struct {
	Message             messages.AgentMessage
	AssociatedRecord    interface{}
	LastReceivedMessage messages.AgentMessage
	LastSentMessage     messages.AgentMessage
}

// GetConnectionlessOutboundMessageContext creates a connectionless outbound context
func GetConnectionlessOutboundMessageContext(
	agentContext *context.AgentContext,
	params ConnectionlessParams,
) (*models.OutboundMessageContext, error) {

	log.Printf("Creating outbound message context for message %s using connection-less exchange",
		params.Message.GetId())

	// Get out of band record if available
	outOfBandRecord := GetOutOfBandRecordForMessage(agentContext, params.Message)
	if outOfBandRecord == nil && params.LastReceivedMessage != nil {
		outOfBandRecord = GetOutOfBandRecordForMessage(agentContext, params.LastReceivedMessage)
	}

	// Get services for the message
	ourService, recipientService, err := GetServicesForMessage(agentContext, ServicesParams{
		LastReceivedMessage: params.LastReceivedMessage,
		LastSentMessage:     params.LastSentMessage,
		Message:             params.Message,
		OutOfBandRecord:     outOfBandRecord,
	})
	if err != nil {
		return nil, err
	}

	// We need to set up routing for this exchange if we haven't sent any messages yet
	if params.LastSentMessage == nil {
		ourService, err = CreateOurService(agentContext, CreateServiceParams{
			OutOfBandRecord: outOfBandRecord,
			Message:         params.Message,
		})
		if err != nil {
			return nil, err
		}
	}

	// These errors should not happen but we check for TypeScript parity
	if ourService == nil {
		return nil, fmt.Errorf("could not determine our service for connection-less exchange for message %s", params.Message.GetId())
	}
	if recipientService == nil {
		return nil, fmt.Errorf("could not determine recipient service for connection-less exchange for message %s", params.Message.GetId())
	}

	// Add exchange data to message (service decorator and thread parent ID)
	err = AddExchangeDataToMessage(agentContext, ExchangeDataParams{
		Message:          params.Message,
		OurService:       ourService,
		OutOfBandRecord:  outOfBandRecord,
		AssociatedRecord: params.AssociatedRecord,
	})
	if err != nil {
		return nil, err
	}

	// Create service params with sender key
	serviceParams := &models.ServiceMessageParams{
		Service:     recipientService,
		SenderKey:   ourService.RecipientKeys[0], // First key is our key
		ReturnRoute: true,
	}

	return models.NewOutboundMessageContext(params.Message, models.OutboundMessageContextParams{
		AgentContext:     agentContext,
		AssociatedRecord: params.AssociatedRecord,
		ServiceParams:    serviceParams,
	}), nil
}

// GetOutOfBandRecordForMessage retrieves the out of band record associated with the message
func GetOutOfBandRecordForMessage(agentContext *context.AgentContext, message messages.AgentMessage) *oob.OutOfBandRecord {
	log.Printf("Looking for out-of-band record for message %s with thread id %s and type %s",
		message.GetId(), message.GetThreadId(), message.GetType())

	// Get OOB repository from DI
	var oobRepo *oob.OutOfBandRepository
	if agentContext != nil && agentContext.DependencyManager != nil {
		// Try to get from typed DI
		if dm, ok := agentContext.DependencyManager.(di.DependencyManager); ok {
			if dep, err := dm.Resolve(di.TokenOutOfBandRepository); err == nil {
				oobRepo, _ = dep.(*oob.OutOfBandRepository)
			}
		}
	}

	if oobRepo == nil {
		return nil
	}

	// Prefer parent thread id (pthid) which should be the invitation id
	// Extract pthid if the concrete message exposes it (most messages embed BaseMessage)
	pthid := ""
	if p, ok := message.(interface{ GetParentThreadId() string }); ok {
		pthid = p.GetParentThreadId()
	}
	log.Printf("OOB lookup: msgId=%s type=%s pthid=%s thid=%s", message.GetId(), message.GetType(), pthid, message.GetThreadId())
	if pthid != "" {
		log.Printf("Attempting OOB record lookup by pthid=%s (invitation id)", pthid)
		record := oobRepo.FindByInvitationThreadId(agentContext, pthid)
		if record != nil {
			log.Printf("Found OOB record %s via pthid=%s", record.ID, pthid)
			return record
		}
		log.Printf("No OOB record found via pthid=%s", pthid)
	}

	// Fallback to current thread id (invitation id often equals invitation thread id)
	thid := message.GetThreadId()
	log.Printf("Attempting OOB record lookup by thid=%s", thid)
	record := oobRepo.FindByInvitationThreadId(agentContext, thid)
	if record != nil {
		log.Printf("Found OOB record %s via thid=%s", record.ID, thid)
		return record
	}

	// Finally, try request thread id index (parity with Credo-TS invitationRequestsThreadIds)
	if thid != "" {
		log.Printf("Attempting OOB record lookup by invitationRequestsThreadIds (thid=%s)", thid)
		record = oobRepo.FindByRequestThreadId(agentContext, thid)
		if record != nil {
			log.Printf("Found OOB record %s via invitationRequestsThreadIds thid=%s", record.ID, thid)
			return record
		}
	}
	return nil
}

// ServicesParams contains parameters for getting services
type ServicesParams struct {
	LastSentMessage     messages.AgentMessage
	LastReceivedMessage messages.AgentMessage
	Message             messages.AgentMessage
	OutOfBandRecord     *oob.OutOfBandRecord
}

// GetServicesForMessage returns the services to use for the message
func GetServicesForMessage(
	agentContext *context.AgentContext,
	params ServicesParams,
) (*models.ResolvedDidCommService, *models.ResolvedDidCommService, error) {

	var ourService *models.ResolvedDidCommService
	var recipientService *models.ResolvedDidCommService

	// Extract services from previous messages if available
	if params.LastSentMessage != nil {
		if svcDec := service.GetServiceDecorator(params.LastSentMessage); svcDec != nil {
			ourService = svcDec.ToResolvedDidCommService()
		}
	}

	if params.LastReceivedMessage != nil {
		if svcDec := service.GetServiceDecorator(params.LastReceivedMessage); svcDec != nil {
			recipientService = svcDec.ToResolvedDidCommService()
		}
	}

	// If OOB record present, derive services directly from invitation (no external wrappers)
	if params.OutOfBandRecord != nil {
		if inv, ok := params.OutOfBandRecord.OutOfBandInvitation.(*oobmessages.OutOfBandInvitationMessage); ok && inv != nil {
			services := inv.GetServices()
			if len(services) > 0 {
				svc := services[0]
				endpoint := ""
				if se, ok := svc.ServiceEndpoint.(string); ok {
					endpoint = se
				}
				// Inline service
				if endpoint != "" && utils.IsValidURL(endpoint) && len(svc.RecipientKeys) > 0 {
					recipientService = &models.ResolvedDidCommService{ID: svc.Id, ServiceEndpoint: endpoint, RecipientKeys: svc.RecipientKeys, RoutingKeys: svc.RoutingKeys}
				}
				// DID-based service
				if utils.IsValidDid(endpoint) {
					// Resolve DID Document via DI
					resolved := resolveDidCommService(agentContext, endpoint)
					if resolved != nil {
						recipientService = resolved
					}
				}
			}
		}
	}

	// If we still don't have services, error
	if ourService == nil || recipientService == nil {
		return nil, nil, fmt.Errorf("could not determine services for message %s", params.Message.GetId())
	}

	return ourService, recipientService, nil
}

// CreateServiceParams contains parameters for creating our service
type CreateServiceParams struct {
	OutOfBandRecord *oob.OutOfBandRecord
	Message         messages.AgentMessage
}

// CreateOurService creates a new service for us as the sender
func CreateOurService(
	agentContext *context.AgentContext,
	params CreateServiceParams,
) (*models.ResolvedDidCommService, error) {

	log.Printf("No previous sent message in thread for outbound message %s with type %s, setting up routing",
		params.Message.GetId(), params.Message.GetType())

	var routingService *routing.RoutingService
	if agentContext != nil && agentContext.DependencyManager != nil {
		if dm, ok := agentContext.DependencyManager.(di.DependencyManager); ok {
			if dep, err := dm.Resolve(di.TokenRoutingService); err == nil {
				routingService, _ = dep.(*routing.RoutingService)
			}
		}
	}

	if routingService == nil {
		return nil, fmt.Errorf("routing service not available")
	}

	// Get routing configuration
	routingConfig, err := routingService.GetRouting(agentContext, routing.GetRoutingParams{
		MediatorId: "", // Could be extracted from OOB record if needed
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get routing: %w", err)
	}

	// Create our service from routing config
	ourService := &models.ResolvedDidCommService{
		ID:              common.GenerateUUID(),
		ServiceEndpoint: routingConfig.Endpoints[0],
		RecipientKeys:   []string{routingConfig.RecipientKey},
		RoutingKeys:     routingConfig.RoutingKeys,
	}

	// Store routing info in OOB record if available
	if params.OutOfBandRecord != nil {
		// Store structured routing metadata (Credo-TS parity fields)
		recipientFp := oobpkg.FingerprintFromKeyString(routingConfig.RecipientKey)
		routingFps := make([]string, 0, len(routingConfig.RoutingKeys))
		for _, rk := range routingConfig.RoutingKeys {
			routingFps = append(routingFps, oobpkg.FingerprintFromKeyString(rk))
		}
		params.OutOfBandRecord.SetMetadata("recipientRouting", map[string]interface{}{
			"recipientKeyFingerprint": recipientFp,
			"routingKeyFingerprints":  routingFps,
			"endpoints":               routingConfig.Endpoints,
			"mediatorId":              routingConfig.MediatorId,
		})
		// Tag for quick lookup
		if params.OutOfBandRecord.Tags == nil {
			params.OutOfBandRecord.Tags = map[string]string{}
		}
		params.OutOfBandRecord.Tags["recipientRoutingKeyFingerprint"] = recipientFp

		// Update OOB record
		if oobRepo := getOobRepository(agentContext); oobRepo != nil {
			oobRepo.Update(agentContext, params.OutOfBandRecord)
		}
	}

	return ourService, nil
}

// ExchangeDataParams contains parameters for adding exchange data
type ExchangeDataParams struct {
	Message          messages.AgentMessage
	OurService       *models.ResolvedDidCommService
	OutOfBandRecord  *oob.OutOfBandRecord
	AssociatedRecord interface{}
}

// AddExchangeDataToMessage adds exchange data to the message
func AddExchangeDataToMessage(
	agentContext *context.AgentContext,
	params ExchangeDataParams,
) error {

	// Set the parentThreadId on the message from the oob invitation if needed
	if params.OutOfBandRecord != nil {
		// Check if not connectionless invitation
		legacyMeta := params.OutOfBandRecord.GetMetadata("legacyInvitation")
		isConnectionless := false
		if meta, ok := legacyMeta.(map[string]interface{}); ok {
			if invType, ok := meta["legacyInvitationType"].(string); ok {
				isConnectionless = (invType == "connectionless")
			}
		}

		if !isConnectionless {
			// Determine the invitation id to set as pthid (stored in record tags as threadId)
			invitationId := ""
			if params.OutOfBandRecord.Tags != nil {
				if tid, ok := params.OutOfBandRecord.Tags["threadId"]; ok {
					invitationId = tid
				}
			}
			// Enforce pthid consistency per RFC 0434
			if thread := params.Message.GetThread(); thread != nil {
				pthid := thread.ParentThreadId
				if pthid != "" && pthid != invitationId {
					return fmt.Errorf("out-of-band invitation requests~attach message contains parent thread id %s that does not match the invitation id %s", pthid, invitationId)
				}
			}
			thread := params.Message.GetThread()
			if thread == nil {
				thread = &messages.ThreadDecorator{ParentThreadId: invitationId}
				params.Message.SetThread(thread)
			} else {
				thread.ParentThreadId = invitationId
			}
		}
	}

	svcDecorator := service.FromResolvedDidCommService(params.OurService)
	service.SetServiceDecorator(params.Message, svcDecorator)

	// Save the message to repository
	if msgRepo := getMessageRepository(agentContext); msgRepo != nil {
		// Get record ID from associated record
		recordId := ""
		if params.AssociatedRecord != nil {
			// Try to extract ID from the record (assuming it has an ID field)
			if rec, ok := params.AssociatedRecord.(interface{ GetId() string }); ok {
				recordId = rec.GetId()
			}
		}

		msgRepo.SaveOrUpdateAgentMessage(repository.SaveMessageParams{
			AgentMessage:       params.Message,
			Role:               repository.DidCommMessageRoleSender,
			AssociatedRecordId: recordId,
		})
	}

	return nil
}

// resolveDidCommService resolves a DID to a ResolvedDidCommService using the DidResolverService.
func resolveDidCommService(agentContext *context.AgentContext, did string) *models.ResolvedDidCommService {
	if agentContext == nil || agentContext.DependencyManager == nil {
		return nil
	}
	dm, ok := agentContext.DependencyManager.(di.DependencyManager)
	if !ok {
		return nil
	}
	dep, err := dm.Resolve(di.TokenDidResolverService)
	if err != nil {
		return nil
	}
	resolver, _ := dep.(*dids.DidResolverService)
	if resolver == nil {
		return nil
	}
	doc, err := resolver.ResolveDidDocument(agentContext, did)
	if err != nil || doc == nil || len(doc.Service) == 0 {
		return nil
	}
	// Prefer DIDCommMessaging, fallback to did-communication/IndyAgent with recipientKeys
	var svc *dids.Service
	for _, s := range doc.Service {
		if s != nil && s.Type == dids.ServiceTypeDIDCommMessaging {
			svc = s
			break
		}
	}
	if svc == nil {
		for _, s := range doc.Service {
			if s != nil && (s.Type == dids.ServiceTypeDIDComm || s.Type == dids.ServiceTypeIndyAgent) && len(s.RecipientKeys) > 0 {
				svc = s
				break
			}
		}
	}
	if svc == nil {
		return nil
	}
	return &models.ResolvedDidCommService{ID: svc.Id, ServiceEndpoint: func() string {
		if se, ok := svc.ServiceEndpoint.(string); ok {
			return se
		}
		return ""
	}(), RecipientKeys: svc.RecipientKeys, RoutingKeys: svc.RoutingKeys}
}

// Helper functions to get repositories from DI
func getOobRepository(agentContext *context.AgentContext) *oob.OutOfBandRepository {
	if agentContext == nil || agentContext.DependencyManager == nil {
		return nil
	}
	if dm, ok := agentContext.DependencyManager.(di.DependencyManager); ok {
		if dep, err := dm.Resolve(di.TokenOutOfBandRepository); err == nil {
			if repo, ok := dep.(*oob.OutOfBandRepository); ok {
				return repo
			}
		}
	}
	return nil
}

func getMessageRepository(agentContext *context.AgentContext) *repository.DidCommMessageRepository {
	if agentContext == nil || agentContext.DependencyManager == nil {
		return nil
	}
	if dm, ok := agentContext.DependencyManager.(di.DependencyManager); ok {
		if dep, err := dm.Resolve(di.TokenDidCommMessageRepository); err == nil {
			if repo, ok := dep.(*repository.DidCommMessageRepository); ok {
				return repo
			}
		}
	}
	return nil
}
