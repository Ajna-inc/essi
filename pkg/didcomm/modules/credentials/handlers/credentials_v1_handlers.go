package handlers

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/ajna-inc/essi/pkg/core/di"
	"github.com/ajna-inc/essi/pkg/didcomm/messages"
	"github.com/ajna-inc/essi/pkg/didcomm/models"
	credmsgs "github.com/ajna-inc/essi/pkg/didcomm/modules/credentials/messages"
	credsvc "github.com/ajna-inc/essi/pkg/didcomm/modules/credentials/services"
	outboundServices "github.com/ajna-inc/essi/pkg/didcomm/services"
	"github.com/ajna-inc/essi/pkg/didcomm/transport"
)

// CredentialsOfferV1HandlerFunc processes v1 credential offer messages
func CredentialsOfferV1HandlerFunc(ctx *transport.InboundMessageContext) (*models.OutboundMessageContext, error) {
	// Parse v1 offer message
	var offer credmsgs.OfferCredentialV1
	if err := json.Unmarshal(ctx.Raw, &offer); err != nil {
		return nil, fmt.Errorf("failed to parse v1 offer: %w", err)
	}

	// Convert to v2 format for processing
	v2Offer := credmsgs.NewOfferCredentialV2()
	v2Offer.SetId(offer.GetId())
	v2Offer.SetThreadId(offer.GetThreadId())

	// Convert credential preview
	if offer.CredentialPreview != nil {
		v2Preview := &credmsgs.CredentialPreview{
			Type:       "https://didcomm.org/issue-credential/2.0/credential-preview",
			Attributes: []credmsgs.CredentialPreviewAttribute{},
		}
		for _, attr := range offer.CredentialPreview.Attributes {
			v2Preview.Attributes = append(v2Preview.Attributes, credmsgs.CredentialPreviewAttribute{
				Name:     attr.Name,
				MimeType: attr.MimeType,
				Value:    attr.Value,
			})
		}
		v2Offer.CredentialPreview = v2Preview
	}

	// Convert offers~attach to v2 format
	v2Offer.OffersAttach = offer.OffersAttach
	// Note: v2 doesn't have comment field in the Go implementation

	// Process using v2 handler logic
	credentialSvc := getCredentialService(ctx)
	if credentialSvc == nil {
		return nil, fmt.Errorf("credential service not configured")
	}

	thid := v2Offer.GetThreadId()
	var connId string
	if ctx != nil && ctx.Connection != nil {
		connId = ctx.Connection.ID
	} else {
		if connectionSvc := getConnectionService(ctx); connectionSvc != nil {
			if conns, _ := connectionSvc.GetAllConnections(); len(conns) > 0 {
				connId = conns[len(conns)-1].ID
			}
		}
	}

	req, credRec, err := credentialSvc.ProcessOffer(thid, connId, v2Offer)
	if err != nil {
		return nil, err
	}

	// Auto-accept check
	var autoSvc *credsvc.CredentialAutoAcceptService
	if ctx != nil && ctx.TypedDI != nil {
		if any, rerr := ctx.TypedDI.Resolve(di.TokenCredentialAutoAcceptService); rerr == nil {
			if s, ok := any.(*credsvc.CredentialAutoAcceptService); ok {
				autoSvc = s
			}
		}
	}
	if autoSvc == nil {
		autoSvc = credsvc.NewCredentialAutoAcceptService(ctx.AgentContext, credentialSvc)
	}
	contentApproved := autoSvc.ShouldAutoRespondToOffer(nil, v2Offer)
	if autoSvc.ShouldAutoAccept(credRec, contentApproved) {
		log.Printf("🤖 Auto-accepting v1 credential offer")
		if connId != "" {
			connectionSvc := getConnectionService(ctx)
			rec, _ := connectionSvc.FindById(connId)
			if rec != nil {
				// Convert v2 request back to v1 format
				v1Request := &credmsgs.RequestCredentialV1{
					BaseMessage: messages.NewBaseMessage("https://didcomm.org/issue-credential/1.0/request-credential"),
				}
				v1Request.SetThreadId(req.GetThreadId())
				v1Request.RequestsAttach = req.RequestsAttach

				// Create outbound context for the request
				outboundCtx, err := outboundServices.GetOutboundMessageContext(
					ctx.AgentContext,
					outboundServices.GetOutboundMessageContextParams{
						Message:             v1Request,
						ConnectionRecord:    rec,
						AssociatedRecord:    credRec,
						LastReceivedMessage: &offer,
					},
				)
				if err != nil {
					log.Printf("❌ Failed to create outbound context: %v", err)
					return nil, nil
				}

				// Mark request as sent
				if credentialSvc != nil {
					_ = credentialSvc.MarkRequestSent(thid)
				}

				return outboundCtx, nil
			} else {
				// Do NOT fall back to connection-less for credentials
				log.Printf("❌ No connection record found for connId=%s. Will not send v1 request connection-less.", connId)
				return nil, fmt.Errorf("no connection found for v1 credential request (connId=%s)", connId)
			}
		}
	} else {
		log.Printf("⏸️ Manual acceptance required for v1 credential offer (thread: %s)", thid)
	}
	return nil, nil
}

// CredentialsProposeV1HandlerFunc processes v1 credential proposal messages
func CredentialsProposeV1HandlerFunc(ctx *transport.InboundMessageContext) (*models.OutboundMessageContext, error) {
	log.Printf("📥 Processing v1 credential proposal")
	// For now, just log - full implementation would convert to v2 and process
	return nil, nil
}

// CredentialsRequestV1HandlerFunc processes v1 credential request messages
func CredentialsRequestV1HandlerFunc(ctx *transport.InboundMessageContext) (*models.OutboundMessageContext, error) {
	log.Printf("📥 Processing v1 credential request")
	// For now, just log - full implementation would convert to v2 and process
	return nil, nil
}

// CredentialsIssueV1HandlerFunc processes v1 credential issue messages
func CredentialsIssueV1HandlerFunc(ctx *transport.InboundMessageContext) (*models.OutboundMessageContext, error) {
	log.Printf("📥 Processing v1 credential issue")
	// For now, just log - full implementation would convert to v2 and process
	return nil, nil
}
