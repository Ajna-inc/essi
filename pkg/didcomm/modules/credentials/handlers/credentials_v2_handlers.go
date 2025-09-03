package handlers

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/ajna-inc/essi/pkg/core/di"
	"github.com/ajna-inc/essi/pkg/didcomm/messages"
	"github.com/ajna-inc/essi/pkg/didcomm/models"
	services "github.com/ajna-inc/essi/pkg/didcomm/modules/connections/services"
	credmsgs "github.com/ajna-inc/essi/pkg/didcomm/modules/credentials/messages"
	credsvc "github.com/ajna-inc/essi/pkg/didcomm/modules/credentials/services"
	outboundServices "github.com/ajna-inc/essi/pkg/didcomm/services"
	"github.com/ajna-inc/essi/pkg/didcomm/transport"
)

// CredentialsOfferHandlerFunc processes v2 credential offer messages (holder-first happy path)
func CredentialsOfferHandlerFunc(ctx *transport.InboundMessageContext) (*models.OutboundMessageContext, error) {
	var offer credmsgs.OfferCredentialV2
	if err := json.Unmarshal(ctx.Raw, &offer); err != nil {
		return nil, fmt.Errorf("failed to parse offer: %w", err)
	}
	credentialSvc := getCredentialService(ctx)
	if credentialSvc == nil {
		return nil, fmt.Errorf("credential service not configured")
	}
	thid := offer.GetThreadId()
	// Prefer associated connection from inbound context; fallback to latest
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
	req, credRec, err := credentialSvc.ProcessOffer(thid, connId, &offer)
	if err != nil {
		return nil, err
	}

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
	contentApproved := autoSvc.ShouldAutoRespondToOffer(nil, &offer)
	if autoSvc.ShouldAutoAccept(credRec, contentApproved) {
		log.Printf("🤖 Auto-accepting credential offer")
		// Send request outbound and mark state
		if connId != "" {
			connectionSvc := getConnectionService(ctx)
			rec, _ := connectionSvc.FindById(connId)
			if rec != nil {
				outboundCtx, err := outboundServices.GetOutboundMessageContext(
					ctx.AgentContext,
					outboundServices.GetOutboundMessageContextParams{
						Message:             req,
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
				log.Printf("❌ No connection record found for connId=%s. Will not send request connection-less.", connId)
				return nil, fmt.Errorf("no connection found for credential request (connId=%s)", connId)
			}
		}
	} else {
		log.Printf("⏸️ Manual acceptance required for credential offer (thread: %s)", thid)
		// Store the request for manual acceptance later
		// The app can call AcceptOffer() when ready
	}
	return nil, nil
}

// CredentialsIssueHandlerFunc processes v2 credential issue messages
func CredentialsIssueHandlerFunc(ctx *transport.InboundMessageContext) (*models.OutboundMessageContext, error) {
	var cred credmsgs.IssueCredentialV2Credential
	if err := json.Unmarshal(ctx.Raw, &cred); err != nil {
		return nil, fmt.Errorf("failed to parse issue-credential: %w", err)
	}
	credentialSvc := getCredentialService(ctx)
	if credentialSvc == nil {
		return nil, fmt.Errorf("credential service not configured")
	}
	thid := cred.GetThreadId()
	// Prefer associated connection from inbound context; fallback to latest
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
	ack, err := credentialSvc.ProcessIssue(thid, connId, &cred)
	if err != nil {
		return nil, err
	}
	if connId != "" && ack != nil {
		connectionSvc := getConnectionService(ctx)
		rec, _ := connectionSvc.FindById(connId)
		if rec != nil {
			outboundCtx, err := outboundServices.GetOutboundMessageContext(
				ctx.AgentContext,
				outboundServices.GetOutboundMessageContextParams{
					Message:             ack,
					ConnectionRecord:    rec,
					AssociatedRecord:    nil, // Could pass credential record if we have it
					LastReceivedMessage: &cred,
				},
			)
			if err != nil {
				log.Printf("❌ Failed to create outbound context for ACK: %v", err)
				return nil, nil
			}
			return outboundCtx, nil
		} else {
			// Do NOT fall back to connection-less for credentials
			log.Printf("❌ No connection record found for connId=%s. Will not send ack connection-less.", connId)
			return nil, fmt.Errorf("no connection found for credential ack (connId=%s)", connId)
		}
	}
	return nil, nil
}

// CredentialsRequestHandlerFunc (issuer stub): on request, send a minimal issue-credential
func CredentialsRequestHandlerFunc(ctx *transport.InboundMessageContext) (*models.OutboundMessageContext, error) {
	var req credmsgs.RequestCredentialV2
	if err := json.Unmarshal(ctx.Raw, &req); err != nil {
		return nil, fmt.Errorf("failed to parse request-credential: %w", err)
	}
	thid := req.GetThreadId()
	credentialSvc := getCredentialService(ctx)
	if credentialSvc == nil {
		return nil, fmt.Errorf("credential service not configured")
	}
	connectionSvc := getConnectionService(ctx)
	var connId string
	var rec *services.ConnectionRecord
	if ctx != nil && ctx.Connection != nil {
		rec = ctx.Connection
		connId = rec.ID
	} else if connectionSvc != nil {
		if conns, _ := connectionSvc.GetAllConnections(); len(conns) > 0 {
			rec = conns[len(conns)-1]
			connId = rec.ID
		}
	}
	cred, err := credentialSvc.ProcessRequest(thid, connId, &req)
	if err != nil {
		return nil, err
	}
	// Per-format auto-respond check vs stored offer
	shouldSend := true
	if credentialSvc != nil {
		if credRec, err := credentialSvc.FindRecordByThreadId(thid); err == nil && credRec != nil {
			offerMsg := credmsgs.NewOfferCredentialV2()
			offerMsg.SetThreadId(thid)
			if credRec.OfferPayload != nil {
				offerMsg.Formats = append(offerMsg.Formats, credmsgs.FormatEntry{AttachID: "offer-0", Format: "anoncreds/credential-offer@v1.0"})
				offerMsg.OffersAttach = append(offerMsg.OffersAttach, messages.AttachmentDecorator{Id: "offer-0", Data: &messages.AttachmentData{Json: credRec.OfferPayload}})
			}
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
			contentApproved := autoSvc.ShouldAutoRespondToRequest(offerMsg, &req)
			shouldSend = autoSvc.ShouldAutoAccept(credRec, contentApproved)
		}
	}
	if shouldSend && rec != nil && cred != nil {
		// Update state to credential-issued BEFORE sending the credential
		if credentialSvc != nil {
			if err := credentialSvc.MarkCredentialIssued(thid); err != nil {
				log.Printf("Warning: Failed to mark credential as issued: %v", err)
			}
		}

		// Create outbound context for the credential
		outboundCtx, err := outboundServices.GetOutboundMessageContext(
			ctx.AgentContext,
			outboundServices.GetOutboundMessageContextParams{
				Message:             cred,
				ConnectionRecord:    rec,
				AssociatedRecord:    nil, // Could pass credential record
				LastReceivedMessage: &req,
			},
		)
		if err != nil {
			log.Printf("❌ Failed to create outbound context: %v", err)
			return nil, nil
		}
		return outboundCtx, nil
	} else if !shouldSend {
		log.Printf("⏸️ Manual acceptance required for credential request (thread: %s)", thid)
	}
	return nil, nil
}

// CredentialsAckHandlerFunc processes credential ACK messages
func CredentialsAckHandlerFunc(ctx *transport.InboundMessageContext) (*models.OutboundMessageContext, error) {
	var ack credmsgs.Ack
	if err := json.Unmarshal(ctx.Raw, &ack); err != nil {
		return nil, fmt.Errorf("failed to parse ack: %w", err)
	}
	log.Printf("✅ Credential ack received (thid=%s)", ack.GetThreadId())
	credentialSvc := getCredentialService(ctx)
	if credentialSvc != nil {
		_ = credentialSvc.MarkDone(ack.GetThreadId())
	}
	return nil, nil
}

// CredentialsAckV2HandlerFunc handles v2 credential ACK messages
func CredentialsAckV2HandlerFunc(ctx *transport.InboundMessageContext) (*models.OutboundMessageContext, error) {
	var ack credmsgs.AckCredentialV2
	if err := json.Unmarshal(ctx.Raw, &ack); err != nil {
		return nil, fmt.Errorf("failed to parse v2 ack: %w", err)
	}

	// Get thread ID from the message
	thid := ack.GetThreadId()
	if thid == "" {
		thid = ack.GetId()
	}

	log.Printf("✅ Credential ACK v2 received (thid=%s, status=%s)", thid, ack.Status)

	// Mark the credential exchange as complete
	credentialSvc := getCredentialService(ctx)
	if credentialSvc != nil {
		// Log current state before updating
		if rec, err := credentialSvc.FindRecordByThreadId(thid); err == nil && rec != nil {
			log.Printf("📊 Current credential state before ACK processing: %s (role: %s)", rec.State, rec.Role)
		}

		if err := credentialSvc.MarkDone(thid); err != nil {
			log.Printf("Warning: Failed to mark credential exchange as done: %v", err)
			// Don't fail the handler - ACK is informational
		} else {
			log.Printf("✅ Credential exchange marked as done for thread: %s", thid)
		}
	}

	// No response needed for ACK
	return nil, nil
}

// CredentialsProposeV2HandlerFunc processes credential proposal messages
func CredentialsProposeV2HandlerFunc(ctx *transport.InboundMessageContext) (*models.OutboundMessageContext, error) {
	log.Printf("📥 Processing credential proposal")

	// Parse the proposal message
	var proposal credmsgs.ProposeCredentialV2
	if err := json.Unmarshal(ctx.Raw, &proposal); err != nil {
		log.Printf("Failed to unmarshal proposal: %v", err)
		return nil, err
	}

	credentialSvc := getCredentialService(ctx)
	if credentialSvc == nil {
		log.Printf("Credential service not available")
		return nil, nil
	}

	// Extract thread ID
	thid := proposal.GetThreadId()
	if thid == "" {
		thid = proposal.GetId()
	}

	// Get connection ID
	connectionSvc := getConnectionService(ctx)
	conns, _ := connectionSvc.GetAllConnections()
	var connId string
	if len(conns) > 0 {
		connId = conns[len(conns)-1].ID
	}

	// Process the proposal
	rec, err := credentialSvc.ProcessProposal(thid, connId, &proposal)
	if err != nil {
		log.Printf("Failed to process proposal: %v", err)
		return nil, err
	}

	log.Printf("✅ Credential proposal processed, record ID: %s, state: %s", rec.ID, rec.State)

	// Check if we should auto-accept the proposal (issuer side)
	if credentialSvc.ShouldAutoAccept(rec) {
		log.Printf("🤖 Auto-accepting credential proposal")
		// TODO: Implement auto-offer creation from proposal
	}

	return nil, nil
}

// CredentialsProblemReportV2HandlerFunc handles credential problem report messages
func CredentialsProblemReportV2HandlerFunc(ctx *transport.InboundMessageContext) (*models.OutboundMessageContext, error) {
	log.Printf("⚠️ Processing credential problem report")

	// Parse the problem report message
	var problemReport credmsgs.CredentialProblemReportV2
	if err := json.Unmarshal(ctx.Raw, &problemReport); err != nil {
		log.Printf("Failed to unmarshal problem report: %v", err)
		return nil, err
	}

	credentialSvc := getCredentialService(ctx)
	if credentialSvc == nil {
		log.Printf("Credential service not available")
		return nil, nil
	}

	// Extract thread ID
	thid := problemReport.GetThreadId()
	if thid == "" {
		// Problem report without thread ID - can't process
		log.Printf("Problem report without thread ID: %s - %s",
			problemReport.Code, problemReport.Comment)
		return nil, nil
	}

	// Process the problem report
	if err := credentialSvc.ProcessProblemReport(thid, &problemReport); err != nil {
		log.Printf("Failed to process problem report: %v", err)
		return nil, err
	}

	log.Printf("✅ Problem report processed for thread %s: %s - %s",
		thid, problemReport.Code, problemReport.Comment)

	return nil, nil
}
