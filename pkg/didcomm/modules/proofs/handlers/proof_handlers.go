package handlers

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/ajna-inc/essi/pkg/core/di"
	"github.com/ajna-inc/essi/pkg/didcomm/messages"
	"github.com/ajna-inc/essi/pkg/didcomm/models"
	proofmsgs "github.com/ajna-inc/essi/pkg/didcomm/modules/proofs/messages"
	proofservice "github.com/ajna-inc/essi/pkg/didcomm/modules/proofs/services"
	"github.com/ajna-inc/essi/pkg/didcomm/repository"
	"github.com/ajna-inc/essi/pkg/didcomm/services"
	"github.com/ajna-inc/essi/pkg/didcomm/transport"
)

// Helper functions to resolve services from DI
func getProofService(ctx *transport.InboundMessageContext) *proofservice.ProofService {
	if ctx != nil && ctx.TypedDI != nil {
		if any, err := ctx.TypedDI.Resolve(di.TokenProofsService); err == nil {
			if svc, ok := any.(*proofservice.ProofService); ok { 
				return svc 
			}
		}
	}
	return nil
}

func getMessageRepository(ctx *transport.InboundMessageContext) *repository.DidCommMessageRepository {
	if ctx != nil && ctx.TypedDI != nil {
		if dep, err := ctx.TypedDI.Resolve(di.TokenDidCommMessageRepository); err == nil {
			if repo, ok := dep.(*repository.DidCommMessageRepository); ok {
				return repo
			}
		}
	}
	return nil
}

// RequestPresentationV2Handler handles proof request messages
func RequestPresentationV2Handler(ctx *transport.InboundMessageContext) (*models.OutboundMessageContext, error) {
	log.Printf("🔍 Processing proof request v2")

	proofSvc := getProofService(ctx)
	if proofSvc == nil {
		return nil, fmt.Errorf("proof service not initialized")
	}

	var request proofmsgs.RequestPresentationV2
	if err := json.Unmarshal(ctx.Raw, &request); err != nil {
		return nil, fmt.Errorf("failed to parse proof request: %w", err)
	}

	thid := request.GetThreadId()
	log.Printf("Received proof request with thread ID: %s", thid)

	// Get connection ID from context
	connectionId := ""
	if ctx.Connection != nil { 
		connectionId = ctx.Connection.ID 
	}
	
	// Process the request and generate presentation
	presentation, proofRecord, err := proofSvc.ProcessProofRequest(connectionId, &request)
	if err != nil { 
		return nil, fmt.Errorf("failed to process proof request: %w", err) 
	}
	
	log.Printf("✅ Created proof presentation for thread %s", thid)
	
	// Check if we should auto-respond
	// TODO: Add auto-accept logic similar to presentation handler
	
	// Create outbound context for the presentation
	outboundCtx, err := services.GetOutboundMessageContext(ctx.AgentContext, services.GetOutboundMessageContextParams{
		Message:             presentation,
		ConnectionRecord:    ctx.Connection,
		AssociatedRecord:    proofRecord,
		LastReceivedMessage: &request,
	})
	
	if err != nil {
		log.Printf("❌ Failed to create outbound context: %v", err)
		return nil, err
	}
	
	return outboundCtx, nil
}

// ProposePresentationV2Handler handles proof proposal messages
func ProposePresentationV2Handler(ctx *transport.InboundMessageContext) (*models.OutboundMessageContext, error) {
	log.Printf("📝 Processing proof proposal v2")
	
	var proposal proofmsgs.ProposePresentationV2
	if err := json.Unmarshal(ctx.Raw, &proposal); err != nil { 
		return nil, fmt.Errorf("failed to parse proof proposal: %w", err) 
	}
	
	log.Printf("Received proof proposal with thread ID: %s", proposal.GetThreadId())
	
	// TODO: Implement proposal processing
	// For now, return nil (no automatic response to proposals)
	return nil, nil
}

// PresentationV2Handler handles proof presentation messages
func PresentationV2Handler(ctx *transport.InboundMessageContext) (*models.OutboundMessageContext, error) {
	log.Printf("📋 Processing proof presentation v2")
	
	proofSvc := getProofService(ctx)
	if proofSvc == nil { 
		return nil, fmt.Errorf("proof service not initialized") 
	}
	
	var presentation proofmsgs.PresentationV2
	if err := json.Unmarshal(ctx.Raw, &presentation); err != nil { 
		return nil, fmt.Errorf("failed to parse presentation: %w", err) 
	}
	
	thid := presentation.GetThreadId()
	log.Printf("Received proof presentation with thread ID: %s", thid)
	
	connectionId := ""
	if ctx.Connection != nil { 
		connectionId = ctx.Connection.ID 
	}
	
	// Process the presentation and get ACK
	ack, proofRecord, err := proofSvc.ProcessPresentation(connectionId, &presentation)
	if err != nil { 
		return nil, fmt.Errorf("failed to process presentation: %w", err) 
	}
	log.Printf("✅ Verified proof presentation for thread %s", thid)
	
	// Check if we should auto-respond (following TypeScript pattern)
	shouldAutoRespond := proofSvc.ShouldAutoRespondToPresentation(ctx.AgentContext, proofRecord, &presentation)
	
	if shouldAutoRespond && ack != nil {
		log.Printf("🤖 Automatically sending acknowledgement with autoAccept")
		
		// Get the request message from repository (for connectionless support)
		var requestMessage messages.AgentMessage
		if msgRepo := getMessageRepository(ctx); msgRepo != nil {
			if msg := msgRepo.GetAgentMessage(repository.GetMessageParams{
				AssociatedRecordId: proofRecord.ID,
				MessageClass:       "RequestPresentationV2",
				Role:               repository.DidCommMessageRoleSender,
			}); msg != nil {
				requestMessage, _ = msg.(messages.AgentMessage)
			}
		}
		
		// Create outbound context following TypeScript pattern
		outboundCtx, err := services.GetOutboundMessageContext(ctx.AgentContext, services.GetOutboundMessageContextParams{
			Message:             ack,
			ConnectionRecord:    ctx.Connection,
			AssociatedRecord:    proofRecord,
			LastReceivedMessage: &presentation,
			LastSentMessage:     requestMessage,
		})
		
		if err != nil {
			log.Printf("❌ Failed to create outbound context: %v", err)
			return nil, err
		}
		
		return outboundCtx, nil
	}
	
	// No auto-response, return nil
	return nil, nil
}

// PresentationAckV2Handler handles proof ACK messages
func PresentationAckV2Handler(ctx *transport.InboundMessageContext) (*models.OutboundMessageContext, error) {
	log.Printf("✅ Processing proof ACK v2")
	
	proofSvc := getProofService(ctx)
	if proofSvc == nil { 
		return nil, fmt.Errorf("proof service not initialized") 
	}
	
	var ack proofmsgs.AckPresentationV2
	if err := json.Unmarshal(ctx.Raw, &ack); err != nil { 
		return nil, fmt.Errorf("failed to parse ack: %w", err) 
	}
	
	connectionId := ""
	if ctx.Connection != nil { 
		connectionId = ctx.Connection.ID 
	}
	
	if err := proofSvc.ProcessAck(connectionId, &ack); err != nil { 
		log.Printf("Warning: Failed to process proof ACK: %v", err) 
	}
	
	// ACK is the final message, no response needed
	return nil, nil
}