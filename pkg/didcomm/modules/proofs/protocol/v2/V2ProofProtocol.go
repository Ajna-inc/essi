package v2

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/core/common"
	"github.com/ajna-inc/essi/pkg/didcomm/messages"
	"github.com/ajna-inc/essi/pkg/didcomm/modules/proofs/formats"
	"github.com/ajna-inc/essi/pkg/didcomm/modules/proofs/models"
	proofmsgs "github.com/ajna-inc/essi/pkg/didcomm/modules/proofs/messages"
	"github.com/ajna-inc/essi/pkg/didcomm/modules/proofs/protocol"
	"github.com/ajna-inc/essi/pkg/didcomm/modules/proofs/records"
	"github.com/ajna-inc/essi/pkg/didcomm/transport"
)

// V2ProofProtocol implements the DIDComm v2 proof protocol
type V2ProofProtocol struct {
	formatServices map[string]formats.ProofFormatService
	repository     records.Repository
	agentContext   *context.AgentContext
}

// NewV2ProofProtocol creates a new V2ProofProtocol
func NewV2ProofProtocol(agentCtx *context.AgentContext, repository records.Repository) *V2ProofProtocol {
	return &V2ProofProtocol{
		formatServices: make(map[string]formats.ProofFormatService),
		repository:     repository,
		agentContext:   agentCtx,
	}
}

// Version returns the version of this protocol
func (p *V2ProofProtocol) Version() protocol.ProofProtocolVersion {
	return protocol.ProofProtocolVersionV2
}

// Register registers the protocol handlers with the dispatcher
func (p *V2ProofProtocol) Register(dispatcher interface{}) error {
	// For now, we'll need to register handlers manually in agent.go
	// since we don't have access to the concrete dispatcher type here
	return nil
}

// AddFormatService adds a proof format service
func (p *V2ProofProtocol) AddFormatService(service formats.ProofFormatService) {
	p.formatServices[service.FormatKey()] = service
}

// CreateProposal creates a new proof proposal
func (p *V2ProofProtocol) CreateProposal(
	ctx *context.AgentContext,
	options protocol.CreateProofProposalOptions,
) (*records.ProofRecord, messages.AgentMessage, error) {
	// Create proof record
	record := &records.ProofRecord{
		ID:              common.GenerateUUID(),
		ConnectionId:    options.ConnectionId,
		ThreadId:        common.GenerateUUID(),
		ParentThreadId:  options.ParentThreadId,
		State:           string(models.ProofStateProposalSent),
		Role:            string(models.ProofRoleProver),
		ProtocolVersion: "v2",
		AutoAcceptProof: options.AutoAcceptProof,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
		ProofFormats:    options.ProofFormats,
		Metadata:        make(map[string]interface{}),
		Tags:            make(map[string]string),
	}
	
	// Create proposal message
	proposal := proofmsgs.NewProposePresentationV2(common.GenerateUUID(), record.ThreadId)
	proposal.Comment = options.Comment
	
	// Process formats
	for formatKey, formatData := range options.ProofFormats {
		service, ok := p.formatServices[formatKey]
		if !ok {
			continue
		}
		
		spec, attachment, err := service.CreateProposal(ctx, formats.CreateProposalOptions{
			ProofRecord:  record,
			ProofFormats: map[string]interface{}{formatKey: formatData},
			Comment:      options.Comment,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create proposal for format %s: %w", formatKey, err)
		}
		
		proposal.Formats = append(proposal.Formats, proofmsgs.AttachmentFormat{
			AttachId: spec.AttachmentId,
			Format:   spec.Format,
		})
		proposal.ProposalAttachments = append(proposal.ProposalAttachments, attachment)
	}
	
	// Save record
	if p.repository != nil {
		if err := p.repository.Save(ctx, record); err != nil {
			return nil, nil, fmt.Errorf("failed to save proof record: %w", err)
		}
	}
	
	return record, proposal, nil
}

// ProcessProposal processes an incoming proof proposal
func (p *V2ProofProtocol) ProcessProposal(
	ctx *context.AgentContext,
	message messages.AgentMessage,
	connectionId string,
) (*records.ProofRecord, error) {
	proposal, ok := message.(*proofmsgs.ProposePresentationV2)
	if !ok {
		return nil, fmt.Errorf("invalid message type for proposal")
	}
	
	// Create proof record
	record := &records.ProofRecord{
		ID:              common.GenerateUUID(),
		ConnectionId:    connectionId,
		ThreadId:        proposal.GetThreadId(),
		State:           string(models.ProofStateProposalReceived),
		Role:            string(models.ProofRoleVerifier),
		ProtocolVersion: "v2",
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
		ProofFormats:    make(map[string]interface{}),
		Metadata:        make(map[string]interface{}),
		Tags:            make(map[string]string),
	}
	
	// Process proposal attachments
	for i, format := range proposal.Formats {
		service, ok := p.formatServices[format.Format]
		if !ok {
			continue
		}
		
		if i < len(proposal.ProposalAttachments) {
			attachment := proposal.ProposalAttachments[i]
			
			if err := service.ProcessProposal(ctx, formats.ProcessProposalOptions{
				ProofRecord:        record,
				ProposalMessage:    proposal,
				ProposalAttachment: attachment,
			}); err != nil {
				return nil, fmt.Errorf("failed to process proposal for format %s: %w", format.Format, err)
			}
		}
	}
	
	// Save record
	if p.repository != nil {
		if err := p.repository.Save(ctx, record); err != nil {
			return nil, fmt.Errorf("failed to save proof record: %w", err)
		}
	}
	
	return record, nil
}

// AcceptProposal accepts a proof proposal
func (p *V2ProofProtocol) AcceptProposal(
	ctx *context.AgentContext,
	options protocol.AcceptProofProposalOptions,
) (*records.ProofRecord, messages.AgentMessage, error) {
	record := options.ProofRecord
	
	// Update state
	record.State = string(models.ProofStateRequestSent)
	record.UpdatedAt = time.Now()
	
	// Create request message
	request := proofmsgs.NewRequestPresentationV2(common.GenerateUUID(), record.ThreadId)
	request.Comment = options.Comment
	request.WillConfirm = true
	
	// Process formats
	for formatKey, formatData := range options.ProofFormats {
		service, ok := p.formatServices[formatKey]
		if !ok {
			continue
		}
		
		spec, attachment, err := service.CreateRequest(ctx, formats.CreateRequestOptions{
			ProofRecord:  record,
			ProofFormats: map[string]interface{}{formatKey: formatData},
		})
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create request for format %s: %w", formatKey, err)
		}
		
		request.Formats = append(request.Formats, proofmsgs.AttachmentFormat{
			AttachId: spec.AttachmentId,
			Format:   spec.Format,
		})
		request.RequestPresentations = append(request.RequestPresentations, attachment)
	}
	
	// Update record
	if p.repository != nil {
		if err := p.repository.Update(ctx, record); err != nil {
			return nil, nil, fmt.Errorf("failed to update proof record: %w", err)
		}
	}
	
	return record, request, nil
}

// Additional methods continue...
// CreateRequest, ProcessRequest, AcceptRequest, ProcessPresentation, etc.
// These follow the same pattern as above

// Handler methods for incoming messages

func (p *V2ProofProtocol) handleProposal(ctx *transport.InboundMessageContext) (messages.AgentMessage, error) {
	var proposal proofmsgs.ProposePresentationV2
	if err := json.Unmarshal(ctx.Raw, &proposal); err != nil {
		return nil, fmt.Errorf("failed to parse proposal: %w", err)
	}
	
	// Get connection ID from context
	connectionId := ""
	if ctx.Connection != nil {
		connectionId = ctx.Connection.ID
	}
	
	// Use the protocol's agent context
	agentCtx := p.agentContext
	
	record, err := p.ProcessProposal(agentCtx, &proposal, connectionId)
	if err != nil {
		return nil, err
	}
	
	// Check auto-accept
	if p.shouldAutoAcceptProposal(agentCtx, record) {
		// Auto-accept logic here
	}
	
	return nil, nil
}

func (p *V2ProofProtocol) handleRequest(ctx *transport.InboundMessageContext) (messages.AgentMessage, error) {
	var request proofmsgs.RequestPresentationV2
	if err := json.Unmarshal(ctx.Raw, &request); err != nil {
		return nil, fmt.Errorf("failed to parse request: %w", err)
	}
	
	// Get connection ID from context
	connectionId := ""
	if ctx.Connection != nil {
		connectionId = ctx.Connection.ID
	}
	
	// Use the protocol's agent context
	agentCtx := p.agentContext
	
	record, err := p.ProcessRequest(agentCtx, &request, connectionId)
	if err != nil {
		return nil, err
	}
	
	// Check auto-accept
	if p.shouldAutoAcceptRequest(agentCtx, record) {
		// Auto-accept logic here
	}
	
	return nil, nil
}

func (p *V2ProofProtocol) handlePresentation(ctx *transport.InboundMessageContext) (messages.AgentMessage, error) {
	var presentation proofmsgs.PresentationV2
	if err := json.Unmarshal(ctx.Raw, &presentation); err != nil {
		return nil, fmt.Errorf("failed to parse presentation: %w", err)
	}
	
	// Get connection ID from context
	connectionId := ""
	if ctx.Connection != nil {
		connectionId = ctx.Connection.ID
	}
	
	// Use the protocol's agent context
	agentCtx := p.agentContext
	
	record, err := p.ProcessPresentation(agentCtx, &presentation, connectionId)
	if err != nil {
		return nil, err
	}
	
	// Check auto-accept
	if p.shouldAutoAcceptPresentation(agentCtx, record) {
		// Auto-accept logic here
	}
	
	return nil, nil
}

func (p *V2ProofProtocol) handleAck(ctx *transport.InboundMessageContext) (messages.AgentMessage, error) {
	var ack proofmsgs.AckPresentationV2
	if err := json.Unmarshal(ctx.Raw, &ack); err != nil {
		return nil, fmt.Errorf("failed to parse ack: %w", err)
	}
	
	// Use the protocol's agent context
	agentCtx := p.agentContext
	
	_, err := p.ProcessAck(agentCtx, &ack)
	return nil, err
}

func (p *V2ProofProtocol) handleProblemReport(ctx *transport.InboundMessageContext) (messages.AgentMessage, error) {
	var report proofmsgs.ProblemReportV2
	if err := json.Unmarshal(ctx.Raw, &report); err != nil {
		return nil, fmt.Errorf("failed to parse problem report: %w", err)
	}
	
	// Use the protocol's agent context
	agentCtx := p.agentContext
	
	_, err := p.ProcessProblemReport(agentCtx, &report)
	return nil, err
}

// Helper methods

func (p *V2ProofProtocol) shouldAutoAcceptProposal(ctx *context.AgentContext, record *records.ProofRecord) bool {
	// Implement auto-accept logic
	return false
}

func (p *V2ProofProtocol) shouldAutoAcceptRequest(ctx *context.AgentContext, record *records.ProofRecord) bool {
	// Basic auto-accept respecting record setting
	switch record.AutoAcceptProof {
	case models.AutoAcceptAlways:
		return true
	case models.AutoAcceptContentApproved:
		// TODO: inspect content/matches before auto-accepting
		return false
	case models.AutoAcceptNever:
		fallthrough
	default:
		return false
	}
}

func (p *V2ProofProtocol) shouldAutoAcceptPresentation(ctx *context.AgentContext, record *records.ProofRecord) bool {
	// Mirror request policy for ACK decisions for now
	return p.shouldAutoAcceptRequest(ctx, record)
}

// Stub implementations for remaining interface methods
// These would need full implementation

func (p *V2ProofProtocol) NegotiateProposal(
	ctx *context.AgentContext,
	proofRecord *records.ProofRecord,
	proofFormats map[string]interface{},
) (*records.ProofRecord, messages.AgentMessage, error) {
	// TODO: Implement
	return nil, nil, fmt.Errorf("not implemented")
}

func (p *V2ProofProtocol) CreateRequest(
	ctx *context.AgentContext,
	options protocol.CreateProofRequestOptions,
) (*records.ProofRecord, messages.AgentMessage, error) {
	// Create proof record
	record := &records.ProofRecord{
		ID:              common.GenerateUUID(),
		ConnectionId:    options.ConnectionId,
		ThreadId:        common.GenerateUUID(),
		ParentThreadId:  options.ParentThreadId,
		State:           string(models.ProofStateRequestSent),
		Role:            string(models.ProofRoleVerifier),
		ProtocolVersion: "v2",
		AutoAcceptProof: options.AutoAcceptProof,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
		ProofFormats:    options.ProofFormats,
		Metadata:        make(map[string]interface{}),
		Tags:            make(map[string]string),
	}
	
	// Create request message
	request := proofmsgs.NewRequestPresentationV2(common.GenerateUUID(), record.ThreadId)
	request.Comment = options.Comment
	request.WillConfirm = options.WillConfirm
	
	// Process formats
	for formatKey, formatData := range options.ProofFormats {
		service, ok := p.formatServices[formatKey]
		if !ok {
			continue
		}
		
		spec, attachment, err := service.CreateRequest(ctx, formats.CreateRequestOptions{
			ProofRecord:  record,
			ProofFormats: map[string]interface{}{formatKey: formatData},
		})
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create request for format %s: %w", formatKey, err)
		}
		
		request.Formats = append(request.Formats, proofmsgs.AttachmentFormat{
			AttachId: spec.AttachmentId,
			Format:   spec.Format,
		})
		request.RequestPresentations = append(request.RequestPresentations, attachment)
	}
	
	// Save record
	if p.repository != nil {
		if err := p.repository.Save(ctx, record); err != nil {
			return nil, nil, fmt.Errorf("failed to save proof record: %w", err)
		}
	}
	
	return record, request, nil
}

func (p *V2ProofProtocol) ProcessRequest(
	ctx *context.AgentContext,
	message messages.AgentMessage,
	connectionId string,
) (*records.ProofRecord, error) {
	// TODO: Implement - similar to ProcessProposal
	return nil, fmt.Errorf("not implemented")
}

func (p *V2ProofProtocol) AcceptRequest(
	ctx *context.AgentContext,
	options protocol.AcceptProofRequestOptions,
) (*records.ProofRecord, messages.AgentMessage, error) {
	// TODO: Implement
	return nil, nil, fmt.Errorf("not implemented")
}

func (p *V2ProofProtocol) NegotiateRequest(
	ctx *context.AgentContext,
	proofRecord *records.ProofRecord,
	proofFormats map[string]interface{},
) (*records.ProofRecord, messages.AgentMessage, error) {
	// TODO: Implement
	return nil, nil, fmt.Errorf("not implemented")
}

func (p *V2ProofProtocol) ProcessPresentation(
	ctx *context.AgentContext,
	message messages.AgentMessage,
	connectionId string,
) (*records.ProofRecord, error) {
	// TODO: Implement
	return nil, fmt.Errorf("not implemented")
}

func (p *V2ProofProtocol) AcceptPresentation(
	ctx *context.AgentContext,
	options protocol.AcceptPresentationOptions,
) (*records.ProofRecord, messages.AgentMessage, error) {
	// TODO: Implement
	return nil, nil, fmt.Errorf("not implemented")
}

func (p *V2ProofProtocol) ProcessAck(
	ctx *context.AgentContext,
	message messages.AgentMessage,
) (*records.ProofRecord, error) {
	// TODO: Implement
	return nil, fmt.Errorf("not implemented")
}

func (p *V2ProofProtocol) CreateProblemReport(
	ctx *context.AgentContext,
	options protocol.CreateProblemReportOptions,
) (messages.AgentMessage, error) {
	// TODO: Implement
	return nil, fmt.Errorf("not implemented")
}

func (p *V2ProofProtocol) ProcessProblemReport(
	ctx *context.AgentContext,
	message messages.AgentMessage,
) (*records.ProofRecord, error) {
	// TODO: Implement
	return nil, fmt.Errorf("not implemented")
}

func (p *V2ProofProtocol) GetCredentialsForRequest(
	ctx *context.AgentContext,
	options protocol.GetCredentialsForRequestOptions,
) ([]formats.ProofCredential, error) {
	// For now, use anoncreds as the default format
	formatId := "anoncreds"
	if len(options.ProofFormats) > 0 {
		for key := range options.ProofFormats {
			formatId = key
			break
		}
	}
	
	service, err := p.GetFormatService(formatId)
	if err != nil {
		return nil, err
	}
	
	// Get proof record from repository
	rec := options.ProofRecord
	if rec == nil {
		return nil, fmt.Errorf("proof record not provided")
	}
	
	// Create attachment from proof request
	var requestData interface{}
	if rec.ProofFormats != nil {
		requestData = rec.ProofFormats[formatId]
	}
	var jsonData map[string]interface{}
	if requestData != nil {
		jsonData, _ = requestData.(map[string]interface{})
	}
	attach := messages.AttachmentDecorator{Data: &messages.AttachmentData{Json: jsonData}}
	return service.GetCredentialsForRequest(ctx, formats.GetCredentialsOptions{ProofRecord: rec, RequestAttachment: attach})
}

func (p *V2ProofProtocol) SelectCredentialsForRequest(
	ctx *context.AgentContext,
	options protocol.SelectCredentialsForRequestOptions,
) (map[string]interface{}, error) {
	// For now, use anoncreds as the default format
	formatId := "anoncreds"
	if len(options.ProofFormats) > 0 {
		for key := range options.ProofFormats {
			formatId = key
			break
		}
	}
	
	service, err := p.GetFormatService(formatId)
	if err != nil {
		return nil, err
	}
	
	// Get proof record from repository
	rec := options.ProofRecord
	if rec == nil {
		return nil, fmt.Errorf("proof record not provided")
	}
	
	// Create attachment from proof request
	var requestData interface{}
	if rec.ProofFormats != nil {
		requestData = rec.ProofFormats[formatId]
	}
	var jsonData map[string]interface{}
	if requestData != nil {
		jsonData, _ = requestData.(map[string]interface{})
	}
	attach := messages.AttachmentDecorator{Data: &messages.AttachmentData{Json: jsonData}}
	
	// For now, return empty credentials map
	var credentials []formats.ProofCredential
	return service.SelectCredentialsForRequest(ctx, formats.SelectCredentialsOptions{ProofRecord: rec, RequestAttachment: attach, Credentials: credentials})
}

func (p *V2ProofProtocol) GetFormatService(formatId string) (formats.ProofFormatService, error) {
	service, ok := p.formatServices[formatId]
	if !ok {
		return nil, fmt.Errorf("format service not found: %s", formatId)
	}
	return service, nil
}

func (p *V2ProofProtocol) GetSupportedFormats() []string {
	formats := make([]string, 0, len(p.formatServices))
	for key := range p.formatServices {
		formats = append(formats, key)
	}
	return formats
}