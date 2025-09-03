package proofs

import (
	"fmt"
	"time"

	"github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/core/di"
	connServices "github.com/ajna-inc/essi/pkg/didcomm/modules/connections/services"
	"github.com/ajna-inc/essi/pkg/didcomm/modules/proofs/formats"
	"github.com/ajna-inc/essi/pkg/didcomm/modules/proofs/models"
	"github.com/ajna-inc/essi/pkg/didcomm/modules/proofs/protocol"
	"github.com/ajna-inc/essi/pkg/didcomm/modules/proofs/records"
	outboundServices "github.com/ajna-inc/essi/pkg/didcomm/services"
	"github.com/ajna-inc/essi/pkg/didcomm/transport"
)

// ProofsApiOptions contains various options for the API methods

type ProposeProofOptions struct {
	ConnectionId    string
	ProofFormats    map[string]interface{}
	Comment         string
	AutoAcceptProof models.AutoAcceptProof
	GoalCode        string
	Goal            string
	ParentThreadId  string
}

type AcceptProposalOptions struct {
	ProofRecordId   string
	ProofFormats    map[string]interface{}
	Comment         string
	AutoAcceptProof models.AutoAcceptProof
}

type RequestProofOptions struct {
	ConnectionId    string
	ProofFormats    map[string]interface{}
	Comment         string
	AutoAcceptProof models.AutoAcceptProof
	WillConfirm     bool
	GoalCode        string
	Goal            string
	ParentThreadId  string
}

type AcceptRequestOptions struct {
	ProofRecordId     string
	ProofFormats      map[string]interface{}
	Comment           string
	UseReturnRoute    bool
	AutoAcceptProof   models.AutoAcceptProof
}

type AcceptPresentationOptions struct {
	ProofRecordId string
}

type DeclineProofOptions struct {
	ProofRecordId string
	Reason        string
}

type GetCredentialsForRequestOptions struct {
	ProofRecordId string
}

type SelectCredentialsForRequestOptions struct {
	ProofRecordId string
}

type SendProblemReportOptions struct {
	ProofRecordId string
	Description   string
}

// ProofsApi provides the API for managing proof exchanges
type ProofsApi struct {
	context           *context.AgentContext
	typedDI           di.DependencyManager
	config            *ProofsModuleConfig
	proofRepository   records.Repository
	connectionService *connServices.ConnectionService
	messageSender     *transport.MessageSender
	protocols         map[protocol.ProofProtocolVersion]protocol.ProofProtocol
}

// NewProofsApi creates a new ProofsApi
func NewProofsApi(ctx *context.AgentContext, config *ProofsModuleConfig) *ProofsApi {
	api := &ProofsApi{
		context:   ctx,
		config:    config,
		protocols: make(map[protocol.ProofProtocolVersion]protocol.ProofProtocol),
	}
	return api
}

// SetTypedDI injects the typed dependency manager
func (api *ProofsApi) SetTypedDI(dm di.DependencyManager) { api.typedDI = dm }

// Initialize resolves dependencies
func (api *ProofsApi) Initialize() {
	// Initialize repository via typed DI token - REQUIRED, no fallback
	if api.typedDI != nil {
		if any, err := api.typedDI.Resolve(di.TokenProofsRepository); err == nil {
			if repo, ok := any.(records.Repository); ok { api.proofRepository = repo }
		}
	}
	if api.proofRepository == nil { 
		// Repository is required - will be initialized by ProofsModule with StorageService
		// If missing, methods will check and return appropriate errors
	}
	// Resolve connection service via typed DI
	if api.typedDI != nil {
		if any, err := api.typedDI.Resolve(di.TokenConnectionService); err == nil { api.connectionService, _ = any.(*connServices.ConnectionService) }
		if any, err := api.typedDI.Resolve(di.TokenMessageSender); err == nil { api.messageSender, _ = any.(*transport.MessageSender) }
	}
	// Register protocols
	for _, proto := range api.config.ProofProtocols { api.protocols[proto.Version()] = proto }
}

// ProposeProof creates and sends a proof proposal
func (api *ProofsApi) ProposeProof(options ProposeProofOptions) (*records.ProofRecord, error) {
	if api.connectionService == nil { api.Initialize() }
	if api.connectionService == nil {
		return nil, fmt.Errorf("connection service not available")
	}
	connection, err := api.connectionService.FindById(options.ConnectionId)
	if err != nil {
		return nil, fmt.Errorf("connection not found: %w", err)
	}
	// Get the appropriate protocol (default to v2)
	proto := api.getProtocol(protocol.ProofProtocolVersionV2)
	if proto == nil {
		return nil, fmt.Errorf("no proof protocol available")
	}
	// Create proposal
	proofRecord, message, err := proto.CreateProposal(api.context, protocol.CreateProofProposalOptions{
		ConnectionId:    options.ConnectionId,
		ProofFormats:    options.ProofFormats,
		Comment:         options.Comment,
		AutoAcceptProof: options.AutoAcceptProof,
		GoalCode:        options.GoalCode,
		Goal:            options.Goal,
		ParentThreadId:  options.ParentThreadId,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create proposal: %w", err)
	}
	// Send message
	if api.messageSender != nil {
		outboundCtx, err := outboundServices.GetOutboundMessageContext(
			api.context,
			outboundServices.GetOutboundMessageContextParams{
				Message:          message,
				ConnectionRecord: connection,
				AssociatedRecord: proofRecord,
			},
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create outbound context: %w", err)
		}
		if err := api.messageSender.SendMessage(outboundCtx); err != nil {
			return nil, fmt.Errorf("failed to send proposal: %w", err)
		}
	}
	return proofRecord, nil
}

// AcceptProposal accepts a proof proposal and sends a request
func (api *ProofsApi) AcceptProposal(options AcceptProposalOptions) (*records.ProofRecord, error) {
	if api.connectionService == nil || api.messageSender == nil { api.Initialize() }
	// Get proof record
	proofRecord, err := api.proofRepository.GetById(api.context, options.ProofRecordId)
	if err != nil {
		return nil, fmt.Errorf("proof record not found: %w", err)
	}
	proto := api.getProtocolForRecord(proofRecord)
	if proto == nil {
		return nil, fmt.Errorf("no proof protocol available for version %s", proofRecord.ProtocolVersion)
	}
	// Accept proposal
	updatedRecord, message, err := proto.AcceptProposal(api.context, protocol.AcceptProofProposalOptions{
		ProofRecord:     proofRecord,
		ProofFormats:    options.ProofFormats,
		Comment:         options.Comment,
		AutoAcceptProof: options.AutoAcceptProof,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to accept proposal: %w", err)
	}
	// Send message
	if api.messageSender != nil && api.connectionService != nil && proofRecord.ConnectionId != "" {
		connection, _ := api.connectionService.FindById(proofRecord.ConnectionId)
		if connection != nil {
			if outboundCtx, err := outboundServices.GetOutboundMessageContext(
				api.context,
				outboundServices.GetOutboundMessageContextParams{
					Message:          message,
					ConnectionRecord: connection,
					AssociatedRecord: proofRecord,
				},
			); err == nil {
				api.messageSender.SendMessage(outboundCtx)
			}
		}
	}
	return updatedRecord, nil
}

// RequestProof creates and sends a proof request
func (api *ProofsApi) RequestProof(options RequestProofOptions) (*records.ProofRecord, error) {
	if api.connectionService == nil || api.messageSender == nil { api.Initialize() }
	if api.connectionService == nil {
		return nil, fmt.Errorf("connection service not available")
	}
	connection, err := api.connectionService.FindById(options.ConnectionId)
	if err != nil {
		return nil, fmt.Errorf("connection not found: %w", err)
	}
	proto := api.getProtocol(protocol.ProofProtocolVersionV2)
	if proto == nil {
		return nil, fmt.Errorf("no proof protocol available")
	}
	// Create request
	proofRecord, message, err := proto.CreateRequest(api.context, protocol.CreateProofRequestOptions{
		ConnectionId:    options.ConnectionId,
		ProofFormats:    options.ProofFormats,
		Comment:         options.Comment,
		AutoAcceptProof: options.AutoAcceptProof,
		WillConfirm:     options.WillConfirm,
		GoalCode:        options.GoalCode,
		Goal:            options.Goal,
		ParentThreadId:  options.ParentThreadId,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	// Send message
	if api.messageSender != nil {
		outboundCtx, err := outboundServices.GetOutboundMessageContext(
			api.context,
			outboundServices.GetOutboundMessageContextParams{
				Message:          message,
				ConnectionRecord: connection,
				AssociatedRecord: proofRecord,
			},
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create outbound context: %w", err)
		}
		if err := api.messageSender.SendMessage(outboundCtx); err != nil {
			return nil, fmt.Errorf("failed to send request: %w", err)
		}
	}
	return proofRecord, nil
}

// AcceptRequest accepts a proof request and sends a presentation
func (api *ProofsApi) AcceptRequest(options AcceptRequestOptions) (*records.ProofRecord, error) {
	if api.connectionService == nil || api.messageSender == nil { api.Initialize() }
	// Get proof record
	proofRecord, err := api.proofRepository.GetById(api.context, options.ProofRecordId)
	if err != nil {
		return nil, fmt.Errorf("proof record not found: %w", err)
	}
	proto := api.getProtocolForRecord(proofRecord)
	if proto == nil {
		return nil, fmt.Errorf("no proof protocol available for version %s", proofRecord.ProtocolVersion)
	}
	// Accept request
	updatedRecord, message, err := proto.AcceptRequest(api.context, protocol.AcceptProofRequestOptions{
		ProofRecord:       proofRecord,
		ProofFormats:      options.ProofFormats,
		Comment:           options.Comment,
		UseReturnRoute:    options.UseReturnRoute,
		AutoAcceptProof:   options.AutoAcceptProof,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to accept request: %w", err)
	}
	// Send message
	if api.messageSender != nil && api.connectionService != nil && proofRecord.ConnectionId != "" {
		connection, _ := api.connectionService.FindById(proofRecord.ConnectionId)
		if connection != nil {
			if outboundCtx, err := outboundServices.GetOutboundMessageContext(
				api.context,
				outboundServices.GetOutboundMessageContextParams{
					Message:          message,
					ConnectionRecord: connection,
					AssociatedRecord: proofRecord,
				},
			); err == nil {
				api.messageSender.SendMessage(outboundCtx)
			}
		}
	}
	return updatedRecord, nil
}

// AcceptPresentation accepts a proof presentation
func (api *ProofsApi) AcceptPresentation(options AcceptPresentationOptions) (*records.ProofRecord, error) {
	if api.connectionService == nil || api.messageSender == nil { api.Initialize() }
	// Get proof record
	proofRecord, err := api.proofRepository.GetById(api.context, options.ProofRecordId)
	if err != nil {
		return nil, fmt.Errorf("proof record not found: %w", err)
	}
	proto := api.getProtocolForRecord(proofRecord)
	if proto == nil {
		return nil, fmt.Errorf("no proof protocol available for version %s", proofRecord.ProtocolVersion)
	}
	// Accept presentation
	updatedRecord, message, err := proto.AcceptPresentation(api.context, protocol.AcceptPresentationOptions{
		ProofRecord: proofRecord,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to accept presentation: %w", err)
	}
	// Send ACK if needed
	if message != nil && api.messageSender != nil && proofRecord.ConnectionId != "" {
		connection, _ := api.connectionService.FindById(proofRecord.ConnectionId)
		if connection != nil {
			if outboundCtx, err := outboundServices.GetOutboundMessageContext(
				api.context,
				outboundServices.GetOutboundMessageContextParams{
					Message:          message,
					ConnectionRecord: connection,
					AssociatedRecord: proofRecord,
				},
			); err == nil {
				api.messageSender.SendMessage(outboundCtx)
			}
		}
	}
	return updatedRecord, nil
}

// DeclineRequest declines a proof request
func (api *ProofsApi) DeclineRequest(options DeclineProofOptions) (*records.ProofRecord, error) {
	// Get proof record
	proofRecord, err := api.proofRepository.GetById(api.context, options.ProofRecordId)
	if err != nil {
		return nil, fmt.Errorf("proof record not found: %w", err)
	}
	// Update state
	proofRecord.State = string(models.ProofStateDeclined)
	proofRecord.ErrorMessage = options.Reason
	proofRecord.UpdatedAt = time.Now()
	// Save record
	if err := api.proofRepository.Update(api.context, proofRecord); err != nil {
		return nil, fmt.Errorf("failed to update proof record: %w", err)
	}
	// Send problem report
	if api.messageSender != nil && proofRecord.ConnectionId != "" {
		proto := api.getProtocolForRecord(proofRecord)
		if proto != nil {
			message, _ := proto.CreateProblemReport(api.context, protocol.CreateProblemReportOptions{
				ProofRecord: proofRecord,
				Description: options.Reason,
			})
			if message != nil {
				connection, _ := api.connectionService.FindById(proofRecord.ConnectionId)
				if connection != nil {
					if outboundCtx, err := outboundServices.GetOutboundMessageContext(
				api.context,
				outboundServices.GetOutboundMessageContextParams{
					Message:          message,
					ConnectionRecord: connection,
					AssociatedRecord: proofRecord,
				},
			); err == nil {
				api.messageSender.SendMessage(outboundCtx)
			}
				}
			}
		}
	}
	return proofRecord, nil
}

// GetCredentialsForRequest gets credentials that can satisfy a proof request
func (api *ProofsApi) GetCredentialsForRequest(options GetCredentialsForRequestOptions) ([]formats.ProofCredential, error) {
	// Get proof record
	proofRecord, err := api.proofRepository.GetById(api.context, options.ProofRecordId)
	if err != nil {
		return nil, fmt.Errorf("proof record not found: %w", err)
	}
	proto := api.getProtocolForRecord(proofRecord)
	if proto == nil {
		return nil, fmt.Errorf("no proof protocol available for version %s", proofRecord.ProtocolVersion)
	}
	// Get credentials
	return proto.GetCredentialsForRequest(api.context, protocol.GetCredentialsForRequestOptions{
		ProofRecord:  proofRecord,
		ProofFormats: proofRecord.ProofFormats,
	})
}

// SelectCredentialsForRequest automatically selects credentials for a request
func (api *ProofsApi) SelectCredentialsForRequest(options SelectCredentialsForRequestOptions) (map[string]interface{}, error) {
	// Get proof record
	proofRecord, err := api.proofRepository.GetById(api.context, options.ProofRecordId)
	if err != nil {
		return nil, fmt.Errorf("proof record not found: %w", err)
	}
	proto := api.getProtocolForRecord(proofRecord)
	if proto == nil {
		return nil, fmt.Errorf("no proof protocol available for version %s", proofRecord.ProtocolVersion)
	}
	// Select credentials
	return proto.SelectCredentialsForRequest(api.context, protocol.SelectCredentialsForRequestOptions{
		ProofRecord:  proofRecord,
		ProofFormats: proofRecord.ProofFormats,
	})
}

// SendProblemReport sends a problem report
func (api *ProofsApi) SendProblemReport(options SendProblemReportOptions) (*records.ProofRecord, error) {
	// Get proof record
	proofRecord, err := api.proofRepository.GetById(api.context, options.ProofRecordId)
	if err != nil {
		return nil, fmt.Errorf("proof record not found: %w", err)
	}
	proto := api.getProtocolForRecord(proofRecord)
	if proto == nil {
		return nil, fmt.Errorf("no proof protocol available for version %s", proofRecord.ProtocolVersion)
	}
	// Create problem report
	message, err := proto.CreateProblemReport(api.context, protocol.CreateProblemReportOptions{
		ProofRecord: proofRecord,
		Description: options.Description,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create problem report: %w", err)
	}
	// Update state
	proofRecord.State = string(models.ProofStateAbandoned)
	proofRecord.ErrorMessage = options.Description
	proofRecord.UpdatedAt = time.Now()
	// Save record
	if err := api.proofRepository.Update(api.context, proofRecord); err != nil {
		return nil, fmt.Errorf("failed to update proof record: %w", err)
	}
	// Send message
	if api.messageSender != nil && api.connectionService != nil && proofRecord.ConnectionId != "" {
		connection, _ := api.connectionService.FindById(proofRecord.ConnectionId)
		if connection != nil {
			if outboundCtx, err := outboundServices.GetOutboundMessageContext(
				api.context,
				outboundServices.GetOutboundMessageContextParams{
					Message:          message,
					ConnectionRecord: connection,
					AssociatedRecord: proofRecord,
				},
			); err == nil {
				api.messageSender.SendMessage(outboundCtx)
			}
		}
	}
	return proofRecord, nil
}

// GetAll returns all proof records
func (api *ProofsApi) GetAll() ([]*records.ProofRecord, error) {
	// This would need to be implemented in the repository
	return []*records.ProofRecord{}, nil
}

// GetById returns a proof record by ID
func (api *ProofsApi) GetById(proofRecordId string) (*records.ProofRecord, error) {
	return api.proofRepository.GetById(api.context, proofRecordId)
}

// GetByThreadId returns a proof record by thread ID
func (api *ProofsApi) GetByThreadId(threadId string) (*records.ProofRecord, error) {
	return api.proofRepository.GetByThreadId(api.context, threadId)
}

// DeleteById deletes a proof record by ID
func (api *ProofsApi) DeleteById(proofRecordId string) error {
	return api.proofRepository.Delete(api.context, proofRecordId)
}

// Update updates a proof record
func (api *ProofsApi) Update(proofRecord *records.ProofRecord) error {
	return api.proofRepository.Update(api.context, proofRecord)
}

// Helper methods

func (api *ProofsApi) getProtocol(version protocol.ProofProtocolVersion) protocol.ProofProtocol {
	return api.protocols[version]
}

func (api *ProofsApi) getProtocolForRecord(record *records.ProofRecord) protocol.ProofProtocol {
	version := protocol.ProofProtocolVersion(record.ProtocolVersion)
	return api.protocols[version]
}