package protocol

import (
	"github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/didcomm/messages"
	"github.com/ajna-inc/essi/pkg/didcomm/modules/proofs/formats"
	"github.com/ajna-inc/essi/pkg/didcomm/modules/proofs/models"
	"github.com/ajna-inc/essi/pkg/didcomm/modules/proofs/records"
)

// ProofProtocolVersion represents the version of a proof protocol
type ProofProtocolVersion string

const (
	ProofProtocolVersionV1 ProofProtocolVersion = "v1"
	ProofProtocolVersionV2 ProofProtocolVersion = "v2"
)

// CreateProofProposalOptions contains options for creating a proof proposal
type CreateProofProposalOptions struct {
	ConnectionId    string
	ProofFormats    map[string]interface{}
	Comment         string
	AutoAcceptProof models.AutoAcceptProof
	GoalCode        string
	Goal            string
	ParentThreadId  string
}

// AcceptProofProposalOptions contains options for accepting a proof proposal
type AcceptProofProposalOptions struct {
	ProofRecord     *records.ProofRecord
	ProofFormats    map[string]interface{}
	Comment         string
	AutoAcceptProof models.AutoAcceptProof
}

// CreateProofRequestOptions contains options for creating a proof request
type CreateProofRequestOptions struct {
	ConnectionId    string
	ProofFormats    map[string]interface{}
	Comment         string
	AutoAcceptProof models.AutoAcceptProof
	WillConfirm     bool
	GoalCode        string
	Goal            string
	ParentThreadId  string
}

// AcceptProofRequestOptions contains options for accepting a proof request
type AcceptProofRequestOptions struct {
	ProofRecord       *records.ProofRecord
	ProofFormats      map[string]interface{}
	Comment           string
	UseReturnRoute    bool
	AutoAcceptProof   models.AutoAcceptProof
}

// AcceptPresentationOptions contains options for accepting a presentation
type AcceptPresentationOptions struct {
	ProofRecord *records.ProofRecord
}

// CreateProblemReportOptions contains options for creating a problem report
type CreateProblemReportOptions struct {
	ProofRecord *records.ProofRecord
	Description string
}

// GetCredentialsForRequestOptions contains options for getting credentials for a request
type GetCredentialsForRequestOptions struct {
	ProofRecord  *records.ProofRecord
	ProofFormats map[string]interface{}
}

// SelectCredentialsForRequestOptions contains options for selecting credentials
type SelectCredentialsForRequestOptions struct {
	ProofRecord  *records.ProofRecord
	ProofFormats map[string]interface{}
}

// ProofProtocol defines the interface for proof protocols
type ProofProtocol interface {
	// Version returns the version of this protocol
	Version() ProofProtocolVersion
	
	// Register registers the protocol handlers with the dispatcher
	Register(dispatcher interface{}) error
	
	// CreateProposal creates a new proof proposal
	CreateProposal(
		ctx *context.AgentContext,
		options CreateProofProposalOptions,
	) (*records.ProofRecord, messages.AgentMessage, error)
	
	// ProcessProposal processes an incoming proof proposal
	ProcessProposal(
		ctx *context.AgentContext,
		message messages.AgentMessage,
		connectionId string,
	) (*records.ProofRecord, error)
	
	// AcceptProposal accepts a proof proposal
	AcceptProposal(
		ctx *context.AgentContext,
		options AcceptProofProposalOptions,
	) (*records.ProofRecord, messages.AgentMessage, error)
	
	// NegotiateProposal negotiates a proof proposal
	NegotiateProposal(
		ctx *context.AgentContext,
		proofRecord *records.ProofRecord,
		proofFormats map[string]interface{},
	) (*records.ProofRecord, messages.AgentMessage, error)
	
	// CreateRequest creates a new proof request
	CreateRequest(
		ctx *context.AgentContext,
		options CreateProofRequestOptions,
	) (*records.ProofRecord, messages.AgentMessage, error)
	
	// ProcessRequest processes an incoming proof request
	ProcessRequest(
		ctx *context.AgentContext,
		message messages.AgentMessage,
		connectionId string,
	) (*records.ProofRecord, error)
	
	// AcceptRequest accepts a proof request
	AcceptRequest(
		ctx *context.AgentContext,
		options AcceptProofRequestOptions,
	) (*records.ProofRecord, messages.AgentMessage, error)
	
	// NegotiateRequest negotiates a proof request
	NegotiateRequest(
		ctx *context.AgentContext,
		proofRecord *records.ProofRecord,
		proofFormats map[string]interface{},
	) (*records.ProofRecord, messages.AgentMessage, error)
	
	// ProcessPresentation processes an incoming presentation
	ProcessPresentation(
		ctx *context.AgentContext,
		message messages.AgentMessage,
		connectionId string,
	) (*records.ProofRecord, error)
	
	// AcceptPresentation accepts a presentation
	AcceptPresentation(
		ctx *context.AgentContext,
		options AcceptPresentationOptions,
	) (*records.ProofRecord, messages.AgentMessage, error)
	
	// ProcessAck processes an acknowledgment
	ProcessAck(
		ctx *context.AgentContext,
		message messages.AgentMessage,
	) (*records.ProofRecord, error)
	
	// CreateProblemReport creates a problem report
	CreateProblemReport(
		ctx *context.AgentContext,
		options CreateProblemReportOptions,
	) (messages.AgentMessage, error)
	
	// ProcessProblemReport processes a problem report
	ProcessProblemReport(
		ctx *context.AgentContext,
		message messages.AgentMessage,
	) (*records.ProofRecord, error)
	
	// GetCredentialsForRequest gets credentials that can satisfy a proof request
	GetCredentialsForRequest(
		ctx *context.AgentContext,
		options GetCredentialsForRequestOptions,
	) ([]formats.ProofCredential, error)
	
	// SelectCredentialsForRequest automatically selects credentials for a request
	SelectCredentialsForRequest(
		ctx *context.AgentContext,
		options SelectCredentialsForRequestOptions,
	) (map[string]interface{}, error)
	
	// GetFormatService gets the format service for a given format
	GetFormatService(formatId string) (formats.ProofFormatService, error)
	
	// GetSupportedFormats returns the supported proof formats
	GetSupportedFormats() []string
}