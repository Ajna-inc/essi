package formats

import (
	"github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/didcomm/messages"
	"github.com/ajna-inc/essi/pkg/didcomm/modules/proofs/records"
)

// ProofFormatSpec represents a proof format specification
type ProofFormatSpec struct {
	AttachmentId string `json:"attach_id"`
	Format       string `json:"format"`
}

// ProofCredential represents a credential that can be used in a proof
type ProofCredential struct {
	CredentialId   string                 `json:"credentialId"`
	CredentialInfo map[string]interface{} `json:"credentialInfo"`
	Attributes     map[string]string      `json:"attributes"`
}

// CreateProposalOptions contains options for creating a proposal
type CreateProposalOptions struct {
	ProofRecord  *records.ProofRecord
	ProofFormats map[string]interface{}
	Comment      string
}

// ProcessProposalOptions contains options for processing a proposal
type ProcessProposalOptions struct {
	ProofRecord       *records.ProofRecord
	ProposalMessage   messages.AgentMessage
	ProposalAttachment messages.AttachmentDecorator
}

// AcceptProposalOptions contains options for accepting a proposal
type AcceptProposalOptions struct {
	ProofRecord          *records.ProofRecord
	ProposalAttachment   messages.AttachmentDecorator
	RequestedCredentials map[string]interface{}
}

// CreateRequestOptions contains options for creating a request
type CreateRequestOptions struct {
	ProofRecord  *records.ProofRecord
	ProofFormats map[string]interface{}
}

// ProcessRequestOptions contains options for processing a request
type ProcessRequestOptions struct {
	ProofRecord       *records.ProofRecord
	RequestMessage    messages.AgentMessage
	RequestAttachment messages.AttachmentDecorator
}

// AcceptRequestOptions contains options for accepting a request
type AcceptRequestOptions struct {
	ProofRecord          *records.ProofRecord
	RequestAttachment    messages.AttachmentDecorator
	SelectedCredentials  map[string]interface{}
}

// ProcessPresentationOptions contains options for processing a presentation
type ProcessPresentationOptions struct {
	ProofRecord            *records.ProofRecord
	PresentationMessage    messages.AgentMessage
	PresentationAttachment messages.AttachmentDecorator
	RequestAttachment      messages.AttachmentDecorator
}

// GetCredentialsOptions contains options for getting credentials
type GetCredentialsOptions struct {
	ProofRecord       *records.ProofRecord
	RequestAttachment messages.AttachmentDecorator
}

// SelectCredentialsOptions contains options for selecting credentials
type SelectCredentialsOptions struct {
	ProofRecord       *records.ProofRecord
	RequestAttachment messages.AttachmentDecorator
	Credentials       []ProofCredential
}

// ProofFormatService defines the interface for proof format services
type ProofFormatService interface {
	// FormatKey returns the unique format key for this service
	FormatKey() string
	
	// SupportsFormat checks if this service supports a given format
	SupportsFormat(format string) bool
	
	// CreateProposal creates a proposal attachment
	CreateProposal(
		ctx *context.AgentContext,
		options CreateProposalOptions,
	) (ProofFormatSpec, messages.AttachmentDecorator, error)
	
	// ProcessProposal processes a proposal attachment
	ProcessProposal(
		ctx *context.AgentContext,
		options ProcessProposalOptions,
	) error
	
	// AcceptProposal accepts a proposal and creates a request
	AcceptProposal(
		ctx *context.AgentContext,
		options AcceptProposalOptions,
	) (ProofFormatSpec, messages.AttachmentDecorator, error)
	
	// CreateRequest creates a request attachment
	CreateRequest(
		ctx *context.AgentContext,
		options CreateRequestOptions,
	) (ProofFormatSpec, messages.AttachmentDecorator, error)
	
	// ProcessRequest processes a request attachment
	ProcessRequest(
		ctx *context.AgentContext,
		options ProcessRequestOptions,
	) error
	
	// AcceptRequest accepts a request and creates a presentation
	AcceptRequest(
		ctx *context.AgentContext,
		options AcceptRequestOptions,
	) (ProofFormatSpec, messages.AttachmentDecorator, error)
	
	// ProcessPresentation processes and verifies a presentation
	ProcessPresentation(
		ctx *context.AgentContext,
		options ProcessPresentationOptions,
	) (bool, error)
	
	// GetCredentialsForRequest gets credentials that can satisfy a request
	GetCredentialsForRequest(
		ctx *context.AgentContext,
		options GetCredentialsOptions,
	) ([]ProofCredential, error)
	
	// SelectCredentialsForRequest automatically selects credentials
	SelectCredentialsForRequest(
		ctx *context.AgentContext,
		options SelectCredentialsOptions,
	) (map[string]interface{}, error)
	
	// ShouldAutoRespondToProposal checks if should auto-respond to proposal
	ShouldAutoRespondToProposal(
		ctx *context.AgentContext,
		proofRecord *records.ProofRecord,
		proposalAttachment messages.AttachmentDecorator,
	) bool
	
	// ShouldAutoRespondToRequest checks if should auto-respond to request
	ShouldAutoRespondToRequest(
		ctx *context.AgentContext,
		proofRecord *records.ProofRecord,
		requestAttachment messages.AttachmentDecorator,
	) bool
	
	// ShouldAutoRespondToPresentation checks if should auto-respond to presentation
	ShouldAutoRespondToPresentation(
		ctx *context.AgentContext,
		proofRecord *records.ProofRecord,
		presentationAttachment messages.AttachmentDecorator,
	) bool
}