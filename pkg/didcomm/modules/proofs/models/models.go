package models

// ProofState represents the state of a proof exchange
type ProofState string

const (
	ProofStateProposalSent         ProofState = "proposal-sent"
	ProofStateProposalReceived     ProofState = "proposal-received"
	ProofStateRequestSent          ProofState = "request-sent"
	ProofStateRequestReceived      ProofState = "request-received"
	ProofStatePresentationSent     ProofState = "presentation-sent"
	ProofStatePresentationReceived ProofState = "presentation-received"
	ProofStateDeclined             ProofState = "declined"
	ProofStateAbandoned            ProofState = "abandoned"
	ProofStateDone                 ProofState = "done"
)

// ProofRole represents the role in a proof exchange
type ProofRole string

const (
	ProofRoleProver   ProofRole = "prover"
	ProofRoleVerifier ProofRole = "verifier"
)

// AutoAcceptProof represents the auto-accept configuration for proofs
type AutoAcceptProof string

const (
	// AutoAcceptAlways always auto-accepts the proof
	AutoAcceptAlways AutoAcceptProof = "always"
	
	// AutoAcceptContentApproved auto-accepts if the content is approved
	AutoAcceptContentApproved AutoAcceptProof = "contentApproved"
	
	// AutoAcceptNever never auto-accepts
	AutoAcceptNever AutoAcceptProof = "never"
)

// PresentationProblemReportReason represents problem report reasons
type PresentationProblemReportReason string

const (
	ProblemReportReasonAbandoned     PresentationProblemReportReason = "abandoned"
	ProblemReportReasonNoProposal    PresentationProblemReportReason = "no-proposal"
	ProblemReportReasonProposalError PresentationProblemReportReason = "proposal-processing-error"
	ProblemReportReasonRequestError  PresentationProblemReportReason = "request-processing-error"
	ProblemReportReasonPresentError  PresentationProblemReportReason = "presentation-processing-error"
	ProblemReportReasonGeneral       PresentationProblemReportReason = "issuance-general-error"
)

// ComposeAutoAccept determines the effective auto-accept setting
func ComposeAutoAccept(recordValue, messageValue, moduleValue AutoAcceptProof) AutoAcceptProof {
	// Priority: record > message > module
	if recordValue != "" {
		return recordValue
	}
	if messageValue != "" {
		return messageValue
	}
	if moduleValue != "" {
		return moduleValue
	}
	return AutoAcceptNever
}