package anoncreds

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ajna-inc/essi/pkg/anoncreds"
	acsvc "github.com/ajna-inc/essi/pkg/anoncreds/services"
	"github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/core/di"
	"github.com/ajna-inc/essi/pkg/didcomm/messages"
	"github.com/ajna-inc/essi/pkg/didcomm/modules/proofs/formats"
	"github.com/ajna-inc/essi/pkg/didcomm/modules/proofs/models"
	"github.com/ajna-inc/essi/pkg/didcomm/modules/proofs/records"
)

const (
	// Format identifiers for AnonCreds
	ProofRequestFormat = "hlindy/proof-req@v2.0"
	ProofFormat        = "hlindy/proof@v2.0"
)

// AnonCredsProofRequest represents an AnonCreds proof request
type AnonCredsProofRequest struct {
	Name                string                          `json:"name"`
	Version             string                          `json:"version"`
	Nonce               string                          `json:"nonce"`
	RequestedAttributes map[string]RequestedAttribute   `json:"requested_attributes"`
	RequestedPredicates map[string]RequestedPredicate   `json:"requested_predicates"`
	NonRevoked          *NonRevokedInterval             `json:"non_revoked,omitempty"`
}

type RequestedAttribute struct {
	Name         string                `json:"name,omitempty"`
	Names        []string              `json:"names,omitempty"`
	Restrictions []AttributeRestriction `json:"restrictions,omitempty"`
	NonRevoked   *NonRevokedInterval   `json:"non_revoked,omitempty"`
}

type RequestedPredicate struct {
	Name         string                 `json:"name"`
	PType        string                 `json:"p_type"`
	PValue       int                    `json:"p_value"`
	Restrictions []AttributeRestriction `json:"restrictions,omitempty"`
	NonRevoked   *NonRevokedInterval    `json:"non_revoked,omitempty"`
}

type AttributeRestriction struct {
	SchemaId     string            `json:"schema_id,omitempty"`
	SchemaName   string            `json:"schema_name,omitempty"`
	SchemaVersion string           `json:"schema_version,omitempty"`
	CredDefId    string            `json:"cred_def_id,omitempty"`
	IssuerDid    string            `json:"issuer_did,omitempty"`
	AttributeValues map[string]string `json:"attr::*::value,omitempty"`
}

type NonRevokedInterval struct {
	From int64 `json:"from,omitempty"`
	To   int64 `json:"to,omitempty"`
}

// AnonCredsProofFormatService implements the ProofFormatService for AnonCreds
type AnonCredsProofFormatService struct {
	anonCredsApi *anoncreds.AnonCredsApi
}

// NewAnonCredsProofFormatService creates a new AnonCredsProofFormatService
func NewAnonCredsProofFormatService(anonCredsApi *anoncreds.AnonCredsApi) *AnonCredsProofFormatService {
	return &AnonCredsProofFormatService{
		anonCredsApi: anonCredsApi,
	}
}

// FormatKey returns the unique format key for this service
func (s *AnonCredsProofFormatService) FormatKey() string {
	return "anoncreds"
}

// SupportsFormat checks if this service supports a given format
func (s *AnonCredsProofFormatService) SupportsFormat(format string) bool {
	return format == ProofRequestFormat || format == ProofFormat
}

// CreateProposal creates a proposal attachment
func (s *AnonCredsProofFormatService) CreateProposal(
	ctx *context.AgentContext,
	options formats.CreateProposalOptions,
) (formats.ProofFormatSpec, messages.AttachmentDecorator, error) {
	// For AnonCreds, proposals are typically not used
	// Return empty attachments
	spec := formats.ProofFormatSpec{
		AttachmentId: "proposal-0",
		Format:       ProofRequestFormat,
	}
	
	attachment := messages.AttachmentDecorator{
		Id:       "proposal-0",
		MimeType: "application/json",
		Data: &messages.AttachmentData{
			Json: map[string]interface{}{},
		},
	}
	
	return spec, attachment, nil
}

// ProcessProposal processes a proposal attachment
func (s *AnonCredsProofFormatService) ProcessProposal(
	ctx *context.AgentContext,
	options formats.ProcessProposalOptions,
) error {
	// Process the proposal if needed
	// For AnonCreds, this is often a no-op
	return nil
}

// AcceptProposal accepts a proposal and creates a request
func (s *AnonCredsProofFormatService) AcceptProposal(
	ctx *context.AgentContext,
	options formats.AcceptProposalOptions,
) (formats.ProofFormatSpec, messages.AttachmentDecorator, error) {
	// Create a proof request based on the proposal
	return s.CreateRequest(ctx, formats.CreateRequestOptions{
		ProofRecord:  options.ProofRecord,
		ProofFormats: options.RequestedCredentials,
	})
}

// CreateRequest creates a request attachment
func (s *AnonCredsProofFormatService) CreateRequest(
	ctx *context.AgentContext,
	options formats.CreateRequestOptions,
) (formats.ProofFormatSpec, messages.AttachmentDecorator, error) {
	// Extract AnonCreds proof request from options
	requestData, ok := options.ProofFormats["anoncreds"]
	if !ok {
		return formats.ProofFormatSpec{}, messages.AttachmentDecorator{}, 
			fmt.Errorf("no anoncreds format data provided")
	}
	
	// Convert to AnonCredsProofRequest
	var proofRequest AnonCredsProofRequest
	requestBytes, err := json.Marshal(requestData)
	if err != nil {
		return formats.ProofFormatSpec{}, messages.AttachmentDecorator{}, err
	}
	if err := json.Unmarshal(requestBytes, &proofRequest); err != nil {
		return formats.ProofFormatSpec{}, messages.AttachmentDecorator{}, err
	}
	
	// Generate nonce if not provided
	if proofRequest.Nonce == "" {
		// Generate a random nonce
		proofRequest.Nonce = fmt.Sprintf("%d", time.Now().UnixNano())
	}
	
	// Create attachment
	spec := formats.ProofFormatSpec{
		AttachmentId: "request-0",
		Format:       ProofRequestFormat,
	}
	
	proofRequestJson, err := json.Marshal(proofRequest)
	if err != nil {
		return formats.ProofFormatSpec{}, messages.AttachmentDecorator{}, err
	}
	
	attachment := messages.AttachmentDecorator{
		Id:       "request-0",
		MimeType: "application/json",
		Data: &messages.AttachmentData{
			Base64: base64.StdEncoding.EncodeToString(proofRequestJson),
		},
	}
	
	// Store proof request in record
	options.ProofRecord.ProofRequest = map[string]interface{}{
		"anoncreds": proofRequest,
	}
	
	return spec, attachment, nil
}

// ProcessRequest processes a request attachment
func (s *AnonCredsProofFormatService) ProcessRequest(
	ctx *context.AgentContext,
	options formats.ProcessRequestOptions,
) error {
	// Extract and validate the proof request
	var proofRequest AnonCredsProofRequest
	
	if options.RequestAttachment.Data.Base64 != "" {
		decoded, err := base64.StdEncoding.DecodeString(options.RequestAttachment.Data.Base64)
		if err != nil {
			return fmt.Errorf("failed to decode proof request: %w", err)
		}
		if err := json.Unmarshal(decoded, &proofRequest); err != nil {
			return fmt.Errorf("failed to unmarshal proof request: %w", err)
		}
	} else if options.RequestAttachment.Data.Json != nil {
		requestBytes, err := json.Marshal(options.RequestAttachment.Data.Json)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(requestBytes, &proofRequest); err != nil {
			return err
		}
	}
	
	// Store proof request in record
	options.ProofRecord.ProofRequest = map[string]interface{}{
		"anoncreds": proofRequest,
	}
	
	return nil
}

// AcceptRequest accepts a request and creates a presentation
func (s *AnonCredsProofFormatService) AcceptRequest(
	ctx *context.AgentContext,
	options formats.AcceptRequestOptions,
) (formats.ProofFormatSpec, messages.AttachmentDecorator, error) {
	// Get proof request from record
	proofRequestData, ok := options.ProofRecord.ProofRequest["anoncreds"]
	if !ok {
		return formats.ProofFormatSpec{}, messages.AttachmentDecorator{}, 
			fmt.Errorf("no anoncreds proof request found")
	}
	
	// Convert to AnonCredsProofRequest
	var proofRequest AnonCredsProofRequest
	requestBytes, err := json.Marshal(proofRequestData)
	if err != nil {
		return formats.ProofFormatSpec{}, messages.AttachmentDecorator{}, err
	}
	if err := json.Unmarshal(requestBytes, &proofRequest); err != nil {
		return formats.ProofFormatSpec{}, messages.AttachmentDecorator{}, err
	}
	
	// Get credentials for the proof request
	// This needs to be implemented with the actual AnonCreds API
	credentials := map[string]interface{}{}
	
	// Select credentials (auto-select first matching or use provided selection)
	selectedCreds := options.SelectedCredentials
	if selectedCreds == nil {
		// Auto-select credentials
		selectedCreds = s.autoSelectCredentials(&proofRequest, credentials)
	}
	
	// Create proof (placeholder structure matching TS layout)
	proof := map[string]interface{}{
		"requested_proof": selectedCreds,
	}
	
	// Create attachment
	spec := formats.ProofFormatSpec{
		AttachmentId: "presentation-0",
		Format:       ProofFormat,
	}
	
	proofJson, err := json.Marshal(proof)
	if err != nil {
		return formats.ProofFormatSpec{}, messages.AttachmentDecorator{}, err
	}
	
	attachment := messages.AttachmentDecorator{
		Id:       "presentation-0",
		MimeType: "application/json",
		Data: &messages.AttachmentData{
			Base64: base64.StdEncoding.EncodeToString(proofJson),
		},
	}
	
	// Store presentation in record
	options.ProofRecord.Presentation = map[string]interface{}{
		"anoncreds": proof,
	}
	
	return spec, attachment, nil
}

// ProcessPresentation processes and verifies a presentation
func (s *AnonCredsProofFormatService) ProcessPresentation(
	ctx *context.AgentContext,
	options formats.ProcessPresentationOptions,
) (bool, error) {
	// Extract proof
	var proof map[string]interface{}
	
	if options.PresentationAttachment.Data.Base64 != "" {
		decoded, err := base64.StdEncoding.DecodeString(options.PresentationAttachment.Data.Base64)
		if err != nil {
			return false, fmt.Errorf("failed to decode proof: %w", err)
		}
		if err := json.Unmarshal(decoded, &proof); err != nil {
			return false, fmt.Errorf("failed to unmarshal proof: %w", err)
		}
	} else if options.PresentationAttachment.Data.Json != nil {
		proofBytes, err := json.Marshal(options.PresentationAttachment.Data.Json)
		if err != nil {
			return false, err
		}
		if err := json.Unmarshal(proofBytes, &proof); err != nil {
			return false, err
		}
	}
	
	// Get proof request from record
	_, ok := options.ProofRecord.ProofRequest["anoncreds"]
	if !ok {
		return false, fmt.Errorf("no anoncreds proof request found")
	}
	
	// TODO: Verify proof using anoncreds-go when available
	isValid := true
	
	// Store presentation in record
	options.ProofRecord.Presentation = map[string]interface{}{
		"anoncreds": proof,
	}
	
	return isValid, nil
}

// GetCredentialsForRequest gets credentials that can satisfy a request
func (s *AnonCredsProofFormatService) GetCredentialsForRequest(
	ctx *context.AgentContext,
	options formats.GetCredentialsOptions,
) ([]formats.ProofCredential, error) {
	// Get proof request from record
	proofRequestData, ok := options.ProofRecord.ProofRequest["anoncreds"]
	if !ok {
		return nil, fmt.Errorf("no anoncreds proof request found")
	}
	
	// Convert to AnonCredsProofRequest
	var proofRequest AnonCredsProofRequest
	requestBytes, err := json.Marshal(proofRequestData)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(requestBytes, &proofRequest); err != nil {
		return nil, err
	}
	
	// Use holder service to fetch matching credentials per requested attribute/predicate
	var holder acsvc.AnonCredsHolderService
	if ctx != nil && ctx.DependencyManager != nil {
		if dm, ok := ctx.DependencyManager.(di.DependencyManager); ok {
			if dep, err := dm.Resolve(di.TokenAnonCredsHolderService); err == nil {
				if h, ok := dep.(acsvc.AnonCredsHolderService); ok {
					holder = h
				}
			}
		}
	}
	if holder == nil {
		return []formats.ProofCredential{}, nil
	}

	// Unpack proof request back to map[string]interface{}
	requestMap := map[string]interface{}{}
	if options.RequestAttachment.Data.Base64 != "" {
		decoded, _ := base64.StdEncoding.DecodeString(options.RequestAttachment.Data.Base64)
		_ = json.Unmarshal(decoded, &requestMap)
	} else if options.RequestAttachment.Data.Json != nil {
		b, _ := json.Marshal(options.RequestAttachment.Data.Json)
		_ = json.Unmarshal(b, &requestMap)
	}

	matches, err := holder.GetCredentialsForProofRequest(ctx, &acsvc.GetCredentialsForProofRequestOptions{ ProofRequest: requestMap })
	if err != nil || matches == nil {
		return []formats.ProofCredential{}, nil
	}

	result := make([]formats.ProofCredential, 0)
	// Flatten attributes
	for _, list := range matches.Attributes {
		for _, m := range list {
			info := map[string]interface{}{}
			if m.CredentialInfo != nil {
				info["schemaId"] = m.CredentialInfo.SchemaId
				info["credentialDefinitionId"] = m.CredentialInfo.CredentialDefinitionId
				info["attributes"] = m.CredentialInfo.Attributes
			}
			result = append(result, formats.ProofCredential{ CredentialId: m.CredentialId, CredentialInfo: info, Attributes: m.CredentialInfo.Attributes })
		}
	}
	// Flatten predicates
	for _, list := range matches.Predicates {
		for _, m := range list {
			info := map[string]interface{}{}
			if m.CredentialInfo != nil {
				info["schemaId"] = m.CredentialInfo.SchemaId
				info["credentialDefinitionId"] = m.CredentialInfo.CredentialDefinitionId
				info["attributes"] = m.CredentialInfo.Attributes
			}
			result = append(result, formats.ProofCredential{ CredentialId: m.CredentialId, CredentialInfo: info, Attributes: m.CredentialInfo.Attributes })
		}
	}

	return result, nil
}

// SelectCredentialsForRequest automatically selects credentials
func (s *AnonCredsProofFormatService) SelectCredentialsForRequest(
	ctx *context.AgentContext,
	options formats.SelectCredentialsOptions,
) (map[string]interface{}, error) {
	// Get proof request from record
	proofRequestData, ok := options.ProofRecord.ProofRequest["anoncreds"]
	if !ok {
		return nil, fmt.Errorf("no anoncreds proof request found")
	}
	
	// Convert to AnonCredsProofRequest
	var proofRequest AnonCredsProofRequest
	requestBytes, err := json.Marshal(proofRequestData)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(requestBytes, &proofRequest); err != nil {
		return nil, err
	}
	
	// Attempt holder-based selection
	requestMap := map[string]interface{}{}
	if options.RequestAttachment.Data.Base64 != "" {
		if decoded, err := base64.StdEncoding.DecodeString(options.RequestAttachment.Data.Base64); err == nil {
			_ = json.Unmarshal(decoded, &requestMap)
		}
	} else if options.RequestAttachment.Data.Json != nil {
		if b, err := json.Marshal(options.RequestAttachment.Data.Json); err == nil {
			_ = json.Unmarshal(b, &requestMap)
		}
	}
	
	var holder acsvc.AnonCredsHolderService
	if ctx != nil && ctx.DependencyManager != nil {
		if dm, ok := ctx.DependencyManager.(di.DependencyManager); ok {
			if dep, err := dm.Resolve(di.TokenAnonCredsHolderService); err == nil {
				if h, ok := dep.(acsvc.AnonCredsHolderService); ok {
					holder = h
				}
			}
		}
	}
	selected := map[string]interface{}{
		"requested_attributes": map[string]interface{}{},
		"requested_predicates": map[string]interface{}{},
	}
	attrsSel := selected["requested_attributes"].(map[string]interface{})
	predsSel := selected["requested_predicates"].(map[string]interface{})
	if holder != nil {
		if matches, err := holder.GetCredentialsForProofRequest(ctx, &acsvc.GetCredentialsForProofRequestOptions{ ProofRequest: requestMap }); err == nil && matches != nil {
			for attrRef := range proofRequest.RequestedAttributes {
				if list, ok := matches.Attributes[attrRef]; ok && len(list) > 0 {
					attrsSel[attrRef] = map[string]interface{}{ "cred_id": list[0].CredentialId, "revealed": true }
				} else {
					attrsSel[attrRef] = map[string]interface{}{ "cred_id": "auto-selected", "revealed": true }
				}
			}
			for predRef := range proofRequest.RequestedPredicates {
				if list, ok := matches.Predicates[predRef]; ok && len(list) > 0 {
					predsSel[predRef] = map[string]interface{}{ "cred_id": list[0].CredentialId }
				} else {
					predsSel[predRef] = map[string]interface{}{ "cred_id": "auto-selected" }
				}
			}
			return selected, nil
		}
	}
	// Fallback defaults
	for attrRef := range proofRequest.RequestedAttributes {
		attrsSel[attrRef] = map[string]interface{}{"cred_id": "auto-selected", "revealed": true}
	}
	for predRef := range proofRequest.RequestedPredicates {
		predsSel[predRef] = map[string]interface{}{"cred_id": "auto-selected"}
	}
	return selected, nil
}

// ShouldAutoRespondToProposal checks if should auto-respond to proposal
func (s *AnonCredsProofFormatService) ShouldAutoRespondToProposal(
	ctx *context.AgentContext,
	proofRecord *records.ProofRecord,
	proposalAttachment messages.AttachmentDecorator,
) bool {
	autoAccept := models.ComposeAutoAccept(
		proofRecord.AutoAcceptProof,
		"",
		models.AutoAcceptNever,
	)
	
	return autoAccept == models.AutoAcceptAlways
}

// ShouldAutoRespondToRequest checks if should auto-respond to request
func (s *AnonCredsProofFormatService) ShouldAutoRespondToRequest(
	ctx *context.AgentContext,
	proofRecord *records.ProofRecord,
	requestAttachment messages.AttachmentDecorator,
) bool {
	autoAccept := models.ComposeAutoAccept(
		proofRecord.AutoAcceptProof,
		"",
		models.AutoAcceptNever,
	)
	
	if autoAccept == models.AutoAcceptAlways {
		return true
	}
	
	if autoAccept == models.AutoAcceptContentApproved {
		// Parse proof request
		var proofRequest AnonCredsProofRequest
		if requestAttachment.Data != nil {
			if requestAttachment.Data.Base64 != "" {
				if decoded, err := base64.StdEncoding.DecodeString(requestAttachment.Data.Base64); err == nil {
					_ = json.Unmarshal(decoded, &proofRequest)
				}
			} else if requestAttachment.Data.Json != nil {
				if b, err := json.Marshal(requestAttachment.Data.Json); err == nil {
					_ = json.Unmarshal(b, &proofRequest)
				}
			}
		}
		// Resolve holder
		var holder acsvc.AnonCredsHolderService
		if ctx != nil && ctx.DependencyManager != nil {
			if dm, ok := ctx.DependencyManager.(di.DependencyManager); ok {
				if dep, err := dm.Resolve(di.TokenAnonCredsHolderService); err == nil {
					if h, ok := dep.(acsvc.AnonCredsHolderService); ok { holder = h }
				}
			}
		}
		if holder == nil { return false }
		// Build generic map request and query matches
		requestMap := map[string]interface{}{}
		if requestAttachment.Data != nil {
			if requestAttachment.Data.Base64 != "" {
				if decoded, err := base64.StdEncoding.DecodeString(requestAttachment.Data.Base64); err == nil {
					_ = json.Unmarshal(decoded, &requestMap)
				}
			} else if requestAttachment.Data.Json != nil {
				if b, err := json.Marshal(requestAttachment.Data.Json); err == nil { _ = json.Unmarshal(b, &requestMap) }
			}
		}
		matches, err := holder.GetCredentialsForProofRequest(ctx, &acsvc.GetCredentialsForProofRequestOptions{ ProofRequest: requestMap })
		if err != nil || matches == nil { return false }
		for attrRef := range proofRequest.RequestedAttributes {
			if list, ok := matches.Attributes[attrRef]; !ok || len(list) == 0 { return false }
		}
		for predRef := range proofRequest.RequestedPredicates {
			if list, ok := matches.Predicates[predRef]; !ok || len(list) == 0 { return false }
		}
		return true
	}
	
	return false
}

// ShouldAutoRespondToPresentation checks if should auto-respond to presentation
func (s *AnonCredsProofFormatService) ShouldAutoRespondToPresentation(
	ctx *context.AgentContext,
	proofRecord *records.ProofRecord,
	presentationAttachment messages.AttachmentDecorator,
) bool {
	autoAccept := models.ComposeAutoAccept(
		proofRecord.AutoAcceptProof,
		"",
		models.AutoAcceptNever,
	)
	
	return autoAccept == models.AutoAcceptAlways
}

// Helper methods

func (s *AnonCredsProofFormatService) autoSelectCredentials(
	proofRequest *AnonCredsProofRequest,
	credentials map[string]interface{},
) map[string]interface{} {
	// Simple auto-selection logic: structure compatible with anoncreds requested_proof
	selected := map[string]interface{}{
		"requested_attributes": map[string]interface{}{},
		"requested_predicates": map[string]interface{}{},
	}
	attrsSel := selected["requested_attributes"].(map[string]interface{})
	for attrRef := range proofRequest.RequestedAttributes {
		attrsSel[attrRef] = map[string]interface{}{"cred_id": "auto-selected", "revealed": true}
	}
	predsSel := selected["requested_predicates"].(map[string]interface{})
	for predRef := range proofRequest.RequestedPredicates {
		predsSel[predRef] = map[string]interface{}{"cred_id": "auto-selected"}
	}
	return selected
}