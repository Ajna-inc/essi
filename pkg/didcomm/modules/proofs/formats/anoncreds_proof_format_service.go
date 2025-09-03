package formats

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"

	"github.com/ajna-inc/essi/pkg/anoncreds/registry"
	"github.com/ajna-inc/essi/pkg/anoncreds/services"
	"github.com/ajna-inc/essi/pkg/anoncreds/services/holder"
	"github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/core/common"
	"github.com/ajna-inc/essi/pkg/didcomm/messages"
	"github.com/ajna-inc/essi/pkg/didcomm/modules/proofs/records"
)

const (
	AnonCredsProofFormatKey = "anoncreds"
	FormatProofRequest      = "anoncreds/proof-request@v1.0"
	FormatProof             = "anoncreds/proof@v1.0"
)

// AnonCredsProofFormatService handles AnonCreds proof format
type AnonCredsProofFormatService struct {
	holderService   services.AnonCredsHolderService
	issuerService   services.AnonCredsIssuerService
	verifierService services.AnonCredsVerifierService
	registryService registry.RegistryService
	credentialRepo  holder.CredentialRepository
}

// NewAnonCredsProofFormatService creates a new AnonCreds proof format service with DI
func NewAnonCredsProofFormatService(
	holderService services.AnonCredsHolderService,
	issuerService services.AnonCredsIssuerService,
	verifierService services.AnonCredsVerifierService,
	registryService registry.RegistryService,
	credentialRepo holder.CredentialRepository,
) *AnonCredsProofFormatService {
	return &AnonCredsProofFormatService{
		holderService:   holderService,
		issuerService:   issuerService,
		verifierService: verifierService,
		registryService: registryService,
		credentialRepo:  credentialRepo,
	}
}

// FormatKey returns the unique format key for this service
func (s *AnonCredsProofFormatService) FormatKey() string {
	return AnonCredsProofFormatKey
}

// SupportsFormat checks if this service supports a given format
func (s *AnonCredsProofFormatService) SupportsFormat(format string) bool {
	return format == FormatProofRequest || format == FormatProof
}

// CreateProposal creates a proposal attachment
func (s *AnonCredsProofFormatService) CreateProposal(
	ctx *context.AgentContext,
	options CreateProposalOptions,
) (ProofFormatSpec, messages.AttachmentDecorator, error) {
	// AnonCreds doesn't typically use proposals, but we can support it
	proposal := options.ProofFormats[AnonCredsProofFormatKey]
	if proposal == nil {
		return ProofFormatSpec{}, messages.AttachmentDecorator{}, fmt.Errorf("no anoncreds proposal provided")
	}

	proposalJson, err := json.Marshal(proposal)
	if err != nil {
		return ProofFormatSpec{}, messages.AttachmentDecorator{}, err
	}

	attachmentId := common.GenerateUUID()
	attachment := messages.AttachmentDecorator{
		Id:       attachmentId,
		MimeType: "application/json",
		Data: &messages.AttachmentData{
			Base64: base64.StdEncoding.EncodeToString(proposalJson),
		},
	}

	format := ProofFormatSpec{
		AttachmentId: attachmentId,
		Format:       FormatProofRequest,
	}

	return format, attachment, nil
}

// ProcessProposal processes a proposal attachment
func (s *AnonCredsProofFormatService) ProcessProposal(
	ctx *context.AgentContext,
	options ProcessProposalOptions,
) error {
	// Extract and validate proposal
	// Store any relevant information in the proof record
	return nil
}

// AcceptProposal accepts a proposal and creates a request
func (s *AnonCredsProofFormatService) AcceptProposal(
	ctx *context.AgentContext,
	options AcceptProposalOptions,
) (ProofFormatSpec, messages.AttachmentDecorator, error) {
	// Convert proposal to request
	// This is less common in AnonCreds flow
	return s.CreateRequest(ctx, CreateRequestOptions{
		ProofRecord:  options.ProofRecord,
		ProofFormats: map[string]interface{}{AnonCredsProofFormatKey: options.RequestedCredentials},
	})
}

// CreateRequest creates a request attachment
func (s *AnonCredsProofFormatService) CreateRequest(
	ctx *context.AgentContext,
	options CreateRequestOptions,
) (ProofFormatSpec, messages.AttachmentDecorator, error) {
	proofRequest := options.ProofFormats[AnonCredsProofFormatKey]
	if proofRequest == nil {
		return ProofFormatSpec{}, messages.AttachmentDecorator{}, fmt.Errorf("no anoncreds proof request provided")
	}

	// Ensure nonce is present
	if proofReqMap, ok := proofRequest.(map[string]interface{}); ok {
		if _, hasNonce := proofReqMap["nonce"]; !hasNonce {
			proofReqMap["nonce"] = s.holderService.GenerateNonce(ctx)
		}
	}

	requestJson, err := json.Marshal(proofRequest)
	if err != nil {
		return ProofFormatSpec{}, messages.AttachmentDecorator{}, err
	}

	attachmentId := common.GenerateUUID()
	attachment := messages.AttachmentDecorator{
		Id:       attachmentId,
		MimeType: "application/json",
		Data: &messages.AttachmentData{
			Base64: base64.StdEncoding.EncodeToString(requestJson),
		},
	}

	format := ProofFormatSpec{
		AttachmentId: attachmentId,
		Format:       FormatProofRequest,
	}

	// Store proof request in record
	options.ProofRecord.ProofRequest = proofRequest.(map[string]interface{})

	return format, attachment, nil
}

// ProcessRequest processes a request attachment
func (s *AnonCredsProofFormatService) ProcessRequest(
	ctx *context.AgentContext,
	options ProcessRequestOptions,
) error {
	// Extract proof request from attachment
	proofRequest, err := s.extractProofRequest(options.RequestAttachment)
	if err != nil {
		return err
	}

	// Store in proof record
	options.ProofRecord.ProofRequest = proofRequest

	return nil
}

// AcceptRequest accepts a request and creates a presentation
func (s *AnonCredsProofFormatService) AcceptRequest(
	ctx *context.AgentContext,
	options AcceptRequestOptions,
) (ProofFormatSpec, messages.AttachmentDecorator, error) {
	// Extract proof request
	proofRequest, err := s.extractProofRequest(options.RequestAttachment)
	if err != nil {
		return ProofFormatSpec{}, messages.AttachmentDecorator{}, err
	}

	// Resolve schemas and credential definitions
	schemas, credDefs, err := s.resolveProofRequestDependencies(ctx, proofRequest)
	if err != nil {
		return ProofFormatSpec{}, messages.AttachmentDecorator{}, err
	}

	// Create proof using holder service
	proof, err := s.holderService.CreateProof(ctx, &services.CreateProofOptions{
		ProofRequest:          proofRequest,
		SelectedCredentials:   options.SelectedCredentials,
		Schemas:              schemas,
		CredentialDefinitions: credDefs,
		LinkSecretId:         "default",
	})
	if err != nil {
		return ProofFormatSpec{}, messages.AttachmentDecorator{}, err
	}

	// Create attachment
	proofJson, err := json.Marshal(proof.Proof)
	if err != nil {
		return ProofFormatSpec{}, messages.AttachmentDecorator{}, err
	}

	attachmentId := common.GenerateUUID()
	attachment := messages.AttachmentDecorator{
		Id:       attachmentId,
		MimeType: "application/json",
		Data: &messages.AttachmentData{
			Base64: base64.StdEncoding.EncodeToString(proofJson),
		},
	}

	format := ProofFormatSpec{
		AttachmentId: attachmentId,
		Format:       FormatProof,
	}

	return format, attachment, nil
}

// ProcessPresentation processes and verifies a presentation
func (s *AnonCredsProofFormatService) ProcessPresentation(
	ctx *context.AgentContext,
	options ProcessPresentationOptions,
) (bool, error) {
	// Extract proof from attachment
	proof, err := s.extractProof(options.PresentationAttachment)
	if err != nil {
		return false, err
	}

	// Extract proof request
	proofRequest, err := s.extractProofRequest(options.RequestAttachment)
	if err != nil {
		// Try to get from proof record
		proofRequest = options.ProofRecord.ProofRequest
		if proofRequest == nil {
			return false, fmt.Errorf("proof request not found")
		}
	}

	// Resolve schemas and credential definitions from proof
	schemas, credDefs, err := s.resolveProofDependencies(ctx, proof)
	if err != nil {
		return false, err
	}

	// Verify using verifier service
	result, err := s.verifierService.VerifyProof(ctx, &services.VerifyProofOptions{
		ProofRequest:          proofRequest,
		Proof:                 proof,
		Schemas:              schemas,
		CredentialDefinitions: credDefs,
	})
	if err != nil {
		return false, err
	}

	return result.Verified, nil
}

// GetCredentialsForRequest gets credentials that can satisfy a request
func (s *AnonCredsProofFormatService) GetCredentialsForRequest(
	ctx *context.AgentContext,
	options GetCredentialsOptions,
) ([]ProofCredential, error) {
	// Extract proof request
	proofRequest, err := s.extractProofRequest(options.RequestAttachment)
	if err != nil {
		return nil, err
	}

	// Get matching credentials from holder service
	matches, err := s.holderService.GetCredentialsForProofRequest(ctx, &services.GetCredentialsForProofRequestOptions{
		ProofRequest: proofRequest,
	})
	if err != nil {
		return nil, err
	}

	// Convert to ProofCredential format
	var credentials []ProofCredential
	
	// Add credentials from attributes
	for _, attrMatches := range matches.Attributes {
		for _, match := range attrMatches {
			credentials = append(credentials, ProofCredential{
				CredentialId:   match.CredentialId,
				CredentialInfo: match.CredentialInfo.Metadata,
				Attributes:     match.CredentialInfo.Attributes,
			})
		}
	}

	// Add credentials from predicates
	for _, predMatches := range matches.Predicates {
		for _, match := range predMatches {
			credentials = append(credentials, ProofCredential{
				CredentialId:   match.CredentialId,
				CredentialInfo: match.CredentialInfo.Metadata,
				Attributes:     match.CredentialInfo.Attributes,
			})
		}
	}

	return credentials, nil
}

// SelectCredentialsForRequest automatically selects credentials
func (s *AnonCredsProofFormatService) SelectCredentialsForRequest(
	ctx *context.AgentContext,
	options SelectCredentialsOptions,
) (map[string]interface{}, error) {
	// Extract proof request
	proofRequest, err := s.extractProofRequest(options.RequestAttachment)
	if err != nil {
		return nil, err
	}

	// Get matching credentials
	matches, err := s.holderService.GetCredentialsForProofRequest(ctx, &services.GetCredentialsForProofRequestOptions{
		ProofRequest: proofRequest,
	})
	if err != nil {
		return nil, err
	}

	// Auto-select credentials
	selected := map[string]interface{}{
		"attributes": map[string]interface{}{},
		"predicates": map[string]interface{}{},
		"selfAttested": map[string]interface{}{},
	}

	// Select for attributes
	attrs := selected["attributes"].(map[string]interface{})
	for referent, attrMatches := range matches.Attributes {
		if len(attrMatches) > 0 {
			attrs[referent] = map[string]interface{}{
				"credentialId": attrMatches[0].CredentialId,
				"revealed":     true,
			}
		}
	}

	// Select for predicates
	preds := selected["predicates"].(map[string]interface{})
	for referent, predMatches := range matches.Predicates {
		if len(predMatches) > 0 {
			preds[referent] = map[string]interface{}{
				"credentialId": predMatches[0].CredentialId,
			}
		}
	}

	return selected, nil
}

// ShouldAutoRespondToProposal checks if should auto-respond to proposal
func (s *AnonCredsProofFormatService) ShouldAutoRespondToProposal(
	ctx *context.AgentContext,
	proofRecord *records.ProofRecord,
	proposalAttachment messages.AttachmentDecorator,
) bool {
	// Implement auto-response logic
	return false
}

// ShouldAutoRespondToRequest checks if should auto-respond to request
func (s *AnonCredsProofFormatService) ShouldAutoRespondToRequest(
	ctx *context.AgentContext,
	proofRecord *records.ProofRecord,
	requestAttachment messages.AttachmentDecorator,
) bool {
	// Check if we have all required credentials
	// For now, return false to require manual action
	return false
}

// ShouldAutoRespondToPresentation checks if should auto-respond to presentation
func (s *AnonCredsProofFormatService) ShouldAutoRespondToPresentation(
	ctx *context.AgentContext,
	proofRecord *records.ProofRecord,
	presentationAttachment messages.AttachmentDecorator,
) bool {
	// Could auto-verify and send ack
	return true
}

// Helper methods

func (s *AnonCredsProofFormatService) extractProofRequest(attachment messages.AttachmentDecorator) (map[string]interface{}, error) {
	var data []byte
	if attachment.Data != nil {
		if attachment.Data.Base64 != "" {
			decoded, err := base64.StdEncoding.DecodeString(attachment.Data.Base64)
			if err != nil {
				return nil, err
			}
			data = decoded
		} else if attachment.Data.Json != nil {
			jsonData, err := json.Marshal(attachment.Data.Json)
			if err != nil {
				return nil, err
			}
			data = jsonData
		}
	}

	var proofRequest map[string]interface{}
	if err := json.Unmarshal(data, &proofRequest); err != nil {
		return nil, err
	}

	return proofRequest, nil
}

func (s *AnonCredsProofFormatService) extractProof(attachment messages.AttachmentDecorator) (map[string]interface{}, error) {
	var data []byte
	if attachment.Data != nil {
		if attachment.Data.Base64 != "" {
			decoded, err := base64.StdEncoding.DecodeString(attachment.Data.Base64)
			if err != nil {
				return nil, err
			}
			data = decoded
		} else if attachment.Data.Json != nil {
			jsonData, err := json.Marshal(attachment.Data.Json)
			if err != nil {
				return nil, err
			}
			data = jsonData
		}
	}

	var proof map[string]interface{}
	if err := json.Unmarshal(data, &proof); err != nil {
		return nil, err
	}

	return proof, nil
}

func (s *AnonCredsProofFormatService) resolveProofRequestDependencies(ctx *context.AgentContext, proofRequest map[string]interface{}) (map[string]map[string]interface{}, map[string]map[string]interface{}, error) {
	schemas := make(map[string]map[string]interface{})
	credDefs := make(map[string]map[string]interface{})

	// Extract schema and cred def IDs from proof request
	schemaIds := make(map[string]bool)
	credDefIds := make(map[string]bool)

	// From requested attributes
	if reqAttrs, ok := proofRequest["requested_attributes"].(map[string]interface{}); ok {
		for _, attr := range reqAttrs {
			s.extractIdsFromRestrictions(attr, schemaIds, credDefIds)
		}
	}

	// From requested predicates
	if reqPreds, ok := proofRequest["requested_predicates"].(map[string]interface{}); ok {
		for _, pred := range reqPreds {
			s.extractIdsFromRestrictions(pred, schemaIds, credDefIds)
		}
	}

	// Resolve schemas
	for schemaId := range schemaIds {
		schema, _, err := s.registryService.GetSchema(schemaId)
		if err != nil {
			log.Printf("Warning: failed to resolve schema %s: %v", schemaId, err)
			continue
		}
		// Convert to map[string]interface{}
		schemaJSON, _ := json.Marshal(schema)
		var schemaMap map[string]interface{}
		json.Unmarshal(schemaJSON, &schemaMap)
		schemas[schemaId] = schemaMap
	}

	// Resolve credential definitions
	for credDefId := range credDefIds {
		credDef, _, err := s.registryService.GetCredentialDefinition(credDefId)
		if err != nil {
			log.Printf("Warning: failed to resolve credential definition %s: %v", credDefId, err)
			continue
		}
		// Convert to map[string]interface{}
		credDefJSON, _ := json.Marshal(credDef)
		var credDefMap map[string]interface{}
		json.Unmarshal(credDefJSON, &credDefMap)
		credDefs[credDefId] = credDefMap
	}

	return schemas, credDefs, nil
}

func (s *AnonCredsProofFormatService) resolveProofDependencies(ctx *context.AgentContext, proof map[string]interface{}) (map[string]map[string]interface{}, map[string]map[string]interface{}, error) {
	schemas := make(map[string]map[string]interface{})
	credDefs := make(map[string]map[string]interface{})

	// Extract identifiers from proof
	if identifiers, ok := proof["identifiers"].([]interface{}); ok {
		for _, identifier := range identifiers {
			if id, ok := identifier.(map[string]interface{}); ok {
				if schemaId, ok := id["schema_id"].(string); ok {
					schema, _, err := s.registryService.GetSchema(schemaId)
					if err != nil {
						log.Printf("Warning: failed to resolve schema %s: %v", schemaId, err)
					} else {
						// Convert to map[string]interface{}
						schemaJSON, _ := json.Marshal(schema)
						var schemaMap map[string]interface{}
						json.Unmarshal(schemaJSON, &schemaMap)
						schemas[schemaId] = schemaMap
					}
				}
				if credDefId, ok := id["cred_def_id"].(string); ok {
					credDef, _, err := s.registryService.GetCredentialDefinition(credDefId)
					if err != nil {
						log.Printf("Warning: failed to resolve credential definition %s: %v", credDefId, err)
					} else {
						// Convert to map[string]interface{}
						credDefJSON, _ := json.Marshal(credDef)
						var credDefMap map[string]interface{}
						json.Unmarshal(credDefJSON, &credDefMap)
						credDefs[credDefId] = credDefMap
					}
				}
			}
		}
	}

	return schemas, credDefs, nil
}

func (s *AnonCredsProofFormatService) extractIdsFromRestrictions(item interface{}, schemaIds, credDefIds map[string]bool) {
	if itemMap, ok := item.(map[string]interface{}); ok {
		if restrictions, ok := itemMap["restrictions"].([]interface{}); ok {
			for _, restriction := range restrictions {
				if r, ok := restriction.(map[string]interface{}); ok {
					if schemaId, ok := r["schema_id"].(string); ok {
						schemaIds[schemaId] = true
					}
					if credDefId, ok := r["cred_def_id"].(string); ok {
						credDefIds[credDefId] = true
					}
				}
			}
		}
	}
}