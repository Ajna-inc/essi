package services

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
	proofmsgs "github.com/ajna-inc/essi/pkg/didcomm/modules/proofs/messages"
	proofrecs "github.com/ajna-inc/essi/pkg/didcomm/modules/proofs/records"
)

const (
	FormatProofRequest = "anoncreds/proof-request@v1.0"
	FormatProof        = "anoncreds/proof@v1.0"
)

type ProofService struct {
	context        *context.AgentContext
	holder         services.AnonCredsHolderService
	verifier       services.AnonCredsVerifierService
	registry       registry.RegistryService
	repository     proofrecs.Repository
	credentialRepo holder.CredentialRepository
}

func NewProofService(
	ctx *context.AgentContext,
	holder services.AnonCredsHolderService,
	verifier services.AnonCredsVerifierService,
	registry registry.RegistryService,
	repo proofrecs.Repository,
	credentialRepo holder.CredentialRepository,
) *ProofService {
	return &ProofService{
		context:        ctx,
		holder:         holder,
		verifier:       verifier,
		registry:       registry,
		repository:     repo,
		credentialRepo: credentialRepo,
	}
}

func (ps *ProofService) ProcessProofRequest(connectionId string, request *proofmsgs.RequestPresentationV2) (*proofmsgs.PresentationV2, *proofrecs.ProofRecord, error) {
	thid := request.GetThreadId()
	
	record := proofrecs.NewProofRecord(common.GenerateUUID())
	record.ConnectionId = connectionId
	record.ThreadId = thid
	record.Role = "prover"
	record.State = "request-received"

	if err := ps.repository.Save(ps.context, record); err != nil {
		return nil, nil, fmt.Errorf("failed to save proof record: %w", err)
	}

	var proofRequest map[string]interface{}
	for i, format := range request.Formats {
		if format.Format == FormatProofRequest {
			if i < len(request.RequestPresentations) {
				attachment := request.RequestPresentations[i]
				
				var data []byte
				if attachment.Data != nil {
					if attachment.Data.Base64 != "" {
						decoded, err := base64.StdEncoding.DecodeString(attachment.Data.Base64)
						if err != nil {
							return nil, nil, fmt.Errorf("failed to decode proof request: %w", err)
						}
						data = decoded
					} else if attachment.Data.Json != nil {
						jsonData, err := json.Marshal(attachment.Data.Json)
						if err != nil {
							return nil, nil, fmt.Errorf("failed to marshal proof request: %w", err)
						}
						data = jsonData
					}
				}

				if err := json.Unmarshal(data, &proofRequest); err != nil {
					return nil, nil, fmt.Errorf("failed to unmarshal proof request: %w", err)
				}
				break
			}
		}
	}

	if proofRequest == nil {
		return nil, nil, fmt.Errorf("no supported proof request format found")
	}

	credentialMatches, err := ps.holder.GetCredentialsForProofRequest(ps.context, &services.GetCredentialsForProofRequestOptions{
		ProofRequest: proofRequest,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get credentials for proof request: %w", err)
	}

	// Auto-select credentials (can be made configurable)
	selectedCredentials := ps.autoSelectCredentials(credentialMatches, proofRequest)

	// Resolve schemas and credential definitions
	schemas, credDefs, err := ps.resolveProofRequestDependencies(proofRequest)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to resolve proof dependencies: %w", err)
	}

	anonCredsProof, err := ps.holder.CreateProof(ps.context, &services.CreateProofOptions{
		ProofRequest:          proofRequest,
		SelectedCredentials:   selectedCredentials,
		Schemas:              schemas,
		CredentialDefinitions: credDefs,
		LinkSecretId:         "default",
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create proof: %w", err)
	}

	// Marshal the proof
	proofJson, err := json.Marshal(anonCredsProof.Proof)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal proof: %w", err)
	}

	presentation := proofmsgs.NewPresentationV2(common.GenerateUUID(), thid)
	presentation.Formats = []proofmsgs.AttachmentFormat{
		{
			AttachId: "proof-0",
			Format:   FormatProof,
		},
	}
	presentation.Presentations = []messages.AttachmentDecorator{
		{
			Id:       "proof-0",
			MimeType: "application/json",
			Data: &messages.AttachmentData{
				Base64: base64.StdEncoding.EncodeToString(proofJson),
			},
		},
	}

	record.State = "presentation-sent"
	if err := ps.repository.Update(ps.context, record); err != nil {
		log.Printf("Failed to update proof record state: %v", err)
	}

	log.Printf("Created proof presentation for thread %s", thid)
	return presentation, record, nil
}

func (ps *ProofService) CreateProofRequest(
	connectionId string,
	proofRequest map[string]interface{},
) (*proofmsgs.RequestPresentationV2, *proofrecs.ProofRecord, error) {
	record := proofrecs.NewProofRecord(common.GenerateUUID())
	record.ConnectionId = connectionId
	record.ThreadId = common.GenerateUUID()
	record.Role = "verifier"
	record.State = "request-sent"

	if err := ps.repository.Save(ps.context, record); err != nil {
		return nil, nil, fmt.Errorf("failed to save proof record: %w", err)
	}

	proofRequestJson, err := json.Marshal(proofRequest)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal proof request: %w", err)
	}

	request := proofmsgs.NewRequestPresentationV2(common.GenerateUUID(), record.ThreadId)
	request.Formats = []proofmsgs.AttachmentFormat{
		{
			AttachId: "request-0",
			Format:   FormatProofRequest,
		},
	}
	request.RequestPresentations = []messages.AttachmentDecorator{
		{
			Id:       "request-0",
			MimeType: "application/json",
			Data: &messages.AttachmentData{
				Base64: base64.StdEncoding.EncodeToString(proofRequestJson),
			},
		},
	}

	log.Printf("Created proof request for connection %s", connectionId)
	return request, record, nil
}

func (ps *ProofService) ProcessPresentation(
	connectionId string,
	presentation *proofmsgs.PresentationV2,
) (*proofmsgs.AckPresentationV2, *proofrecs.ProofRecord, error) {
	thid := presentation.GetThreadId()

	record, err := ps.repository.GetByThreadId(ps.context, thid)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get proof record: %w", err)
	}

	var proof map[string]interface{}
	for i, format := range presentation.Formats {
		if format.Format == FormatProof {
			if i < len(presentation.Presentations) {
				attachment := presentation.Presentations[i]
				
				var data []byte
				if attachment.Data != nil {
					if attachment.Data.Base64 != "" {
						decoded, err := base64.StdEncoding.DecodeString(attachment.Data.Base64)
						if err != nil {
							return nil, nil, fmt.Errorf("failed to decode proof: %w", err)
						}
						data = decoded
					} else if attachment.Data.Json != nil {
						jsonData, err := json.Marshal(attachment.Data.Json)
						if err != nil {
							return nil, nil, fmt.Errorf("failed to marshal proof: %w", err)
						}
						data = jsonData
					}
				}

				if err := json.Unmarshal(data, &proof); err != nil {
					return nil, nil, fmt.Errorf("failed to unmarshal proof: %w", err)
				}
				break
			}
		}
	}

	if proof == nil {
		return nil, nil, fmt.Errorf("no supported proof format found")
	}

	// Get the original proof request from the record
	proofRequest := record.ProofRequest
	if proofRequest == nil {
		// Try to retrieve from storage or context
		log.Printf("Warning: proof request not found in record")
	}

	// Resolve schemas and credential definitions for verification
	schemas, credDefs, err := ps.resolveProofDependencies(proof)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to resolve proof dependencies: %w", err)
	}

	// Verify the proof using verifier service
	log.Printf("🔍 Verifying proof with %d schemas and %d credential definitions", len(schemas), len(credDefs))
	verifyResult, err := ps.verifier.VerifyProof(ps.context, &services.VerifyProofOptions{
		ProofRequest:          proofRequest,
		Proof:                 proof,
		Schemas:               schemas,
		CredentialDefinitions: credDefs,
	})
	if err != nil {
		log.Printf("❌ Verifier returned error: %v", err)
		return nil, nil, fmt.Errorf("proof verification failed: %w", err)
	}

	// Update record based on verification result
	if verifyResult.Verified {
		record.State = "done"
		record.IsVerified = true
		log.Printf("✅ Proof verified successfully for thread %s", thid)
	} else {
		record.State = "abandoned"
		record.Error = "Proof verification failed"
		log.Printf("❌ Proof verification failed for thread %s (verifier returned false)", thid)
	}

	if err := ps.repository.Update(ps.context, record); err != nil {
		log.Printf("Failed to update proof record: %v", err)
	}

	// Create acknowledgment
	ack := proofmsgs.NewAckPresentationV2(common.GenerateUUID(), thid)
	if verifyResult.Verified {
		ack.Status = "OK"
	} else {
		ack.Status = "FAIL"
	}

	return ack, record, nil
}

// ShouldAutoRespondToPresentation checks if we should auto-respond to a presentation
func (ps *ProofService) ShouldAutoRespondToPresentation(
	agentContext *context.AgentContext,
	proofRecord *proofrecs.ProofRecord,
	presentation *proofmsgs.PresentationV2,
) bool {
	// Check if the specific proof record has auto-accept enabled
	if proofRecord != nil && proofRecord.AutoAccept {
		return true
	}
	
	// TODO: Check config when available
	// Default to auto-accepting for now (for testing)
	return true
}

// resolveProofDependencies extracts and resolves schemas and credential definitions from the proof
func (ps *ProofService) resolveProofDependencies(proof map[string]interface{}) (map[string]map[string]interface{}, map[string]map[string]interface{}, error) {
	schemas := make(map[string]map[string]interface{})
	credDefs := make(map[string]map[string]interface{})

	// Extract identifiers from proof
	if identifiers, ok := proof["identifiers"].([]interface{}); ok {
		for _, identifier := range identifiers {
			if id, ok := identifier.(map[string]interface{}); ok {
				if schemaId, ok := id["schema_id"].(string); ok {
					schema, _, err := ps.registry.GetSchema(schemaId)
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
					credDef, _, err := ps.registry.GetCredentialDefinition(credDefId)
					if err != nil {
						log.Printf("Warning: failed to resolve credential definition %s: %v", credDefId, err)
					} else {
						// Convert to map[string]interface{}
						credDefJSON, _ := json.Marshal(credDef)
						var credDefMap map[string]interface{}
						json.Unmarshal(credDefJSON, &credDefMap)
						
						// Fix double-nested structure: extract the inner value for anoncreds compatibility
						if val, ok := credDefMap["value"].(map[string]interface{}); ok {
							// Check if this is a double-nested structure
							if innerType, hasType := val["type"].(string); hasType && innerType == "CL" {
								if innerVal, ok := val["value"].(map[string]interface{}); ok {
									// Reconstruct in the format expected by anoncreds
									credDefMap = map[string]interface{}{
										"issuerId": val["issuerId"],
										"schemaId": val["schemaId"],
										"type":     val["type"],
										"tag":      val["tag"],
										"value":    innerVal,
									}
									log.Printf("🔧 Fixed credential definition structure for %s", credDefId)
								}
							}
						}
						
						credDefs[credDefId] = credDefMap
					}
				}
			}
		}
	}

	return schemas, credDefs, nil
}

func (ps *ProofService) ProcessAck(connectionId string, ack *proofmsgs.AckPresentationV2) error {
	thid := ack.GetThreadId()

	record, err := ps.repository.GetByThreadId(ps.context, thid)
	if err != nil {
		return fmt.Errorf("failed to get proof record: %w", err)
	}

	record.State = "done"
	if err := ps.repository.Update(ps.context, record); err != nil {
		return fmt.Errorf("failed to update proof record: %w", err)
	}

	log.Printf("✅ Proof ACK received for thread %s", thid)
	return nil
}

func (ps *ProofService) GetProofRecord(id string) (*proofrecs.ProofRecord, error) {
	return ps.repository.GetById(ps.context, id)
}

func (ps *ProofService) GetProofRecordByThreadId(threadId string) (*proofrecs.ProofRecord, error) {
	return ps.repository.GetByThreadId(ps.context, threadId)
}

// autoSelectCredentials automatically selects credentials for proof request
func (ps *ProofService) autoSelectCredentials(matches *services.GetCredentialsForProofRequestReturn, proofRequest map[string]interface{}) map[string]interface{} {
	selected := map[string]interface{}{
		"attributes": map[string]interface{}{},
		"predicates": map[string]interface{}{},
		"selfAttested": map[string]interface{}{},
	}

	// Select credentials for attributes
	if attrs, ok := selected["attributes"].(map[string]interface{}); ok {
		for referent, credMatches := range matches.Attributes {
			if len(credMatches) > 0 {
				// Select the first matching credential
				attrs[referent] = map[string]interface{}{
					"credentialId": credMatches[0].CredentialId,
					"revealed":     true, // Default to revealing attributes
				}
			}
		}
	}

	// Select credentials for predicates
	if preds, ok := selected["predicates"].(map[string]interface{}); ok {
		for referent, credMatches := range matches.Predicates {
			if len(credMatches) > 0 {
				// Select the first matching credential
				preds[referent] = map[string]interface{}{
					"credentialId": credMatches[0].CredentialId,
				}
			}
		}
	}

	// Handle self-attested attributes if no credential matches
	if reqAttrs, ok := proofRequest["requested_attributes"].(map[string]interface{}); ok {
		attrs := selected["attributes"].(map[string]interface{})
		selfAttested := selected["selfAttested"].(map[string]interface{})
		
		for referent, reqAttr := range reqAttrs {
			if _, hasCredential := attrs[referent]; !hasCredential {
				// Check if self-attestation is allowed
				if attr, ok := reqAttr.(map[string]interface{}); ok {
					if _, hasSelfAttested := attr["self_attested_allowed"]; hasSelfAttested {
						// Add placeholder for self-attested value
						selfAttested[referent] = "self_attested_value"
					}
				}
			}
		}
	}

	return selected
}

// resolveProofRequestDependencies resolves schemas and credential definitions for proof request
func (ps *ProofService) resolveProofRequestDependencies(proofRequest map[string]interface{}) (map[string]map[string]interface{}, map[string]map[string]interface{}, error) {
	schemas := make(map[string]map[string]interface{})
	credDefs := make(map[string]map[string]interface{})

	// Extract schema and cred def IDs from proof request
	schemaIds := make(map[string]bool)
	credDefIds := make(map[string]bool)

	// From requested attributes
	if reqAttrs, ok := proofRequest["requested_attributes"].(map[string]interface{}); ok {
		for _, attr := range reqAttrs {
			if attrMap, ok := attr.(map[string]interface{}); ok {
				if restrictions, ok := attrMap["restrictions"].([]interface{}); ok {
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
	}

	// From requested predicates
	if reqPreds, ok := proofRequest["requested_predicates"].(map[string]interface{}); ok {
		for _, pred := range reqPreds {
			if predMap, ok := pred.(map[string]interface{}); ok {
				if restrictions, ok := predMap["restrictions"].([]interface{}); ok {
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
	}

	// Resolve schemas
	for schemaId := range schemaIds {
		schema, _, err := ps.registry.GetSchema(schemaId)
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
		credDef, _, err := ps.registry.GetCredentialDefinition(credDefId)
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