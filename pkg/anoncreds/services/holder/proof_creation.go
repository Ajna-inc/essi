package holder

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/Ajna-inc/anoncreds-go/pkg/anoncreds"
	"github.com/ajna-inc/essi/pkg/anoncreds/services"
	"github.com/ajna-inc/essi/pkg/core/context"
)

// CreateProof creates a proof for the given proof request
func (s *AnonCredsRsHolderService) CreateProof(
	ctx *context.AgentContext,
	options *services.CreateProofOptions,
) (*services.AnonCredsProof, error) {
	// Get link secret
	linkSecretId := options.LinkSecretId
	if linkSecretId == "" {
		linkSecretId = "default"
	}
	
	linkSecret, err := s.getLinkSecret(ctx, linkSecretId)
	if err != nil {
		return nil, fmt.Errorf("failed to get link secret: %w", err)
	}
	
	// Parse proof request
	proofRequest, err := anoncreds.PresentationRequestFromJSON(options.ProofRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to parse proof request: %w", err)
	}
	defer proofRequest.Clear()
	
	// Prepare credentials and prove items
	credentials := []anoncreds.CredentialForPresentation{}
	credentialsProve := []anoncreds.CredentialProve{}
	credentialIndex := make(map[string]int) // Map credential ID to index
	
	// Process selected credentials for attributes
	if attrs, ok := options.SelectedCredentials["attributes"].(map[string]interface{}); ok {
		for referent, selection := range attrs {
			selectionMap, ok := selection.(map[string]interface{})
			if !ok {
				continue
			}
			
			credId, _ := selectionMap["credentialId"].(string)
			revealed, _ := selectionMap["revealed"].(bool)
			
			// Get the credential from repository
			credRecord, err := s.credentialRepo.GetById(ctx, credId)
			if err != nil {
				return nil, fmt.Errorf("failed to get credential %s: %w", credId, err)
			}
			
			// Check if we already added this credential
			index, exists := credentialIndex[credId]
			if !exists {
				// Parse the stored credential
				credJSON, err := json.Marshal(credRecord.Credential)
				if err != nil {
					return nil, fmt.Errorf("failed to marshal credential: %w", err)
				}
				
				cred, err := anoncreds.CredentialFromJSON(string(credJSON))
				if err != nil {
					return nil, fmt.Errorf("failed to parse credential: %w", err)
				}
				
				index = len(credentials)
				credentials = append(credentials, anoncreds.CredentialForPresentation{
					Credential: cred,
				})
				credentialIndex[credId] = index
			}
			
			credentialsProve = append(credentialsProve, anoncreds.CredentialProve{
				EntryIndex:  index,
				Referent:    referent,
				IsPredicate: false,
				Reveal:      revealed,
			})
		}
	}
	
	// Process selected credentials for predicates
	if preds, ok := options.SelectedCredentials["predicates"].(map[string]interface{}); ok {
		for referent, selection := range preds {
			selectionMap, ok := selection.(map[string]interface{})
			if !ok {
				continue
			}
			
			credId, _ := selectionMap["credentialId"].(string)
			
			// Get the credential from repository
			credRecord, err := s.credentialRepo.GetById(ctx, credId)
			if err != nil {
				return nil, fmt.Errorf("failed to get credential %s: %w", credId, err)
			}
			
			// Check if we already added this credential
			index, exists := credentialIndex[credId]
			if !exists {
				// Parse the stored credential
				credJSON, err := json.Marshal(credRecord.Credential)
				if err != nil {
					return nil, fmt.Errorf("failed to marshal credential: %w", err)
				}
				
				cred, err := anoncreds.CredentialFromJSON(string(credJSON))
				if err != nil {
					return nil, fmt.Errorf("failed to parse credential: %w", err)
				}
				
				index = len(credentials)
				credentials = append(credentials, anoncreds.CredentialForPresentation{
					Credential: cred,
				})
				credentialIndex[credId] = index
			}
			
			credentialsProve = append(credentialsProve, anoncreds.CredentialProve{
				EntryIndex:  index,
				Referent:    referent,
				IsPredicate: true,
				Reveal:      false, // Predicates never reveal values
			})
		}
	}
	
	// Process self-attested attributes
	selfAttestedAttrs := make(map[string]string)
	if selfAttested, ok := options.SelectedCredentials["selfAttestedAttributes"].(map[string]interface{}); ok {
		for referent, value := range selfAttested {
			if strValue, ok := value.(string); ok {
				selfAttestedAttrs[referent] = strValue
			}
		}
	}
	
	// Convert schemas to anoncreds format
	schemas := make(map[string]*anoncreds.Schema)
	for id, schemaData := range options.Schemas {
		schemaJSON, err := json.Marshal(schemaData)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal schema %s: %w", id, err)
		}
		
		schema, err := anoncreds.SchemaFromJSON(string(schemaJSON))
		if err != nil {
			return nil, fmt.Errorf("failed to parse schema %s: %w", id, err)
		}
		schemas[id] = schema
	}
	
	// Convert credential definitions to anoncreds format
	credDefs := make(map[string]*anoncreds.CredentialDefinition)
	for id, credDefData := range options.CredentialDefinitions {
		credDefJSON, err := json.Marshal(credDefData)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal credential definition %s: %w", id, err)
		}
		
		credDef, err := anoncreds.CredentialDefinitionFromJSON(string(credDefJSON))
		if err != nil {
			return nil, fmt.Errorf("failed to parse credential definition %s: %w", id, err)
		}
		credDefs[id] = credDef
	}
	
	// Create the presentation
	log.Printf("Creating presentation with %d credentials, %d prove items", len(credentials), len(credentialsProve))
	
	presentationResult, err := anoncreds.CreatePresentation(anoncreds.CreatePresentationOptions{
		PresentationRequest: proofRequest,
		Credentials:         credentials,
		CredentialsProve:    credentialsProve,
		SelfAttestedAttrs:   selfAttestedAttrs,
		LinkSecret:          linkSecret,
		Schemas:             schemas,
		CredentialDefs:      credDefs,
	})
	
	if err != nil {
		return nil, fmt.Errorf("failed to create presentation: %w", err)
	}
	defer presentationResult.Presentation.Clear()
	
	// Convert presentation to JSON
	presentationJSON, err := presentationResult.Presentation.ToJSON()
	if err != nil {
		return nil, fmt.Errorf("failed to convert presentation to JSON: %w", err)
	}
	
	// Clean up anoncreds objects
	for _, schema := range schemas {
		schema.Clear()
	}
	for _, credDef := range credDefs {
		credDef.Clear()
	}
	for _, credEntry := range credentials {
		credEntry.Credential.Clear()
	}
	
	// Build the response
	proof := &services.AnonCredsProof{
		Proof:          presentationJSON,
		RequestedProof: presentationJSON["requested_proof"].(map[string]interface{}),
		Identifiers:    []interface{}{}, // TODO: Populate identifiers if needed
	}
	
	return proof, nil
}