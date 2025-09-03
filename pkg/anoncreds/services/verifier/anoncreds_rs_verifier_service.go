package verifier

import (
	"encoding/json"
	"fmt"
	"log"
	
	anoncreds "github.com/Ajna-inc/anoncreds-go/pkg/anoncreds"
	"github.com/ajna-inc/essi/pkg/anoncreds/services"
	"github.com/ajna-inc/essi/pkg/core/context"
)

// AnonCredsRsVerifierService implements the AnonCredsVerifierService interface
type AnonCredsRsVerifierService struct {
	anoncredsLib interface{}
}

// NewAnonCredsRsVerifierService creates a new verifier service
func NewAnonCredsRsVerifierService(anoncredsLib interface{}) *AnonCredsRsVerifierService {
	return &AnonCredsRsVerifierService{
		anoncredsLib: anoncredsLib,
	}
}

func (s *AnonCredsRsVerifierService) VerifyProof(ctx *context.AgentContext, options *services.VerifyProofOptions) (*services.VerifyProofReturn, error) {
	if options == nil {
		return &services.VerifyProofReturn{Verified: false}, fmt.Errorf("options is nil")
	}
	
	// Log what we're verifying
	log.Printf("🔍 [Verifier] Starting proof verification")
	log.Printf("🔍 [Verifier] Proof request: %+v", options.ProofRequest)
	log.Printf("🔍 [Verifier] Number of schemas: %d", len(options.Schemas))
	log.Printf("🔍 [Verifier] Number of cred defs: %d", len(options.CredentialDefinitions))
	
	// Parse presentation from proof JSON (following TypeScript pattern)
	presentation, err := anoncreds.PresentationFromJSON(options.Proof)
	if err != nil {
		log.Printf("❌ [Verifier] Failed to parse presentation: %v", err)
		return &services.VerifyProofReturn{Verified: false}, fmt.Errorf("failed to parse presentation: %w", err)
	}
	defer presentation.Clear()
	
	// Parse presentation request from ProofRequest (it's already a map[string]interface{})
	presentationRequest, err := anoncreds.PresentationRequestFromJSON(options.ProofRequest)
	if err != nil {
		log.Printf("❌ [Verifier] Failed to parse presentation request: %v", err)
		return &services.VerifyProofReturn{Verified: false}, fmt.Errorf("failed to parse presentation request: %w", err)
	}
	defer presentationRequest.Clear()
	
	// Parse schemas
	schemas := make(map[string]*anoncreds.Schema)
	for id, schemaJSON := range options.Schemas {
		schema, err := anoncreds.SchemaFromJSON(schemaJSON)
		if err != nil {
			// Clean up previously parsed schemas
			for _, s := range schemas {
				if s != nil {
					s.Clear()
				}
			}
			log.Printf("❌ [Verifier] Failed to parse schema %s: %v", id, err)
			return &services.VerifyProofReturn{Verified: false}, fmt.Errorf("failed to parse schema %s: %w", id, err)
		}
		schemas[id] = schema
	}
	// Clean up schemas after use
	defer func() {
		for _, s := range schemas {
			if s != nil {
				s.Clear()
			}
		}
	}()
	
	// Parse credential definitions
	credDefs := make(map[string]*anoncreds.CredentialDefinition)
	for id, credDefJSON := range options.CredentialDefinitions {
		// Log the credential definition JSON for debugging
		credDefBytes, _ := json.Marshal(credDefJSON)
		log.Printf("🔍 [Verifier] Parsing credential definition %s: %s", id, string(credDefBytes))
		
		credDef, err := anoncreds.CredentialDefinitionFromJSON(credDefJSON)
		if err != nil {
			// Clean up previously parsed credential definitions
			for _, cd := range credDefs {
				if cd != nil {
					cd.Clear()
				}
			}
			log.Printf("❌ [Verifier] Failed to parse credential definition %s: %v", id, err)
			log.Printf("❌ [Verifier] CredDef JSON type: %T", credDefJSON)
			return &services.VerifyProofReturn{Verified: false}, fmt.Errorf("failed to parse credential definition %s: %w", id, err)
		}
		credDefs[id] = credDef
	}
	// Clean up credential definitions after use
	defer func() {
		for _, cd := range credDefs {
			if cd != nil {
				cd.Clear()
			}
		}
	}()
	
	// Verify the presentation using the new VerifyPresentation function
	verified, err := anoncreds.VerifyPresentation(anoncreds.VerifyPresentationOptions{
		Presentation:          presentation,
		PresentationRequest:   presentationRequest,
		Schemas:               schemas,
		CredentialDefinitions: credDefs,
		// RevocationRegistries and RevocationStatusLists can be added when needed
	})
	
	if err != nil {
		log.Printf("❌ [Verifier] Proof verification error: %v", err)
		return &services.VerifyProofReturn{Verified: false}, fmt.Errorf("proof verification failed: %w", err)
	}
	
	log.Printf("✅ [Verifier] Proof verification result: %v", verified)
	
	return &services.VerifyProofReturn{
		Verified: verified,
	}, nil
}

