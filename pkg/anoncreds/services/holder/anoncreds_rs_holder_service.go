package holder

import (
	"encoding/json"
	"fmt"
	"log"
	"sync"

	"github.com/Ajna-inc/anoncreds-go/pkg/anoncreds"
	"github.com/ajna-inc/essi/pkg/anoncreds/repository"
	"github.com/ajna-inc/essi/pkg/anoncreds/services"
	"github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/core/di"
	"github.com/google/uuid"
)

// AnonCredsRsHolderService implements the AnonCredsHolderService interface using anoncreds-rs
type AnonCredsRsHolderService struct {
	linkSecretRepo  LinkSecretRepository
	credentialRepo  CredentialRepository
	registryService RegistryService

	// In-memory caches
	linkSecrets   map[string]string
	linkSecretsMu sync.RWMutex
}

// NewAnonCredsRsHolderService creates a new holder service instance
func NewAnonCredsRsHolderService(anoncredsLib interface{}) *AnonCredsRsHolderService {
	// anoncredsLib parameter kept for compatibility but not used
	// The anoncreds package functions are used directly
	return &AnonCredsRsHolderService{linkSecrets: make(map[string]string)}
}

// SetRepositories sets the repositories (injected by dependency manager)
func (s *AnonCredsRsHolderService) SetRepositories(
	linkSecretRepo LinkSecretRepository,
	credentialRepo CredentialRepository,
	registryService RegistryService,
) {
	s.linkSecretRepo = linkSecretRepo
	s.credentialRepo = credentialRepo
	s.registryService = registryService
}

// CreateLinkSecret creates a new link secret
func (s *AnonCredsRsHolderService) CreateLinkSecret(
	ctx *context.AgentContext,
	options *services.CreateLinkSecretOptions,
) (*services.CreateLinkSecretReturn, error) {
	linkSecretId := options.LinkSecretId
	if linkSecretId == "" {
		linkSecretId = uuid.New().String()
	}
	linkSecretObj, err := anoncreds.CreateLinkSecret()
	if err != nil {
		return nil, fmt.Errorf("failed to create link secret: %w", err)
	}
	linkSecret := linkSecretObj.Value
	if s.linkSecretRepo != nil {
		if err := s.linkSecretRepo.Save(ctx, linkSecretId, linkSecret); err != nil {
			log.Printf("Warning: Failed to persist link secret: %v", err)
		}
	}
	s.linkSecretsMu.Lock()
	s.linkSecrets[linkSecretId] = linkSecret
	s.linkSecretsMu.Unlock()
	return &services.CreateLinkSecretReturn{LinkSecretId: linkSecretId, LinkSecretValue: linkSecret}, nil
}

// CreateCredentialRequest creates a credential request
func (s *AnonCredsRsHolderService) CreateCredentialRequest(
	ctx *context.AgentContext,
	options *services.CreateCredentialRequestOptions,
) (*services.CreateCredentialRequestReturn, error) {
	// Get link secret - use provided ID or default
	linkSecretId := options.LinkSecretId
	linkSecret, err := s.getLinkSecret(ctx, linkSecretId)
	if err != nil {
		return nil, fmt.Errorf("failed to get link secret: %w", err)
	}

	// Convert offer map to JSON string
	offerJSON, err := json.Marshal(options.CredentialOffer)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal credential offer: %w", err)
	}

	// Convert offer to CredentialOffer type
	credOffer, err := anoncreds.CredentialOfferFromJSON(string(offerJSON))
	if err != nil {
		return nil, fmt.Errorf("failed to parse credential offer: %w", err)
	}
	defer credOffer.Clear()

	// Convert credential definition
	credDefJson, err := json.Marshal(options.CredentialDefinition)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal credential definition: %w", err)
	}

	credDef, err := anoncreds.CredentialDefinitionFromJSON(string(credDefJson))
	if err != nil {
		return nil, fmt.Errorf("failed to parse credential definition: %w", err)
	}
	defer credDef.Clear()

	// Create link secret object
	linkSecretObj := &anoncreds.LinkSecret{Value: linkSecret}

	// Create credential request
	result, err := anoncreds.CreateCredentialRequest(anoncreds.CreateCredentialRequestOptions{
		CredentialDefinition: credDef,
		LinkSecret:           linkSecretObj,
		LinkSecretID:         options.LinkSecretId,
		CredentialOffer:      credOffer,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create credential request: %w", err)
	}
	defer result.CredentialRequest.Clear()
	defer result.CredentialRequestMetadata.Clear()

	// Convert to JSON
	requestMap, err := result.CredentialRequest.ToJSON()
	if err != nil {
		return nil, fmt.Errorf("failed to convert request to JSON: %w", err)
	}

	metadataMap, err := result.CredentialRequestMetadata.ToJSON()
	if err != nil {
		return nil, fmt.Errorf("failed to convert metadata to JSON: %w", err)
	}

	return &services.CreateCredentialRequestReturn{
		CredentialRequest:         requestMap,
		CredentialRequestMetadata: metadataMap,
	}, nil
}

// StoreCredential stores a credential
func (s *AnonCredsRsHolderService) StoreCredential(
	ctx *context.AgentContext,
	options *services.StoreCredentialOptions,
	metadata map[string]interface{},
) (string, error) {
	// Get link secret - use the same one that was used for the credential request
	linkSecretId := "default"
	if options.CredentialRequestMetadata != nil {
		// Check for link_secret_name first (what anoncreds returns)
		if lsName, ok := options.CredentialRequestMetadata["link_secret_name"].(string); ok {
			linkSecretId = lsName
		} else if lsId, ok := options.CredentialRequestMetadata["link_secret_id"].(string); ok {
			linkSecretId = lsId
		}
	}

	linkSecret, err := s.getLinkSecret(ctx, linkSecretId)
	if err != nil {
		return "", fmt.Errorf("failed to get link secret: %w", err)
	}

	// Convert credential map to JSON string
	credentialJSON, err := json.Marshal(options.Credential)
	if err != nil {
		return "", fmt.Errorf("failed to marshal credential: %w", err)
	}

	// Convert credential to Credential type
	cred, err := anoncreds.CredentialFromJSON(string(credentialJSON))
	if err != nil {
		return "", fmt.Errorf("failed to parse credential: %w", err)
	}
	defer cred.Clear()

	// Convert request metadata map to JSON string
	reqMetadataJSON, err := json.Marshal(options.CredentialRequestMetadata)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request metadata: %w", err)
	}

	// Convert request metadata
	reqMetadata, err := anoncreds.CredentialRequestMetadataFromJSON(string(reqMetadataJSON))
	if err != nil {
		return "", fmt.Errorf("failed to parse request metadata: %w", err)
	}
	defer reqMetadata.Clear()

	// Convert credential definition
	credDefJson, err := json.Marshal(options.CredentialDefinition)
	if err != nil {
		return "", fmt.Errorf("failed to marshal credential definition: %w", err)
	}

	credDef, err := anoncreds.CredentialDefinitionFromJSON(string(credDefJson))
	if err != nil {
		return "", fmt.Errorf("failed to parse credential definition: %w", err)
	}
	defer credDef.Clear()

	// Create link secret object
	linkSecretObj := &anoncreds.LinkSecret{Value: linkSecret}

	// Process credential with anoncreds library
	log.Printf("Processing credential with link secret ID: %s", linkSecretId)
	processedCred, err := anoncreds.ProcessCredential(anoncreds.ProcessCredentialOptions{
		Credential:                cred,
		CredentialRequestMetadata: reqMetadata,
		LinkSecret:                linkSecretObj,
		CredentialDefinition:      credDef,
	})
	if err != nil {
		// Log more details about the error
		log.Printf("ProcessCredential failed with link secret ID: %s", linkSecretId)
		log.Printf("Credential has cred_def_id: %v", options.Credential["cred_def_id"])
		log.Printf("CredDef has id: %v", options.CredentialDefinition["id"])
		return "", fmt.Errorf("failed to process credential: %w", err)
	}
	defer processedCred.Clear()

	// Convert to JSON string for storage
	processedCredJson, err := processedCred.ToJSON()
	if err != nil {
		return "", fmt.Errorf("failed to convert processed credential to JSON: %w", err)
	}

	processedCredStr, err := json.Marshal(processedCredJson)
	if err != nil {
		return "", fmt.Errorf("failed to marshal processed credential: %w", err)
	}

	// Generate credential ID if not provided
	credentialId := options.CredentialId
	if credentialId == "" {
		credentialId = uuid.New().String()
	}

	// Store in repository
	if s.credentialRepo != nil {
		credRecord := &CredentialRecord{
			Id:                     credentialId,
			Credential:             string(processedCredStr),
			CredentialDefinitionId: getCredDefId(options.CredentialDefinition),
			SchemaId:               getSchemaId(options.Schema),
			Metadata:               metadata,
		}

		if err := s.credentialRepo.Save(ctx, credRecord); err != nil {
			return "", fmt.Errorf("failed to store credential: %w", err)
		}
	}

	log.Printf("Stored credential with ID: %s", credentialId)
	return credentialId, nil
}

// GetCredential retrieves a credential by ID
func (s *AnonCredsRsHolderService) GetCredential(
	ctx *context.AgentContext,
	options *services.GetCredentialOptions,
) (*services.AnonCredsCredentialInfo, error) {
	if s.credentialRepo == nil {
		return nil, fmt.Errorf("credential repository not available")
	}

	record, err := s.credentialRepo.GetById(ctx, options.CredentialId)
	if err != nil {
		return nil, fmt.Errorf("failed to get credential: %w", err)
	}

	return convertToCredentialInfo(record), nil
}

// GetCredentials retrieves credentials matching a filter
func (s *AnonCredsRsHolderService) GetCredentials(
	ctx *context.AgentContext,
	options *services.GetCredentialsOptions,
) ([]*services.AnonCredsCredentialInfo, error) {
	if s.credentialRepo == nil {
		return nil, fmt.Errorf("credential repository not available")
	}

	records, err := s.credentialRepo.GetByFilter(ctx, options.Filter)
	if err != nil {
		return nil, fmt.Errorf("failed to get credentials: %w", err)
	}

	infos := make([]*services.AnonCredsCredentialInfo, len(records))
	for i, record := range records {
		infos[i] = convertToCredentialInfo(record)
	}

	return infos, nil
}

// DeleteCredential deletes a credential
func (s *AnonCredsRsHolderService) DeleteCredential(
	ctx *context.AgentContext,
	credentialId string,
) error {
	if s.credentialRepo == nil {
		return fmt.Errorf("credential repository not available")
	}

	return s.credentialRepo.Delete(ctx, credentialId)
}

// CreateProof creates a proof
// CreateProof is now implemented in proof_creation.go

// GetCredentialsForProofRequest gets credentials matching a proof request
func (s *AnonCredsRsHolderService) GetCredentialsForProofRequest(
	ctx *context.AgentContext,
	options *services.GetCredentialsForProofRequestOptions,
) (*services.GetCredentialsForProofRequestReturn, error) {
	if s.credentialRepo == nil {
		return nil, fmt.Errorf("credential repository not available")
	}

	// Parse proof request to extract requirements
	proofRequest := options.ProofRequest

	result := &services.GetCredentialsForProofRequestReturn{
		Attributes: make(map[string][]*services.AnonCredsRequestedAttributeMatch),
		Predicates: make(map[string][]*services.AnonCredsRequestedPredicateMatch),
	}

	// Get all credentials
	allCreds, err := s.credentialRepo.GetAll(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get credentials: %w", err)
	}

	// Match credentials against requested attributes
	if reqAttrs, ok := proofRequest["requested_attributes"].(map[string]interface{}); ok {
		for attrRef, reqAttr := range reqAttrs {
			matches := s.findMatchingCredentialsForAttribute(allCreds, reqAttr)
			result.Attributes[attrRef] = matches
		}
	}

	// Match credentials against requested predicates
	if reqPreds, ok := proofRequest["requested_predicates"].(map[string]interface{}); ok {
		for predRef, reqPred := range reqPreds {
			matches := s.findMatchingCredentialsForPredicate(allCreds, reqPred)
			result.Predicates[predRef] = matches
		}
	}

	return result, nil
}

// GenerateNonce generates a nonce for proof requests
func (s *AnonCredsRsHolderService) GenerateNonce(ctx *context.AgentContext) string {
	nonce, err := anoncreds.New().GenerateNonce()
	if err != nil {
		// Generate a simple random nonce as fallback
		return uuid.New().String()
	}
	return nonce
}

// Helper functions

func (s *AnonCredsRsHolderService) getLinkSecret(ctx *context.AgentContext, linkSecretId string) (string, error) {
	// If no ID provided, try default via DI
	if linkSecretId == "" {
		if ctx != nil && ctx.DependencyManager != nil {
			if dm, ok := ctx.DependencyManager.(di.DependencyManager); ok {
				if any, err := dm.Resolve(di.TokenLinkSecretRepository); err == nil {
					if repo, ok := any.(repository.LinkSecretRepository); ok && repo != nil {
						if defaultRecord, err := repo.FindDefault(ctx); err == nil && defaultRecord != nil {
							linkSecretId = defaultRecord.LinkSecretId
							if defaultRecord.Value != "" {
								s.linkSecretsMu.Lock()
								s.linkSecrets[linkSecretId] = defaultRecord.Value
								s.linkSecretsMu.Unlock()
								return defaultRecord.Value, nil
							}
						}
					}
				}
			}
		}
		linkSecretId = "default"
	}
	// Cache
	s.linkSecretsMu.RLock()
	linkSecret, exists := s.linkSecrets[linkSecretId]
	s.linkSecretsMu.RUnlock()
	if exists {
		return linkSecret, nil
	}
	// Query repo via DI
	if ctx != nil && ctx.DependencyManager != nil {
		if dm, ok := ctx.DependencyManager.(di.DependencyManager); ok {
			if any, err := dm.Resolve(di.TokenLinkSecretRepository); err == nil {
				if repo, ok := any.(repository.LinkSecretRepository); ok && repo != nil {
					if record, err := repo.FindByLinkSecretId(ctx, linkSecretId); err == nil && record != nil && record.Value != "" {
						s.linkSecretsMu.Lock()
						s.linkSecrets[linkSecretId] = record.Value
						s.linkSecretsMu.Unlock()
						return record.Value, nil
					}
				}
			}
		}
	}
	if linkSecretId == "default" || linkSecretId == "" {
		result, err := s.CreateLinkSecret(ctx, &services.CreateLinkSecretOptions{LinkSecretId: linkSecretId})
		if err != nil {
			return "", err
		}
		return result.LinkSecretValue, nil
	}
	return "", fmt.Errorf("link secret not found: %s", linkSecretId)
}

func (s *AnonCredsRsHolderService) findMatchingCredentialsForAttribute(
	credentials []*CredentialRecord,
	reqAttr interface{},
) []*services.AnonCredsRequestedAttributeMatch {
	var matches []*services.AnonCredsRequestedAttributeMatch

	// TODO: Implement proper matching logic based on restrictions
	// For now, return all credentials that have the requested attribute

	return matches
}

func (s *AnonCredsRsHolderService) findMatchingCredentialsForPredicate(
	credentials []*CredentialRecord,
	reqPred interface{},
) []*services.AnonCredsRequestedPredicateMatch {
	var matches []*services.AnonCredsRequestedPredicateMatch

	// TODO: Implement proper matching logic based on restrictions
	// For now, return all credentials that have the requested predicate

	return matches
}

func convertToCredentialInfo(record *CredentialRecord) *services.AnonCredsCredentialInfo {
	return &services.AnonCredsCredentialInfo{
		CredentialId:           record.Id,
		SchemaId:               record.SchemaId,
		CredentialDefinitionId: record.CredentialDefinitionId,
		Attributes:             extractAttributes(record.Credential),
		Metadata:               record.Metadata,
		MethodName:             "anoncreds",
	}
}

func extractAttributes(credential string) map[string]string {
	attrs := make(map[string]string)

	// Parse credential to extract attribute values
	var credMap map[string]interface{}
	if err := json.Unmarshal([]byte(credential), &credMap); err == nil {
		if values, ok := credMap["values"].(map[string]interface{}); ok {
			for name, value := range values {
				if valMap, ok := value.(map[string]interface{}); ok {
					if raw, ok := valMap["raw"].(string); ok {
						attrs[name] = raw
					}
				}
			}
		}
	}

	return attrs
}

func getCredDefId(credDef map[string]interface{}) string {
	if id, ok := credDef["id"].(string); ok {
		return id
	}
	return ""
}

func getSchemaId(schema map[string]interface{}) string {
	if id, ok := schema["id"].(string); ok {
		return id
	}
	return ""
}
