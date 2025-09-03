package issuer

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/Ajna-inc/anoncreds-go/pkg/anoncreds"
)

// AnoncredsIssuer implements the anoncreds.Issuer interface using the new wrapper
type AnoncredsIssuer struct {
	mu      sync.RWMutex
	secrets map[string]*issuerSecrets // credDefId -> secrets
}

type issuerSecrets struct {
	CredDefPublic  map[string]interface{}
	CredDefPrivate *anoncreds.CredentialDefinitionPrivate
	KeyProof       *anoncreds.KeyCorrectnessProof
	SchemaID       string
	Schema         *anoncreds.Schema
}

// NewIssuer creates a new issuer instance
func NewIssuer() *AnoncredsIssuer {
	return &AnoncredsIssuer{
		secrets: make(map[string]*issuerSecrets),
	}
}

// StoreIssuerSecrets stores the private keys and KCP for a credential definition
func (i *AnoncredsIssuer) StoreIssuerSecrets(
	credDefID string,
	credDefPublic map[string]interface{},
	credDefPrivate *anoncreds.CredentialDefinitionPrivate,
	keyProof *anoncreds.KeyCorrectnessProof,
	schemaID string,
	schema *anoncreds.Schema,
) {
	i.mu.Lock()
	defer i.mu.Unlock()

	i.secrets[credDefID] = &issuerSecrets{
		CredDefPublic:  credDefPublic,
		CredDefPrivate: credDefPrivate,
		KeyProof:       keyProof,
		SchemaID:       schemaID,
		Schema:         schema,
	}
}

// CreateCredentialOffer builds an anoncreds credential offer for a given credential definition id
func (i *AnoncredsIssuer) CreateCredentialOffer(credentialDefinitionId string) (map[string]interface{}, error) {
	i.mu.RLock()
	secrets, ok := i.secrets[credentialDefinitionId]
	i.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("no issuer secrets found for credential definition: %s", credentialDefinitionId)
	}

	return anoncreds.CreateCredentialOfferJSON(anoncreds.CreateCredentialOfferOptions{
		SchemaID:               secrets.SchemaID,
		CredentialDefinitionID: credentialDefinitionId,
		KeyCorrectnessProof:    secrets.KeyProof,
	})
}

// CreateCredential issues a credential given offer, request and attribute values
func (i *AnoncredsIssuer) CreateCredential(
	offer map[string]interface{},
	request map[string]interface{},
	values map[string]map[string]string,
) (credential map[string]interface{}, credentialRevocationId string, err error) {
	// Extract credential definition ID from offer
	credDefID, ok := offer["cred_def_id"].(string)
	if !ok {
		return nil, "", fmt.Errorf("offer missing cred_def_id")
	}

	i.mu.RLock()
	secrets, ok := i.secrets[credDefID]
	i.mu.RUnlock()

	if !ok {
		return nil, "", fmt.Errorf("no issuer secrets found for credential definition: %s", credDefID)
	}

	// Convert offer and request to proper types
	credOffer, err := anoncreds.CredentialOfferFromJSON(offer)
	if err != nil {
		return nil, "", fmt.Errorf("invalid offer: %w", err)
	}
	defer credOffer.Clear()

	credRequest, err := anoncreds.CredentialRequestFromJSON(request)
	if err != nil {
		return nil, "", fmt.Errorf("invalid request: %w", err)
	}
	defer credRequest.Clear()

	// Recreate credential definition from stored public JSON
	credDefJSON, _ := json.Marshal(secrets.CredDefPublic)
	credDef, err := anoncreds.CredentialDefinitionFromJSON(string(credDefJSON))
	if err != nil {
		return nil, "", fmt.Errorf("invalid credential definition: %w", err)
	}
	defer credDef.Clear()

	// Create the credential
	cred, err := anoncreds.CreateCredential(anoncreds.CreateCredentialOptions{
		CredentialDefinition:        credDef,
		CredentialDefinitionPrivate: secrets.CredDefPrivate,
		CredentialOffer:             credOffer,
		CredentialRequest:           credRequest,
		AttributeRawValues:          extractRawValues(values),
		AttributeEncodedValues:      extractEncodedValues(values),
	})
	if err != nil {
		return nil, "", fmt.Errorf("failed to create credential: %w", err)
	}
	defer cred.Clear()

	// Get credential as JSON
	credJSON, err := cred.ToJSON()
	if err != nil {
		return nil, "", fmt.Errorf("failed to convert credential to JSON: %w", err)
	}

	// Extract revocation ID if present
	var revocationId string
	if revRegIndex, ok := credJSON["rev_reg_index"].(float64); ok {
		revocationId = fmt.Sprintf("%d", int(revRegIndex))
	}

	return credJSON, revocationId, nil
}

// Helper to extract raw values from the values map
func extractRawValues(values map[string]map[string]string) map[string]string {
	result := make(map[string]string)
	for attr, vals := range values {
		if raw, ok := vals["raw"]; ok {
			result[attr] = raw
		}
	}
	return result
}

// Helper to extract encoded values from the values map
func extractEncodedValues(values map[string]map[string]string) map[string]string {
	result := make(map[string]string)
	for attr, vals := range values {
		if encoded, ok := vals["encoded"]; ok {
			result[attr] = encoded
		}
	}
	return result
}

// CreateAndStoreCredentialDefinition creates a new credential definition and stores the secrets
func (i *AnoncredsIssuer) CreateAndStoreCredentialDefinition(
	schemaID string,
	schema *anoncreds.Schema,
	issuerID string,
	tag string,
	credDefID string,
) (credDefPublicJSON string, keyProofJSON string, err error) {
	// Create credential definition
	result, err := anoncreds.CreateCredentialDefinition(anoncreds.CreateCredentialDefinitionOptions{
		SchemaID:          schemaID,
		Schema:            schema,
		IssuerID:          issuerID,
		Tag:               tag,
		SignatureType:     "CL",
		SupportRevocation: false,
	})
	if err != nil {
		return "", "", err
	}

	// Get public JSON
	credDefPublic, err := result.CredentialDefinition.ToJSON()
	if err != nil {
		result.CredentialDefinition.Clear()
		result.CredentialDefinitionPrivate.Clear()
		result.KeyCorrectnessProof.Clear()
		return "", "", err
	}

	// Get KCP JSON
	kcpJSON, err := result.KeyCorrectnessProof.ToJSON()
	if err != nil {
		result.CredentialDefinition.Clear()
		result.CredentialDefinitionPrivate.Clear()
		result.KeyCorrectnessProof.Clear()
		return "", "", err
	}

	// Store secrets (keep handles alive)
	i.StoreIssuerSecrets(
		credDefID,
		credDefPublic,
		result.CredentialDefinitionPrivate,
		result.KeyCorrectnessProof,
		schemaID,
		schema,
	)

	// Note: We keep the credential definition objects alive in secrets
	// They will be cleaned up when the issuer is destroyed

	credDefPublicBytes, _ := json.Marshal(credDefPublic)
	kcpBytes, _ := json.Marshal(kcpJSON)

	return string(credDefPublicBytes), string(kcpBytes), nil
}
