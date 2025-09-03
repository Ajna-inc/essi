package services

import (
	"github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/core/di"
)

// Service symbols for dependency injection
const (
	AnonCredsHolderServiceSymbol   = "AnonCredsHolderService"
	AnonCredsIssuerServiceSymbol   = "AnonCredsIssuerService"
	AnonCredsVerifierServiceSymbol = "AnonCredsVerifierService"
)

// DI Tokens for service registration
var (
	TokenAnonCredsHolderService   = di.Token{Name: "AnonCredsHolderService"}
	TokenAnonCredsIssuerService   = di.Token{Name: "AnonCredsIssuerService"}
	TokenAnonCredsVerifierService = di.Token{Name: "AnonCredsVerifierService"}
)

// AnonCredsHolderService defines the interface for holder operations
type AnonCredsHolderService interface {
	// Link secret management
	CreateLinkSecret(ctx *context.AgentContext, options *CreateLinkSecretOptions) (*CreateLinkSecretReturn, error)
	
	// Credential operations
	CreateCredentialRequest(ctx *context.AgentContext, options *CreateCredentialRequestOptions) (*CreateCredentialRequestReturn, error)
	StoreCredential(ctx *context.AgentContext, options *StoreCredentialOptions, metadata map[string]interface{}) (string, error)
	GetCredential(ctx *context.AgentContext, options *GetCredentialOptions) (*AnonCredsCredentialInfo, error)
	GetCredentials(ctx *context.AgentContext, options *GetCredentialsOptions) ([]*AnonCredsCredentialInfo, error)
	DeleteCredential(ctx *context.AgentContext, credentialId string) error
	
	// Proof operations
	CreateProof(ctx *context.AgentContext, options *CreateProofOptions) (*AnonCredsProof, error)
	GetCredentialsForProofRequest(ctx *context.AgentContext, options *GetCredentialsForProofRequestOptions) (*GetCredentialsForProofRequestReturn, error)
	
	// Utility
	GenerateNonce(ctx *context.AgentContext) string
}

// AnonCredsIssuerService defines the interface for issuer operations
type AnonCredsIssuerService interface {
	CreateSchema(ctx *context.AgentContext, options *CreateSchemaOptions) (*AnonCredsSchema, error)
	CreateCredentialDefinition(ctx *context.AgentContext, options *CreateCredentialDefinitionOptions) (*CreateCredentialDefinitionReturn, error)
	CreateCredentialOffer(ctx *context.AgentContext, options *CreateCredentialOfferOptions) (*AnonCredsCredentialOffer, error)
	CreateCredential(ctx *context.AgentContext, options *CreateCredentialOptions) (*CreateCredentialReturn, error)
	CreateRevocationRegistryDefinition(ctx *context.AgentContext, options *CreateRevocationRegistryDefinitionOptions) (*CreateRevocationRegistryDefinitionReturn, error)
	UpdateRevocationStatusList(ctx *context.AgentContext, options *UpdateRevocationStatusListOptions) (*RevocationStatusList, error)
}

// AnonCredsVerifierService defines the interface for verifier operations
type AnonCredsVerifierService interface {
	VerifyProof(ctx *context.AgentContext, options *VerifyProofOptions) (*VerifyProofReturn, error)
}

// Option structures for holder operations
type CreateLinkSecretOptions struct {
	LinkSecretId string `json:"linkSecretId,omitempty"`
}

type CreateLinkSecretReturn struct {
	LinkSecretId    string `json:"linkSecretId"`
	LinkSecretValue string `json:"linkSecretValue"`
}

type CreateCredentialRequestOptions struct {
	CredentialOffer          map[string]interface{} `json:"credentialOffer"`
	CredentialDefinition     map[string]interface{} `json:"credentialDefinition"`
	LinkSecretId            string                 `json:"linkSecretId"`
}

type CreateCredentialRequestReturn struct {
	CredentialRequest         map[string]interface{} `json:"credentialRequest"`
	CredentialRequestMetadata map[string]interface{} `json:"credentialRequestMetadata"`
}

type StoreCredentialOptions struct {
	Credential                map[string]interface{} `json:"credential"`
	CredentialDefinition      map[string]interface{} `json:"credentialDefinition"`
	Schema                    map[string]interface{} `json:"schema"`
	CredentialRequestMetadata map[string]interface{} `json:"credentialRequestMetadata"`
	CredentialId              string                 `json:"credentialId,omitempty"`
	RevocationRegistry        map[string]interface{} `json:"revocationRegistry,omitempty"`
}

type GetCredentialOptions struct {
	CredentialId string `json:"credentialId"`
}

type GetCredentialsOptions struct {
	Filter *CredentialFilter `json:"filter,omitempty"`
}

type CredentialFilter struct {
	SchemaId              string            `json:"schemaId,omitempty"`
	CredentialDefinitionId string            `json:"credentialDefinitionId,omitempty"`
	IssuerDid             string            `json:"issuerDid,omitempty"`
	AttributeValues       map[string]string `json:"attributeValues,omitempty"`
}

type AnonCredsCredentialInfo struct {
	CredentialId           string                 `json:"credentialId"`
	Attributes             map[string]string      `json:"attributes"`
	SchemaId               string                 `json:"schemaId"`
	CredentialDefinitionId string                 `json:"credentialDefinitionId"`
	RevocationRegistryId   string                 `json:"revocationRegistryId,omitempty"`
	CredentialRevocationId string                 `json:"credentialRevocationId,omitempty"`
	MethodName             string                 `json:"methodName"`
	Metadata               map[string]interface{} `json:"metadata,omitempty"`
}

type CreateProofOptions struct {
	ProofRequest            map[string]interface{}            `json:"proofRequest"`
	SelectedCredentials     map[string]interface{}            `json:"selectedCredentials"`
	Schemas                 map[string]map[string]interface{} `json:"schemas"`
	CredentialDefinitions   map[string]map[string]interface{} `json:"credentialDefinitions"`
	LinkSecretId            string                            `json:"linkSecretId"`
	RevocationStates        map[string]interface{}            `json:"revocationStates,omitempty"`
}

type AnonCredsProof struct {
	Proof          map[string]interface{} `json:"proof"`
	RequestedProof map[string]interface{} `json:"requestedProof"`
	Identifiers    []interface{}          `json:"identifiers"`
}

type GetCredentialsForProofRequestOptions struct {
	ProofRequest     map[string]interface{} `json:"proofRequest"`
	AttributeFilter  map[string]interface{} `json:"attributeFilter,omitempty"`
}

type GetCredentialsForProofRequestReturn struct {
	Attributes  map[string][]*AnonCredsRequestedAttributeMatch  `json:"attributes"`
	Predicates  map[string][]*AnonCredsRequestedPredicateMatch  `json:"predicates"`
}

type AnonCredsRequestedAttributeMatch struct {
	CredentialId   string              `json:"credentialId"`
	RevealedValues map[string]string   `json:"revealedValues"`
	CredentialInfo *AnonCredsCredentialInfo `json:"credentialInfo"`
}

type AnonCredsRequestedPredicateMatch struct {
	CredentialId   string              `json:"credentialId"`
	PredicateValue int                 `json:"predicateValue"`
	CredentialInfo *AnonCredsCredentialInfo `json:"credentialInfo"`
}

// Issuer option structures
type CreateSchemaOptions struct {
	IssuerId          string   `json:"issuerId"`
	Name              string   `json:"name"`
	Version           string   `json:"version"`
	AttributeNames    []string `json:"attributeNames"`
}

type AnonCredsSchema struct {
	IssuerId       string   `json:"issuerId"`
	Name           string   `json:"name"`
	Version        string   `json:"version"`
	AttributeNames []string `json:"attrNames"`
}

type CreateCredentialDefinitionOptions struct {
	Schema                        *AnonCredsSchema `json:"schema"`
	SchemaId                      string          `json:"schemaId"`
	IssuerId                      string          `json:"issuerId"`
	Tag                           string          `json:"tag"`
	SupportRevocation             bool            `json:"supportRevocation"`
}

type CreateCredentialDefinitionReturn struct {
	CredentialDefinition        map[string]interface{} `json:"credentialDefinition"`
	CredentialDefinitionPrivate map[string]interface{} `json:"credentialDefinitionPrivate"`
	KeyCorrectnessProof         map[string]interface{} `json:"keyCorrectnessProof"`
}

type CreateCredentialOfferOptions struct {
	CredentialDefinitionId string `json:"credentialDefinitionId"`
}

type AnonCredsCredentialOffer struct {
	SchemaId               string                 `json:"schema_id"`
	CredentialDefinitionId string                 `json:"cred_def_id"`
	KeyCorrectnessProof    map[string]interface{} `json:"key_correctness_proof"`
	Nonce                  string                 `json:"nonce"`
	MethodName             string                 `json:"method_name,omitempty"`
}

type CreateCredentialOptions struct {
	CredentialOffer             map[string]interface{}       `json:"credentialOffer"`
	CredentialRequest           map[string]interface{}       `json:"credentialRequest"`
	CredentialValues            map[string]map[string]string `json:"credentialValues"`
	RevocationRegistryId        string                       `json:"revocationRegistryId,omitempty"`
	RevocationStatusList        map[string]interface{}       `json:"revocationStatusList,omitempty"`
	RevocationConfiguration     map[string]interface{}       `json:"revocationConfiguration,omitempty"`
}

type CreateCredentialReturn struct {
	Credential                     map[string]interface{} `json:"credential"`
	CredentialRevocationId         string                `json:"credentialRevocationId,omitempty"`
	RevocationRegistryDefinition   map[string]interface{} `json:"revocationRegistryDefinition,omitempty"`
}

type CreateRevocationRegistryDefinitionOptions struct {
	CredentialDefinitionId string `json:"credentialDefinitionId"`
	IssuerId               string `json:"issuerId"`
	Tag                    string `json:"tag"`
	MaximumCredentialNumber int    `json:"maximumCredentialNumber"`
	TailsDirectoryPath     string `json:"tailsDirectoryPath,omitempty"`
}

type CreateRevocationRegistryDefinitionReturn struct {
	RevocationRegistryDefinition        map[string]interface{} `json:"revocationRegistryDefinition"`
	RevocationRegistryDefinitionPrivate map[string]interface{} `json:"revocationRegistryDefinitionPrivate"`
}

type UpdateRevocationStatusListOptions struct {
	RevocationRegistryDefinition map[string]interface{} `json:"revocationRegistryDefinition"`
	RevocationStatusList         map[string]interface{} `json:"revocationStatusList"`
	RevokedCredentialIds         []string              `json:"revokedCredentialIds"`
	IssuedCredentialIds          []string              `json:"issuedCredentialIds"`
	Timestamp                    int64                 `json:"timestamp,omitempty"`
}

type RevocationStatusList struct {
	IssuerId                     string                 `json:"issuerId"`
	RevocationRegistryDefinitionId string                 `json:"revRegDefId"`
	RevocationList               []int                  `json:"revocationList"`
	CurrentAccumulator           string                 `json:"currentAccumulator"`
	Timestamp                    int64                  `json:"timestamp"`
}

// Verifier option structures
type VerifyProofOptions struct {
	ProofRequest          map[string]interface{}            `json:"proofRequest"`
	Proof                 map[string]interface{}            `json:"proof"`
	Schemas               map[string]map[string]interface{} `json:"schemas"`
	CredentialDefinitions map[string]map[string]interface{} `json:"credentialDefinitions"`
	RevocationRegistries  map[string]interface{}            `json:"revocationRegistries,omitempty"`
	RevocationStates      map[string]interface{}            `json:"revocationStates,omitempty"`
}

type VerifyProofReturn struct {
	Verified bool `json:"verified"`
}