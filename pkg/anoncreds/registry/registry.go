package registry

import "regexp"

// Registry defines the pluggable interface that an AnonCreds backend must implement.
// Implementations can back this interface with EVM (Kanon), Indy, or in-memory stores.
type Registry interface {
	// MethodName returns a human-readable method name (e.g., "kanon", "indy", "memory").
	MethodName() string
	// SupportedIdentifier returns a regex that indicates which identifiers this registry supports.
	SupportedIdentifier() *regexp.Regexp

	// Reads
	GetSchema(schemaId string) (Schema, string, error) // returns schema, resolved id
	GetCredentialDefinition(credDefId string) (CredentialDefinition, string, error)
	GetRevocationRegistryDefinition(revRegDefId string) (RevocationRegistryDefinition, string, error)
	GetRevocationStatusList(revRegDefId string, timestamp int64) (RevocationStatusList, error)

	// Writes (optional for holder flows)
	RegisterSchema(opts RegisterSchemaOptions) (RegisterSchemaResult, error)
	RegisterCredentialDefinition(opts RegisterCredentialDefinitionOptions) (RegisterCredentialDefinitionResult, error)
	RegisterRevocationRegistryDefinition(opts RegisterRevocationRegistryDefinitionOptions) (RegisterRevocationRegistryDefinitionResult, error)
	RegisterRevocationStatusList(opts RegisterRevocationStatusListOptions) (RegisterRevocationStatusListResult, error)
}
