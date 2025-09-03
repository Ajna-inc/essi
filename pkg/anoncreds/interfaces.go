package anoncreds

// Holder defines the AnonCreds holder-side operations we need
type Holder interface {
	EnsureLinkSecret() (string, error)
	// CreateCredentialRequest returns request payload and opaque request metadata
	CreateCredentialRequest(offer map[string]interface{}) (map[string]interface{}, map[string]interface{}, error)
	// ProcessIssuedCredential verifies and stores credential using request metadata
	ProcessIssuedCredential(credential map[string]interface{}, requestMetadata map[string]interface{}) error
}

// Resolver provides methods to resolve anoncreds artifacts
// Implementations may fetch from Indy VDR, cheqd, or local registry
// The return values should be JSON-compatible maps matching indy-credx types
// e.g. CredentialDefinition, Schema
// Optional for now; used to enrich offers/credentials when data is not embedded
//
// TODO: integrate concrete resolvers in agent context when available
// kept minimal to not block current flow
type Resolver interface {
	ResolveCredentialDefinition(credDefId string) (map[string]interface{}, error)
	ResolveSchema(schemaId string) (map[string]interface{}, error)
}

// Issuer defines the AnonCreds issuer-side operations we need
// These map to anoncreds-rs functions used by Credo-TS during issuance
type Issuer interface {
	// CreateCredentialOffer builds an anoncreds credential offer for a given credential definition id
	CreateCredentialOffer(credentialDefinitionId string) (map[string]interface{}, error)
	// CreateCredential issues a credential given offer, request and attribute values
	// values should be of shape: map[attrName]map[string]string{"raw":"..","encoded":".."}
	CreateCredential(offer map[string]interface{}, request map[string]interface{}, values map[string]map[string]string) (credential map[string]interface{}, credentialRevocationId string, err error)
}
