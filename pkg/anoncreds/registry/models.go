package registry

// Basic models required by registry service; keep minimal for compile and tests

type Schema struct {
	Id        string   `json:"id,omitempty"`
	Name      string   `json:"name,omitempty"`
	Version   string   `json:"version,omitempty"`
	AttrNames []string `json:"attrNames,omitempty"`
	IssuerId  string   `json:"issuerId,omitempty"`
}

type CredentialDefinition struct {
	Id         string                 `json:"id,omitempty"`
	Tag        string                 `json:"tag,omitempty"`
	SchemaId   string                 `json:"schemaId,omitempty"`
	IssuerId   string                 `json:"issuerId,omitempty"`
	Value      map[string]interface{} `json:"value,omitempty"`
	Revocation *struct{}              `json:"revocation,omitempty"`
}

// Minimal placeholders for registry interface usage
type RevocationRegistryDefinition struct{}
type RevocationStatusList struct{}

type RegisterSchemaOptions struct{ Schema Schema }
type RegisterSchemaResult struct {
	State    string
	Schema   Schema
	Reason   string
	SchemaId string
}
type RegisterCredentialDefinitionOptions struct{ CredentialDefinition CredentialDefinition }
type RegisterCredentialDefinitionResult struct {
	State                  string
	CredentialDefinition   CredentialDefinition
	Reason                 string
	CredentialDefinitionId string
}
type RegisterRevocationRegistryDefinitionOptions struct{ RevocationRegistryDefinition struct{ CredDefId string } }
type RegisterRevocationRegistryDefinitionResult struct {
	State                          string
	RevocationRegistryDefinition   interface{}
	Reason                         string
	RevocationRegistryDefinitionId string
}
type RegisterRevocationStatusListOptions struct{ RevocationStatusList struct{ RevRegDefId string } }
type RegisterRevocationStatusListResult struct {
	State                string
	RevocationStatusList interface{}
	Reason               string
}
