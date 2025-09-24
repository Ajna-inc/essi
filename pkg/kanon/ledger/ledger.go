package ledger

// KanonLedger defines the minimal read operations required by the Kanon
// anoncreds registry implementation. A real implementation would call
// an EVM contract via JSON-RPC. We provide a memory-backed implementation
// to enable tests and local development without a chain.

// CredentialDefinitionPayload mirrors the JSON stored on-chain by the TS plugin.
// Typically it's a JSON with a root { data: { issuerId, schemaId, tag, value: { primary: { value: {...} } } } }
type CredentialDefinitionPayload struct {
	Data struct {
		IssuerId string                 `json:"issuerId"`
		SchemaId string                 `json:"schemaId"`
		Tag      string                 `json:"tag"`
		Value    map[string]interface{} `json:"value"`
	} `json:"data"`
}

// SchemaPayload mirrors the JSON stored on-chain for schemas: { data: { name, version, attrNames, issuerId } }
type SchemaPayload struct {
	Data struct {
		Name      string   `json:"name"`
		Version   string   `json:"version"`
		AttrNames []string `json:"attrNames"`
		IssuerId  string   `json:"issuerId"`
	} `json:"data"`
}

type KanonLedger interface {
	// GetSchema returns a JSON string payload compatible with SchemaPayload
	GetSchema(schemaId string) (string, error)
	// GetCredentialDefinition returns (idOnChain, version, payloadJson)
	GetCredentialDefinition(credDefId string) (string, string, string, error)

	// DID operations
	// GetDID returns (didDocJson, metadataJson)
	GetDID(did string) (string, string, error)
	// RegisterDID writes a DID and associated context/metadata
	RegisterDID(did string, didDocJson string, metadata string) error
	// UpdateDID updates an existing DID
	UpdateDID(did string, didDocJson string, metadata string) error

	// AnonCreds-related resources (write + read)
	RegisterSchema(schemaId string, detailsJson string, issuerId string) error
	AddApprovedIssuer(schemaId string, issuerAddress string) error

	RegisterCredentialDefinition(credDefId string, schemaId string, issuer string, detailsJson string) error

	RegisterRevocationRegistry(revRegDefId string, definitionJson string) error
	GetRevocationRegistry(revRegDefId string) (string, error)

	StoreStatusList(statusListId string, statusPurpose string, encodedList string, issuerId string, length int) error
	GetStatusList(statusListId string) (statusPurpose string, encodedList string, issuerId string, length int, timestamp int64, err error)
	UpdateStatusList(statusListId string, encodedList string) error
}
