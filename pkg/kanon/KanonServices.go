//go:build ignore
// +build ignore

package kanon

import (
	"fmt"
	
	"github.com/Ajna-inc/anoncreds-go/pkg/anoncreds"
	dids "github.com/ajna-inc/essi/pkg/core/modules/dids"
	"github.com/ajna-inc/essi/pkg/kanon/ledger"
)

// KanonSchemaService handles schema operations for Kanon
type KanonSchemaService struct {
	ledger ledger.KanonLedger
}

// NewKanonSchemaService creates a new Kanon schema service
func NewKanonSchemaService(ledger ledger.KanonLedger) *KanonSchemaService {
	return &KanonSchemaService{
		ledger: ledger,
	}
}

// RegisterSchema registers a schema
func (s *KanonSchemaService) RegisterSchema(schema *anoncreds.Schema) (string, error) {
	schemaId := s.generateSchemaId(schema)
	if err := s.ledger.RegisterSchema(schemaId, schema); err != nil {
		return "", err
	}
	return schemaId, nil
}

// GetSchema retrieves a schema
func (s *KanonSchemaService) GetSchema(schemaId string) (*anoncreds.Schema, error) {
	return s.ledger.GetSchema(schemaId)
}

func (s *KanonSchemaService) generateSchemaId(schema *anoncreds.Schema) string {
	return fmt.Sprintf("schema:kanon:%s:%s:%s",
		schema.IssuerId,
		schema.Name,
		schema.Version)
}

// KanonCredDefService handles credential definition operations for Kanon
type KanonCredDefService struct {
	ledger ledger.KanonLedger
}

// NewKanonCredDefService creates a new Kanon credential definition service
func NewKanonCredDefService(ledger ledger.KanonLedger) *KanonCredDefService {
	return &KanonCredDefService{
		ledger: ledger,
	}
}

// RegisterCredentialDefinition registers a credential definition
func (s *KanonCredDefService) RegisterCredentialDefinition(
	credDef *anoncreds.CredentialDefinition,
) (string, error) {
	credDefId := s.generateCredDefId(credDef)
	if err := s.ledger.RegisterCredentialDefinition(credDefId, credDef); err != nil {
		return "", err
	}
	return credDefId, nil
}

// GetCredentialDefinition retrieves a credential definition
func (s *KanonCredDefService) GetCredentialDefinition(credDefId string) (*anoncreds.CredentialDefinition, error) {
	return s.ledger.GetCredentialDefinition(credDefId)
}

func (s *KanonCredDefService) generateCredDefId(credDef *anoncreds.CredentialDefinition) string {
	return fmt.Sprintf("creddef:kanon:%s:%s:%s",
		credDef.IssuerId,
		credDef.SchemaId,
		credDef.Tag)
}

// KanonRevocationService handles revocation operations for Kanon
type KanonRevocationService struct {
	ledger ledger.KanonLedger
}

// NewKanonRevocationService creates a new Kanon revocation service
func NewKanonRevocationService(ledger ledger.KanonLedger) *KanonRevocationService {
	return &KanonRevocationService{
		ledger: ledger,
	}
}

// RegisterRevocationRegistryDefinition registers a revocation registry definition
func (s *KanonRevocationService) RegisterRevocationRegistryDefinition(
	revRegDef *anoncreds.RevocationRegistryDefinition,
) (string, error) {
	revRegId := s.generateRevRegId(revRegDef)
	if err := s.ledger.RegisterRevocationRegistryDefinition(revRegId, revRegDef); err != nil {
		return "", err
	}
	return revRegId, nil
}

// GetRevocationRegistryDefinition retrieves a revocation registry definition
func (s *KanonRevocationService) GetRevocationRegistryDefinition(
	revRegId string,
) (*anoncreds.RevocationRegistryDefinition, error) {
	return s.ledger.GetRevocationRegistryDefinition(revRegId)
}

// RegisterRevocationStatusList registers a revocation status list
func (s *KanonRevocationService) RegisterRevocationStatusList(
	revRegId string,
	statusList *anoncreds.RevocationStatusList,
	timestamp uint64,
) error {
	return s.ledger.RegisterRevocationStatusList(revRegId, statusList, timestamp)
}

// GetRevocationStatusList retrieves a revocation status list
func (s *KanonRevocationService) GetRevocationStatusList(
	revRegId string,
	timestamp uint64,
) (*anoncreds.RevocationStatusList, error) {
	return s.ledger.GetRevocationStatusList(revRegId, timestamp)
}

func (s *KanonRevocationService) generateRevRegId(revRegDef *anoncreds.RevocationRegistryDefinition) string {
	return fmt.Sprintf("revreg:kanon:%s:%s:%s",
		revRegDef.IssuerId,
		revRegDef.CredDefId,
		revRegDef.Tag)
}

// KanonDidResolver resolves did:kanon DIDs
type KanonDidResolver struct {
	ledger ledger.KanonLedger
}

// NewKanonDidResolver creates a new Kanon DID resolver
func NewKanonDidResolver(ledger ledger.KanonLedger) *KanonDidResolver {
	return &KanonDidResolver{
		ledger: ledger,
	}
}

// SupportedMethods returns the DID methods this resolver supports
func (r *KanonDidResolver) SupportedMethods() []string {
	return []string{"kanon"}
}

// Resolve resolves a did:kanon DID
func (r *KanonDidResolver) Resolve(did string) (*dids.DidResolutionResult, error) {
	// Resolve from ledger
	didDocData, err := r.ledger.ResolveDid(did)
	if err != nil {
		return &dids.DidResolutionResult{
			DidResolutionMetadata: &dids.DidResolutionMetadata{
				Error: "notFound",
				Message: err.Error(),
			},
		}, nil
	}
	
	// Parse DID document
	var didDoc *dids.DidDoc
	if doc, ok := didDocData.(*dids.DidDoc); ok {
		didDoc = doc
	} else {
		// Try to construct from raw data
		didDoc = dids.NewDidDoc(did)
		// Parse the data and populate didDoc
	}
	
	return &dids.DidResolutionResult{
		DidDocument: didDoc,
		DidResolutionMetadata: &dids.DidResolutionMetadata{
			ContentType: "application/did+ld+json",
		},
		DidDocumentMetadata: &dids.DidDocumentMetadata{
			Created: "",
			Updated: "",
		},
	}, nil
}

// Register registers a new did:kanon DID
func (r *KanonDidResolver) Register(did string, didDocument *dids.DidDoc) error {
	return r.ledger.RegisterDid(did, didDocument)
}