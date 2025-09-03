package issuer

import (
	"fmt"

	issuercore "github.com/ajna-inc/essi/pkg/anoncreds/issuer"
	regsvc "github.com/ajna-inc/essi/pkg/anoncreds/registry"
	"github.com/ajna-inc/essi/pkg/anoncreds/services"
	"github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/core/di"
)

// AnonCredsRsIssuerService implements the AnonCredsIssuerService interface
type AnonCredsRsIssuerService struct {
	anoncredsLib interface{}
	dm           di.DependencyManager
}

// NewAnonCredsRsIssuerService creates a new issuer service
func NewAnonCredsRsIssuerService(anoncredsLib interface{}) *AnonCredsRsIssuerService {
	return &AnonCredsRsIssuerService{
		anoncredsLib: anoncredsLib,
	}
}

// SetTypedDI injects the dependency manager (called by module)
func (s *AnonCredsRsIssuerService) SetTypedDI(dm di.DependencyManager) { s.dm = dm }

func (s *AnonCredsRsIssuerService) CreateSchema(ctx *context.AgentContext, options *services.CreateSchemaOptions) (*services.AnonCredsSchema, error) {
	if options == nil {
		return nil, fmt.Errorf("missing options")
	}
	// For anoncreds-rs, schema objects are created when needed. Here we just echo the structure.
	schema := &services.AnonCredsSchema{
		IssuerId:       options.IssuerId,
		Name:           options.Name,
		Version:        options.Version,
		AttributeNames: options.AttributeNames,
	}
	return schema, nil
}

func (s *AnonCredsRsIssuerService) CreateCredentialDefinition(ctx *context.AgentContext, options *services.CreateCredentialDefinitionOptions) (*services.CreateCredentialDefinitionReturn, error) {
	if s.dm == nil {
		return nil, fmt.Errorf("typed dependency manager unavailable")
	}
	if options == nil {
		return nil, fmt.Errorf("missing options")
	}
	// Route through registry router so registry can persist and the core issuer can store secrets
	any, err := s.dm.Resolve(di.TokenRegistryService)
	if err != nil {
		return nil, err
	}
	router, ok := any.(*regsvc.Service)
	if !ok {
		return nil, fmt.Errorf("registry service not available")
	}
	res, err := router.RegisterCredentialDefinition(regsvc.RegisterCredentialDefinitionOptions{CredentialDefinition: regsvc.CredentialDefinition{
		SchemaId: options.SchemaId,
		IssuerId: options.IssuerId,
		Tag:      options.Tag,
	}})
	if err != nil {
		return nil, err
	}
	if res.State != "finished" {
		return nil, fmt.Errorf("register cred def failed: %s", res.Reason)
	}
	credDefMap := map[string]interface{}{
		"id":       res.CredentialDefinitionId,
		"schemaId": options.SchemaId,
		"issuerId": options.IssuerId,
		"tag":      options.Tag,
	}
	return &services.CreateCredentialDefinitionReturn{CredentialDefinition: credDefMap}, nil
}

func (s *AnonCredsRsIssuerService) CreateCredentialOffer(ctx *context.AgentContext, options *services.CreateCredentialOfferOptions) (*services.AnonCredsCredentialOffer, error) {
	if s.dm == nil {
		return nil, fmt.Errorf("typed dependency manager unavailable")
	}
	if options == nil || options.CredentialDefinitionId == "" {
		return nil, fmt.Errorf("missing credentialDefinitionId")
	}
	any, err := s.dm.Resolve(di.TokenAnonCredsCoreIssuer)
	if err != nil {
		return nil, err
	}
	core, ok := any.(*issuercore.AnoncredsIssuer)
	if !ok {
		return nil, fmt.Errorf("core issuer not available")
	}
	payload, err := core.CreateCredentialOffer(options.CredentialDefinitionId)
	if err != nil {
		return nil, err
	}
	offer := &services.AnonCredsCredentialOffer{}
	if v, ok := payload["schema_id"].(string); ok {
		offer.SchemaId = v
	}
	if v, ok := payload["cred_def_id"].(string); ok {
		offer.CredentialDefinitionId = v
	}
	if v, ok := payload["nonce"].(string); ok {
		offer.Nonce = v
	}
	if kcp, ok := payload["key_correctness_proof"].(map[string]interface{}); ok {
		offer.KeyCorrectnessProof = kcp
	}
	offer.MethodName = "anoncreds"
	return offer, nil
}

func (s *AnonCredsRsIssuerService) CreateCredential(ctx *context.AgentContext, options *services.CreateCredentialOptions) (*services.CreateCredentialReturn, error) {
	if s.dm == nil {
		return nil, fmt.Errorf("typed dependency manager unavailable")
	}
	if options == nil {
		return nil, fmt.Errorf("missing options")
	}
	any, err := s.dm.Resolve(di.TokenAnonCredsCoreIssuer)
	if err != nil {
		return nil, err
	}
	core, ok := any.(*issuercore.AnoncredsIssuer)
	if !ok {
		return nil, fmt.Errorf("core issuer not available")
	}
	cred, revId, err := core.CreateCredential(options.CredentialOffer, options.CredentialRequest, options.CredentialValues)
	if err != nil {
		return nil, err
	}
	return &services.CreateCredentialReturn{Credential: cred, CredentialRevocationId: revId}, nil
}

func (s *AnonCredsRsIssuerService) CreateRevocationRegistryDefinition(ctx *context.AgentContext, options *services.CreateRevocationRegistryDefinitionOptions) (*services.CreateRevocationRegistryDefinitionReturn, error) {
	if s.dm == nil {
		return nil, fmt.Errorf("typed dependency manager unavailable")
	}
	if options == nil {
		return nil, fmt.Errorf("missing options")
	}
	any, err := s.dm.Resolve(di.TokenRegistryService)
	if err != nil {
		return nil, err
	}
	router, ok := any.(*regsvc.Service)
	if !ok {
		return nil, fmt.Errorf("registry service not available")
	}
	opts := regsvc.RegisterRevocationRegistryDefinitionOptions{}
	opts.RevocationRegistryDefinition.CredDefId = options.CredentialDefinitionId
	res, err := router.RegisterRevocationRegistryDefinition(opts)
	if err != nil {
		return nil, err
	}
	if res.State != "finished" {
		return nil, fmt.Errorf("register revocation registry failed: %s", res.Reason)
	}
	return &services.CreateRevocationRegistryDefinitionReturn{RevocationRegistryDefinition: map[string]interface{}{"cred_def_id": options.CredentialDefinitionId}}, nil
}

func (s *AnonCredsRsIssuerService) UpdateRevocationStatusList(ctx *context.AgentContext, options *services.UpdateRevocationStatusListOptions) (*services.RevocationStatusList, error) {
	if s.dm == nil {
		return nil, fmt.Errorf("typed dependency manager unavailable")
	}
	if options == nil {
		return nil, fmt.Errorf("missing options")
	}
	any, err := s.dm.Resolve(di.TokenRegistryService)
	if err != nil {
		return nil, err
	}
	router, ok := any.(*regsvc.Service)
	if !ok {
		return nil, fmt.Errorf("registry service not available")
	}
	opts := regsvc.RegisterRevocationStatusListOptions{}
	if rrid, ok := options.RevocationRegistryDefinition["id"].(string); ok {
		opts.RevocationStatusList.RevRegDefId = rrid
	}
	res, err := router.RegisterRevocationStatusList(opts)
	if err != nil {
		return nil, err
	}
	if res.State != "finished" {
		return nil, fmt.Errorf("register revocation status list failed: %s", res.Reason)
	}
	return &services.RevocationStatusList{RevocationRegistryDefinitionId: opts.RevocationStatusList.RevRegDefId, RevocationList: []int{}, CurrentAccumulator: "", Timestamp: options.Timestamp}, nil
}
