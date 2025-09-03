package registry

import (
	"fmt"
	"log"
)

// Service routes registry calls to the first registered Registry whose
// SupportedIdentifier matches the provided identifier.
type Service struct {
	registries []Registry
}

// RegistryService is an alias for *Service for compatibility
type RegistryService = *Service

// NewService creates a new registry router.
func NewService() *Service {
	return &Service{registries: make([]Registry, 0, 4)}
}

// Register adds a registry implementation to the router.
func (s *Service) Register(r Registry) {
	s.registries = append(s.registries, r)
	log.Printf("📝 [RegistryService] Registered registry %s, total count: %d", r.MethodName(), len(s.registries))
}

// GetRegistries returns the list of registered registries (for debugging)
func (s *Service) GetRegistries() []Registry {
	return s.registries
}

// find returns the first registry that supports the given identifier.
func (s *Service) find(identifier string) (Registry, error) {
	log.Printf("🔍 [RegistryService] Finding registry for identifier: %s", identifier)
	log.Printf("🔍 [RegistryService] Number of registries: %d", len(s.registries))
	
	for _, r := range s.registries {
		if rx := r.SupportedIdentifier(); rx != nil {
			log.Printf("🔍 [RegistryService] Checking pattern %s against %s", rx.String(), identifier)
			if rx.MatchString(identifier) {
				log.Printf("✅ [RegistryService] Found matching registry for %s", identifier)
				return r, nil
			}
		}
	}
	// Log available registries for debugging
	var patterns []string
	for _, r := range s.registries {
		if rx := r.SupportedIdentifier(); rx != nil {
			patterns = append(patterns, rx.String())
		}
	}
	return nil, fmt.Errorf("no anoncreds registry found for identifier: %s (available patterns: %v, registry count: %d)", identifier, patterns, len(s.registries))
}

func (s *Service) GetSchema(schemaId string) (Schema, string, error) {
	r, err := s.find(schemaId)
	if err != nil {
		return Schema{}, "", err
	}
	return r.GetSchema(schemaId)
}

func (s *Service) GetCredentialDefinition(credDefId string) (CredentialDefinition, string, error) {
	r, err := s.find(credDefId)
	if err != nil {
		return CredentialDefinition{}, "", err
	}
	return r.GetCredentialDefinition(credDefId)
}

func (s *Service) GetRevocationRegistryDefinition(revRegDefId string) (RevocationRegistryDefinition, string, error) {
	r, err := s.find(revRegDefId)
	if err != nil {
		return RevocationRegistryDefinition{}, "", err
	}
	return r.GetRevocationRegistryDefinition(revRegDefId)
}

func (s *Service) GetRevocationStatusList(revRegDefId string, timestamp int64) (RevocationStatusList, error) {
	r, err := s.find(revRegDefId)
	if err != nil {
		return RevocationStatusList{}, err
	}
	return r.GetRevocationStatusList(revRegDefId, timestamp)
}

func (s *Service) RegisterSchema(opts RegisterSchemaOptions) (RegisterSchemaResult, error) {
	// Choose registry by issuer identifier embedded in schema id when possible.
	// For now, route by Schema.IssuerId
	r, err := s.find(opts.Schema.IssuerId)
	if err != nil {
		return RegisterSchemaResult{State: "failed", Schema: opts.Schema, Reason: err.Error()}, nil
	}
	return r.RegisterSchema(opts)
}

func (s *Service) RegisterCredentialDefinition(opts RegisterCredentialDefinitionOptions) (RegisterCredentialDefinitionResult, error) {
	r, err := s.find(opts.CredentialDefinition.IssuerId)
	if err != nil {
		return RegisterCredentialDefinitionResult{State: "failed", CredentialDefinition: opts.CredentialDefinition, Reason: err.Error()}, nil
	}
	return r.RegisterCredentialDefinition(opts)
}

func (s *Service) RegisterRevocationRegistryDefinition(opts RegisterRevocationRegistryDefinitionOptions) (RegisterRevocationRegistryDefinitionResult, error) {
	// Route by cred def id embedded in revocation registry
	r, err := s.find(opts.RevocationRegistryDefinition.CredDefId)
	if err != nil {
		return RegisterRevocationRegistryDefinitionResult{State: "failed", RevocationRegistryDefinition: opts.RevocationRegistryDefinition, Reason: err.Error()}, nil
	}
	return r.RegisterRevocationRegistryDefinition(opts)
}

func (s *Service) RegisterRevocationStatusList(opts RegisterRevocationStatusListOptions) (RegisterRevocationStatusListResult, error) {
	r, err := s.find(opts.RevocationStatusList.RevRegDefId)
	if err != nil {
		return RegisterRevocationStatusListResult{State: "failed", RevocationStatusList: opts.RevocationStatusList, Reason: err.Error()}, nil
	}
	return r.RegisterRevocationStatusList(opts)
}
