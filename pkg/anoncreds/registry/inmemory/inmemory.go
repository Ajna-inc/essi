package inmemory

import (
	"fmt"
	"regexp"
	"sync"

	"github.com/ajna-inc/essi/pkg/anoncreds/registry"
)

// MemoryRegistry is a simple in-memory implementation of the anoncreds Registry interface
// intended for development and testing.
type MemoryRegistry struct {
	mu             sync.RWMutex
	schemaById     map[string]registry.Schema
	credDefById    map[string]registry.CredentialDefinition
	revRegById     map[string]registry.RevocationRegistryDefinition
	statusListById map[string]registry.RevocationStatusList
	rx             *regexp.Regexp
}

// NewMemoryRegistry creates a new in-memory registry. Identifiers matching the provided
// regex will be handled by this registry. If rx is nil, it defaults to ^did:mem:.
func NewMemoryRegistry(rx *regexp.Regexp) *MemoryRegistry {
	if rx == nil {
		rx = regexp.MustCompile(`^did:mem:`)
	}
	return &MemoryRegistry{
		schemaById:     make(map[string]registry.Schema),
		credDefById:    make(map[string]registry.CredentialDefinition),
		revRegById:     make(map[string]registry.RevocationRegistryDefinition),
		statusListById: make(map[string]registry.RevocationStatusList),
		rx:             rx,
	}
}

func (m *MemoryRegistry) MethodName() string                  { return "memory" }
func (m *MemoryRegistry) SupportedIdentifier() *regexp.Regexp { return m.rx }

// Testing helpers to pre-seed data
func (m *MemoryRegistry) PutSchema(id string, s registry.Schema) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.schemaById[id] = s
}
func (m *MemoryRegistry) PutCredentialDefinition(id string, cd registry.CredentialDefinition) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.credDefById[id] = cd
}
func (m *MemoryRegistry) PutRevocationRegistryDefinition(id string, rr registry.RevocationRegistryDefinition) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.revRegById[id] = rr
}
func (m *MemoryRegistry) PutStatusList(id string, sl registry.RevocationStatusList) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.statusListById[id] = sl
}

func (m *MemoryRegistry) GetSchema(schemaId string) (registry.Schema, string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.schemaById[schemaId]
	if !ok {
		return registry.Schema{}, "", fmt.Errorf("schema not found: %s", schemaId)
	}
	return s, schemaId, nil
}

func (m *MemoryRegistry) GetCredentialDefinition(credDefId string) (registry.CredentialDefinition, string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	cd, ok := m.credDefById[credDefId]
	if !ok {
		return registry.CredentialDefinition{}, "", fmt.Errorf("credential definition not found: %s", credDefId)
	}
	return cd, credDefId, nil
}

func (m *MemoryRegistry) GetRevocationRegistryDefinition(revRegDefId string) (registry.RevocationRegistryDefinition, string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rr, ok := m.revRegById[revRegDefId]
	if !ok {
		return registry.RevocationRegistryDefinition{}, "", fmt.Errorf("revocation registry definition not found: %s", revRegDefId)
	}
	return rr, revRegDefId, nil
}

func (m *MemoryRegistry) GetRevocationStatusList(revRegDefId string, timestamp int64) (registry.RevocationStatusList, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	sl, ok := m.statusListById[revRegDefId]
	if !ok {
		return registry.RevocationStatusList{}, fmt.Errorf("revocation status list not found: %s", revRegDefId)
	}
	return sl, nil
}

func (m *MemoryRegistry) RegisterSchema(opts registry.RegisterSchemaOptions) (registry.RegisterSchemaResult, error) {
	id := opts.Schema.IssuerId + "/schema/1"
	m.PutSchema(id, opts.Schema)
	return registry.RegisterSchemaResult{State: "finished", Schema: opts.Schema, SchemaId: id}, nil
}

func (m *MemoryRegistry) RegisterCredentialDefinition(opts registry.RegisterCredentialDefinitionOptions) (registry.RegisterCredentialDefinitionResult, error) {
	id := opts.CredentialDefinition.IssuerId + "/creddef/1"
	m.PutCredentialDefinition(id, opts.CredentialDefinition)
	return registry.RegisterCredentialDefinitionResult{State: "finished", CredentialDefinition: opts.CredentialDefinition, CredentialDefinitionId: id}, nil
}

func (m *MemoryRegistry) RegisterRevocationRegistryDefinition(opts registry.RegisterRevocationRegistryDefinitionOptions) (registry.RegisterRevocationRegistryDefinitionResult, error) {
	id := opts.RevocationRegistryDefinition.CredDefId + "/revreg/1"
	// store a minimal placeholder
	m.PutRevocationRegistryDefinition(id, registry.RevocationRegistryDefinition{})
	return registry.RegisterRevocationRegistryDefinitionResult{State: "finished", RevocationRegistryDefinition: opts.RevocationRegistryDefinition, RevocationRegistryDefinitionId: id}, nil
}

func (m *MemoryRegistry) RegisterRevocationStatusList(opts registry.RegisterRevocationStatusListOptions) (registry.RegisterRevocationStatusListResult, error) {
	id := opts.RevocationStatusList.RevRegDefId
	// store a minimal placeholder
	m.PutStatusList(id, registry.RevocationStatusList{})
	return registry.RegisterRevocationStatusListResult{State: "finished", RevocationStatusList: opts.RevocationStatusList}, nil
}
