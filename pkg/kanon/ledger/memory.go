package ledger

import (
	"encoding/json"
	"fmt"
	"sync"
)

// MemoryLedger is a simple in-memory implementation of KanonLedger for testing.
type MemoryLedger struct {
	mu          sync.RWMutex
	schemaJson  map[string]string
	credDefJson map[string]string // stores the raw JSON payload (3rd return item of contract)
	didJson     map[string]string // did -> didDoc JSON
	didMeta     map[string]string // did -> metadata JSON
	// anoncreds resources
	schema map[string]struct {
		details string
		issuer  string
		issuers []string
	}
	credDefs map[string]struct {
		schemaId string
		issuer   string
		details  string
	}
	revRegs     map[string]string
	statusLists map[string]struct {
		purpose   string
		encoded   string
		issuer    string
		length    int
		timestamp int64
	}
}

func NewMemoryLedger() *MemoryLedger {
	return &MemoryLedger{
		schemaJson:  make(map[string]string),
		credDefJson: make(map[string]string),
		didJson:     make(map[string]string),
		didMeta:     make(map[string]string),
		schema: make(map[string]struct {
			details string
			issuer  string
			issuers []string
		}),
		credDefs: make(map[string]struct {
			schemaId string
			issuer   string
			details  string
		}),
		revRegs: make(map[string]string),
		statusLists: make(map[string]struct {
			purpose   string
			encoded   string
			issuer    string
			length    int
			timestamp int64
		}),
	}
}

// SeedSchema helps tests/dev pre-populate a schema payload
func (m *MemoryLedger) SeedSchema(id string, payload SchemaPayload) {
	b, _ := json.Marshal(payload)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.schemaJson[id] = string(b)
}

// SeedCredentialDefinition helps tests/dev pre-populate a cred def payload
func (m *MemoryLedger) SeedCredentialDefinition(id string, payload CredentialDefinitionPayload) {
	b, _ := json.Marshal(payload)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.credDefJson[id] = string(b)
}

func (m *MemoryLedger) GetSchema(schemaId string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.schemaJson[schemaId]
	if !ok {
		return "", fmt.Errorf("kanon schema not found: %s", schemaId)
	}
	return s, nil
}

func (m *MemoryLedger) GetCredentialDefinition(credDefId string) (string, string, string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, ok := m.credDefJson[credDefId]
	if !ok {
		return "", "", "", fmt.Errorf("kanon cred def not found: %s", credDefId)
	}
	// Emulate contract returns: (idOnChain, version, json)
	return credDefId, "v1", p, nil
}

func (m *MemoryLedger) GetDID(did string) (string, string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	doc, ok := m.didJson[did]
	if !ok {
		return "", "", fmt.Errorf("did not found: %s", did)
	}
	meta := m.didMeta[did]
	return doc, meta, nil
}

func (m *MemoryLedger) RegisterDID(did string, didDocJson string, metadata string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.didJson[did] = didDocJson
	m.didMeta[did] = metadata
	return nil
}

func (m *MemoryLedger) UpdateDID(did string, didDocJson string, metadata string) error {
	return m.RegisterDID(did, didDocJson, metadata)
}

func (m *MemoryLedger) RegisterSchema(schemaId string, detailsJson string, issuerId string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.schema[schemaId] = struct {
		details string
		issuer  string
		issuers []string
	}{details: detailsJson, issuer: issuerId, issuers: []string{}}
	return nil
}

func (m *MemoryLedger) AddApprovedIssuer(schemaId string, issuerAddress string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.schema[schemaId]
	s.issuers = append(s.issuers, issuerAddress)
	m.schema[schemaId] = s
	return nil
}

func (m *MemoryLedger) RegisterCredentialDefinition(credDefId string, schemaId string, issuer string, detailsJson string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.credDefs[credDefId] = struct {
		schemaId string
		issuer   string
		details  string
	}{schemaId: schemaId, issuer: issuer, details: detailsJson}
	m.credDefJson[credDefId] = detailsJson
	return nil
}

func (m *MemoryLedger) RegisterRevocationRegistry(revRegDefId string, definitionJson string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.revRegs[revRegDefId] = definitionJson
	return nil
}

func (m *MemoryLedger) GetRevocationRegistry(revRegDefId string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	v, ok := m.revRegs[revRegDefId]
	if !ok {
		return "", fmt.Errorf("revocation registry not found: %s", revRegDefId)
	}
	return v, nil
}

func (m *MemoryLedger) StoreStatusList(statusListId string, statusPurpose string, encodedList string, issuerId string, length int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.statusLists[statusListId] = struct {
		purpose   string
		encoded   string
		issuer    string
		length    int
		timestamp int64
	}{purpose: statusPurpose, encoded: encodedList, issuer: issuerId, length: length, timestamp: 0}
	return nil
}

func (m *MemoryLedger) GetStatusList(statusListId string) (string, string, string, int, int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.statusLists[statusListId]
	if !ok {
		return "", "", "", 0, 0, fmt.Errorf("status list not found: %s", statusListId)
	}
	return s.purpose, s.encoded, s.issuer, s.length, s.timestamp, nil
}

func (m *MemoryLedger) UpdateStatusList(statusListId string, encodedList string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.statusLists[statusListId]
	s.encoded = encodedList
	s.timestamp = s.timestamp + 1
	m.statusLists[statusListId] = s
	return nil
}
