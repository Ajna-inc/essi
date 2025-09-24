package kanon

import (
	"encoding/json"
	"regexp"
	"testing"

	"github.com/ajna-inc/essi/pkg/kanon/ledger"
)

func TestKanonRegistry_Reads(t *testing.T) {
	mem := ledger.NewMemoryLedger()
	// Seed schema
	mem.SeedSchema("did:kanon:testnet:issuer/resources/schema1", ledger.SchemaPayload{Data: struct {
		Name      string   `json:"name"`
		Version   string   `json:"version"`
		AttrNames []string `json:"attrNames"`
		IssuerId  string   `json:"issuerId"`
	}{Name: "Employee", Version: "1.0", AttrNames: []string{"name", "age"}, IssuerId: "did:kanon:testnet:issuer"}})

	// Seed credential definition with nested value.primary.value shape
	payload := ledger.CredentialDefinitionPayload{}
	payload.Data.IssuerId = "did:kanon:testnet:issuer"
	payload.Data.SchemaId = "did:kanon:testnet:issuer/resources/schema1"
	payload.Data.Tag = "default"
	payload.Data.Value = map[string]interface{}{
		"primary": map[string]interface{}{
			"value": map[string]interface{}{"n": "1"},
		},
	}
	mem.SeedCredentialDefinition("did:kanon:testnet:issuer/resources/creddef1", payload)

	r := New(regexp.MustCompile(`^did:kanon:`), mem)

	s, id, err := r.GetSchema("did:kanon:testnet:issuer/resources/schema1")
	if err != nil || id == "" || s.Name != "Employee" || s.Version != "1.0" {
		t.Fatalf("schema read unexpected: %+v id=%s err=%v", s, id, err)
	}

	cd, id2, err := r.GetCredentialDefinition("did:kanon:testnet:issuer/resources/creddef1")
	if err != nil || id2 == "" || cd.Type != "CL" || cd.Tag != "default" {
		b, _ := json.Marshal(cd.Value)
		t.Fatalf("cred def read unexpected: tag=%s type=%s value=%s err=%v", cd.Tag, cd.Type, string(b), err)
	}
}
