package messages

import (
	"encoding/json"
	"testing"
)

func TestSerializeDidServiceAsString(t *testing.T) {
	inv := NewOutOfBandInvitationMessage("Alice")
	if err := inv.AddDidService("did:peer:2.Ez6LSm...test"); err != nil {
		t.Fatalf("failed to add did service: %v", err)
	}
	b, err := inv.ToJSON()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	svcs, ok := raw["services"].([]interface{})
	if !ok || len(svcs) != 1 {
		t.Fatalf("expected services array of length 1, got %#v", raw["services"])
	}
	if _, isObj := svcs[0].(map[string]interface{}); isObj {
		t.Fatalf("expected DID service to serialize as string, got object: %#v", svcs[0])
	}
	if _, isStr := svcs[0].(string); !isStr {
		t.Fatalf("expected DID service to be string, got %#v", svcs[0])
	}
}

func TestSerializeInlineServiceTypeDidCommunication(t *testing.T) {
	inv := NewOutOfBandInvitationMessage("Alice")
	err := inv.AddInlineService("#inline-0", "https://example.org/endpoint", []string{"did:key:z6MkhExample"})
	if err != nil {
		t.Fatalf("failed to add inline service: %v", err)
	}
	b, err := inv.ToJSON()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	svcs, ok := raw["services"].([]interface{})
	if !ok || len(svcs) != 1 {
		t.Fatalf("expected services array of length 1, got %#v", raw["services"])
	}
	svc, ok := svcs[0].(map[string]interface{})
	if !ok {
		t.Fatalf("expected inline service to be object, got %#v", svcs[0])
	}
	if svc["type"] != "did-communication" {
		t.Fatalf("expected service type did-communication, got %#v", svc["type"])
	}
}

func TestUnmarshalServicesStringAndObject(t *testing.T) {
	jsonStr := `{
		"@type":"https://didcomm.org/out-of-band/1.1/invitation",
		"@id":"123",
		"label":"Alice",
		"services":["did:peer:2.Ez6LSm...abc", {"id":"#inline-0","type":"did-communication","serviceEndpoint":"https://example.org","recipientKeys":["did:key:z6Mk..."],"routingKeys":[]}],
		"handshake_protocols":["https://didcomm.org/didexchange/1.1"]
	}`
	var inv OutOfBandInvitationMessage
	if err := json.Unmarshal([]byte(jsonStr), &inv); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(inv.Services) != 2 {
		t.Fatalf("expected 2 services, got %d", len(inv.Services))
	}
	if inv.Handshake == nil || len(inv.Handshake) != 1 || inv.Handshake[0].ProtocolId != "https://didcomm.org/didexchange/1.1" {
		t.Fatalf("unexpected handshake protocols: %#v", inv.Handshake)
	}
}

