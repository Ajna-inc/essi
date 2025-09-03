package dids

import "encoding/json"

// Aries DIDDoc defaults to https://w3id.org/did/v1 context and uses Aries 0160 fields.

// AuthenticationType constants for Aries DIDDocs
const (
	AuthenticationTypeEd25519Signature2018 = "Ed25519SignatureAuthentication2018"
)

// PublicKey represents a verification method in an Aries DIDDoc. This is an alias
// of VerificationMethod from the generic DID Document for convenience.
type PublicKey = VerificationMethod

// Authentication represents an authentication object in an Aries DIDDoc. The
// PublicKey field references a public key defined in the DIDDoc.
type Authentication struct {
	Type      string     `json:"type"`
	PublicKey *PublicKey `json:"publicKey"`
}

// MarshalJSON ensures the publicKey field is serialized as a reference to the
// public key id instead of embedding the full public key object.
func (a *Authentication) MarshalJSON() ([]byte, error) {
	type authAlias struct {
		Type      string `json:"type,omitempty"`
		PublicKey string `json:"publicKey,omitempty"`
	}

	var pk string
	if a.PublicKey != nil {
		pk = a.PublicKey.Id
	}

	return json.Marshal(authAlias{Type: a.Type, PublicKey: pk})
}

// UnmarshalJSON allows the authentication publicKey to be either a string reference
// (e.g., "did:peer:...#key-1") or an embedded public key object.
func (a *Authentication) UnmarshalJSON(data []byte) error {
	// Try to unmarshal into a flexible alias first
	type authAlias struct {
		Type      string          `json:"type"`
		PublicKey json.RawMessage `json:"publicKey"`
	}
	var alias authAlias
	if err := json.Unmarshal(data, &alias); err != nil {
		return err
	}
	a.Type = alias.Type

	// Handle publicKey being a string (reference) or an object
	var pkRef string
	if err := json.Unmarshal(alias.PublicKey, &pkRef); err == nil {
		// It's a string reference. Create a minimal PublicKey with only Id.
		a.PublicKey = &PublicKey{Id: pkRef}
		return nil
	}

	// Otherwise, parse as embedded PublicKey object
	var pkObj PublicKey
	if err := json.Unmarshal(alias.PublicKey, &pkObj); err != nil {
		return err
	}
	a.PublicKey = &pkObj
	return nil
}

// DidDoc represents a simplified Aries style DID Document
// following the conventions from Aries RFC 0160.
type DidDoc struct {
	Context        string            `json:"@context"`
	Id             string            `json:"id"`
	PublicKey      []*PublicKey      `json:"publicKey,omitempty"`
	Authentication []*Authentication `json:"authentication,omitempty"`
	Service        []*Service        `json:"service,omitempty"`
	// Additional fields from generic DID Document for compatibility
	KeyAgreement []VerificationMethodRef `json:"keyAgreement,omitempty"`
}

const (
	// AriesDidContext is the default context for Aries style DIDDocs
	AriesDidContext = "https://w3id.org/did/v1"
)

// NewDidDoc creates a new Aries style DIDDoc with the default context
func NewDidDoc(id string) *DidDoc {
	return &DidDoc{
		Context: AriesDidContext,
		Id:      id,
	}
}

// AddPublicKey appends a public key to the DIDDoc
func (d *DidDoc) AddPublicKey(pk *PublicKey) {
	if d.PublicKey == nil {
		d.PublicKey = []*PublicKey{}
	}
	d.PublicKey = append(d.PublicKey, pk)
}

// AddService appends a service to the DIDDoc
func (d *DidDoc) AddService(svc *Service) {
	if d.Service == nil {
		d.Service = []*Service{}
	}
	d.Service = append(d.Service, svc)
}

// AddAuthentication adds an authentication reference
func (d *DidDoc) AddAuthentication(auth *Authentication) {
	if d.Authentication == nil {
		d.Authentication = []*Authentication{}
	}
	d.Authentication = append(d.Authentication, auth)
}

// AddKeyAgreement adds a keyAgreement reference
func (d *DidDoc) AddKeyAgreement(ref VerificationMethodRef) {
	if d.KeyAgreement == nil {
		d.KeyAgreement = []VerificationMethodRef{}
	}
	d.KeyAgreement = append(d.KeyAgreement, ref)
}

// Clone creates a deep copy of the DIDDoc
func (d *DidDoc) Clone() *DidDoc {
	if d == nil {
		return nil
	}
	clone := &DidDoc{
		Id: d.Id,
	}
	clone.Context = d.Context
	if d.PublicKey != nil {
		clone.PublicKey = make([]*PublicKey, len(d.PublicKey))
		for i, pk := range d.PublicKey {
			cp := *pk
			if pk.PublicKeyJwk != nil {
				cp.PublicKeyJwk = make(map[string]interface{})
				for k, v := range pk.PublicKeyJwk {
					cp.PublicKeyJwk[k] = v
				}
			}
			clone.PublicKey[i] = &cp
		}
	}
	clone.Authentication = cloneAuthentications(d.Authentication)
	clone.KeyAgreement = cloneVerificationMethodRefs(d.KeyAgreement)
	if d.Service != nil {
		clone.Service = make([]*Service, len(d.Service))
		for i, svc := range d.Service {
			cs := *svc
			if svc.RoutingKeys != nil {
				cs.RoutingKeys = append([]string{}, svc.RoutingKeys...)
			}
			if svc.Accept != nil {
				cs.Accept = append([]string{}, svc.Accept...)
			}
			if svc.RecipientKeys != nil {
				cs.RecipientKeys = append([]string{}, svc.RecipientKeys...)
			}
			if svc.Properties != nil {
				cs.Properties = make(map[string]interface{})
				for k, v := range svc.Properties {
					cs.Properties[k] = v
				}
			}
			clone.Service[i] = &cs
		}
	}
	return clone
}

// Validate performs a basic validation using the DidDocument validator
func (d *DidDoc) Validate() error {
	return d.ToDidDocument().Validate()
}

// ToDidDocument converts an Aries DidDoc to a generic DidDocument
func (d *DidDoc) ToDidDocument() *DidDocument {
	if d == nil {
		return nil
	}
	var ctx []string
	if d.Context != "" {
		ctx = []string{d.Context}
	}
	doc := &DidDocument{
		Context: ctx,
		Id:      d.Id,
		Service: d.Service,
	}

	if d.PublicKey != nil {
		doc.VerificationMethod = make([]*VerificationMethod, len(d.PublicKey))
		for i, pk := range d.PublicKey {
			cp := *pk
			doc.VerificationMethod[i] = &cp
		}
	}

	if d.Authentication != nil {
		doc.Authentication = make([]VerificationMethodRef, len(d.Authentication))
		for i, auth := range d.Authentication {
			if auth.PublicKey != nil {
				doc.Authentication[i] = NewVerificationMethodRefString(auth.PublicKey.Id)
			}
		}
	}

	if d.KeyAgreement != nil {
		doc.KeyAgreement = cloneVerificationMethodRefs(d.KeyAgreement)
	}

	return doc
}

// GetRecipientKeys returns recipient keys from DIDComm services
func (d *DidDoc) GetRecipientKeys() []string {
	doc := d.ToDidDocument()
	if doc == nil {
		return nil
	}
	return doc.GetRecipientKeys()
}

// GetDIDCommServices returns DIDComm services from the DIDDoc
func (d *DidDoc) GetDIDCommServices() []*Service {
	doc := d.ToDidDocument()
	if doc == nil {
		return nil
	}
	return doc.GetDIDCommServices()
}

// cloneAuthentications creates a deep copy of authentication entries
func cloneAuthentications(auths []*Authentication) []*Authentication {
	if auths == nil {
		return nil
	}

	cloned := make([]*Authentication, len(auths))
	for i, a := range auths {
		var pk *PublicKey
		if a.PublicKey != nil {
			cp := *a.PublicKey
			if a.PublicKey.PublicKeyJwk != nil {
				cp.PublicKeyJwk = make(map[string]interface{})
				for k, v := range a.PublicKey.PublicKeyJwk {
					cp.PublicKeyJwk[k] = v
				}
			}
			pk = &cp
		}
		cloned[i] = &Authentication{
			Type:      a.Type,
			PublicKey: pk,
		}
	}

	return cloned
}
