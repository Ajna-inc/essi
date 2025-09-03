package dids

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// DidDocument represents a DID Document according to the DID specification
type DidDocument struct {
	Context              []string                `json:"@context"`
	Id                   string                  `json:"id"`
	AlsoKnownAs          []string                `json:"alsoKnownAs,omitempty"`
	Controller           []string                `json:"controller,omitempty"`
	VerificationMethod   []*VerificationMethod   `json:"verificationMethod,omitempty"`
	Authentication       []VerificationMethodRef `json:"authentication,omitempty"`
	AssertionMethod      []VerificationMethodRef `json:"assertionMethod,omitempty"`
	KeyAgreement         []VerificationMethodRef `json:"keyAgreement,omitempty"`
	CapabilityInvocation []VerificationMethodRef `json:"capabilityInvocation,omitempty"`
	CapabilityDelegation []VerificationMethodRef `json:"capabilityDelegation,omitempty"`
	Service              []*Service              `json:"service,omitempty"`
	Created              *time.Time              `json:"created,omitempty"`
	Updated              *time.Time              `json:"updated,omitempty"`
	VersionId            string                  `json:"versionId,omitempty"`
	NextUpdate           *time.Time              `json:"nextUpdate,omitempty"`
	NextVersionId        string                  `json:"nextVersionId,omitempty"`
}

// VerificationMethod represents a verification method in a DID Document
type VerificationMethod struct {
	Id                  string                 `json:"id"`
	Type                string                 `json:"type"`
	Controller          string                 `json:"controller"`
	PublicKeyBase58     string                 `json:"publicKeyBase58,omitempty"`
	PublicKeyMultibase  string                 `json:"publicKeyMultibase,omitempty"`
	PublicKeyJwk        map[string]interface{} `json:"publicKeyJwk,omitempty"`
	BlockchainAccountId string                 `json:"blockchainAccountId,omitempty"`
	EthereumAddress     string                 `json:"ethereumAddress,omitempty"`
}

// VerificationMethodRef represents a reference to a verification method
// It can be either a string (reference) or an embedded VerificationMethod
type VerificationMethodRef interface {
	GetId() string
	IsEmbedded() bool
	GetVerificationMethod() *VerificationMethod
}

// VerificationMethodRefString represents a string reference to a verification method
type VerificationMethodRefString struct {
	Ref string
}

func (r *VerificationMethodRefString) GetId() string {
	return r.Ref
}

func (r *VerificationMethodRefString) IsEmbedded() bool {
	return false
}

func (r *VerificationMethodRefString) GetVerificationMethod() *VerificationMethod {
	return nil
}

// MarshalJSON implements json.Marshaler for VerificationMethodRefString
func (r *VerificationMethodRefString) MarshalJSON() ([]byte, error) {
	return json.Marshal(r.Ref)
}

// VerificationMethodRefEmbedded represents an embedded verification method
type VerificationMethodRefEmbedded struct {
	Method *VerificationMethod
}

func (r *VerificationMethodRefEmbedded) GetId() string {
	if r.Method != nil {
		return r.Method.Id
	}
	return ""
}

func (r *VerificationMethodRefEmbedded) IsEmbedded() bool {
	return true
}

func (r *VerificationMethodRefEmbedded) GetVerificationMethod() *VerificationMethod {
	return r.Method
}

// MarshalJSON implements json.Marshaler for VerificationMethodRefEmbedded
func (r *VerificationMethodRefEmbedded) MarshalJSON() ([]byte, error) {
	return json.Marshal(r.Method)
}

// Service represents a service in a DID Document
type Service struct {
	Id              string                 `json:"id"`
	Type            string                 `json:"type"`
	ServiceEndpoint interface{}            `json:"serviceEndpoint"`
	RoutingKeys     []string               `json:"routingKeys,omitempty"`
	Accept          []string               `json:"accept,omitempty"`
	RecipientKeys   []string               `json:"recipientKeys,omitempty"`
	Priority        int                    `json:"priority,omitempty"`
	Properties      map[string]interface{} `json:"-"` // For additional properties
}

// Common DID Document contexts
const (
	DIDContextV1               = "https://w3id.org/did/v1"
	SecurityContextV1          = "https://w3id.org/security/v1"
	SecurityContextV2          = "https://w3id.org/security/v2"
	SecurityContextV3alpha     = "https://w3id.org/security/v3-unstable"
	Ed25519VerificationKey2018 = "https://w3id.org/security#Ed25519VerificationKey2018"
	Ed25519VerificationKey2020 = "https://w3id.org/security#Ed25519VerificationKey2020"
)

// Common verification method types
const (
	VerificationMethodTypeEd25519VerificationKey2018        = "Ed25519VerificationKey2018"
	VerificationMethodTypeEd25519VerificationKey2020        = "Ed25519VerificationKey2020"
	VerificationMethodTypeJsonWebKey2020                    = "JsonWebKey2020"
	VerificationMethodTypeEcdsaSecp256k1VerificationKey2019 = "EcdsaSecp256k1VerificationKey2019"
	VerificationMethodTypeRsaVerificationKey2018            = "RsaVerificationKey2018"
	VerificationMethodTypeX25519KeyAgreementKey2019         = "X25519KeyAgreementKey2019"
)

// Common service types
const (
	ServiceTypeDIDCommMessaging = "DIDCommMessaging"
	ServiceTypeDIDComm          = "did-communication"
	ServiceTypeIndyAgent        = "IndyAgent"
)

// NewDidDocument creates a new DID Document with default context
func NewDidDocument(id string) *DidDocument {
	return &DidDocument{
		Context: []string{DIDContextV1},
		Id:      id,
	}
}

// AddContext adds a context to the DID Document
func (doc *DidDocument) AddContext(context string) {
	// Check if context already exists
	for _, existing := range doc.Context {
		if existing == context {
			return
		}
	}
	doc.Context = append(doc.Context, context)
}

// AddVerificationMethod adds a verification method to the DID Document
func (doc *DidDocument) AddVerificationMethod(method *VerificationMethod) {
	if doc.VerificationMethod == nil {
		doc.VerificationMethod = []*VerificationMethod{}
	}
	doc.VerificationMethod = append(doc.VerificationMethod, method)
}

// AddService adds a service to the DID Document
func (doc *DidDocument) AddService(service *Service) {
	if doc.Service == nil {
		doc.Service = []*Service{}
	}
	doc.Service = append(doc.Service, service)
}

// FindVerificationMethodById finds a verification method by its ID
func (doc *DidDocument) FindVerificationMethodById(id string) *VerificationMethod {
	for _, method := range doc.VerificationMethod {
		if method.Id == id || strings.HasSuffix(method.Id, "#"+id) {
			return method
		}
	}
	return nil
}

// DereferenceVerificationMethod finds a verification method by key ID
// This handles both full IDs and fragment-only references
func (doc *DidDocument) DereferenceVerificationMethod(keyId string) (*VerificationMethod, error) {
	// Look for exact match first
	for _, method := range doc.VerificationMethod {
		if method.Id == keyId {
			return method, nil
		}
	}

	// Look for methods that end with the keyId (for fragment matching)
	for _, method := range doc.VerificationMethod {
		if strings.HasSuffix(method.Id, keyId) {
			return method, nil
		}
	}

	return nil, fmt.Errorf("unable to locate verification method with id '%s'", keyId)
}

// FindServiceById finds a service by its ID
func (doc *DidDocument) FindServiceById(id string) *Service {
	for _, service := range doc.Service {
		if service.Id == id || strings.HasSuffix(service.Id, "#"+id) {
			return service
		}
	}
	return nil
}

// AddAuthentication adds an authentication relationship
func (doc *DidDocument) AddAuthentication(ref VerificationMethodRef) {
	if doc.Authentication == nil {
		doc.Authentication = []VerificationMethodRef{}
	}
	doc.Authentication = append(doc.Authentication, ref)
}

// AddAssertionMethod adds an assertion method relationship
func (doc *DidDocument) AddAssertionMethod(ref VerificationMethodRef) {
	if doc.AssertionMethod == nil {
		doc.AssertionMethod = []VerificationMethodRef{}
	}
	doc.AssertionMethod = append(doc.AssertionMethod, ref)
}

// AddKeyAgreement adds a key agreement relationship
func (doc *DidDocument) AddKeyAgreement(ref VerificationMethodRef) {
	if doc.KeyAgreement == nil {
		doc.KeyAgreement = []VerificationMethodRef{}
	}
	doc.KeyAgreement = append(doc.KeyAgreement, ref)
}

// AddCapabilityInvocation adds a capability invocation relationship
func (doc *DidDocument) AddCapabilityInvocation(ref VerificationMethodRef) {
	if doc.CapabilityInvocation == nil {
		doc.CapabilityInvocation = []VerificationMethodRef{}
	}
	doc.CapabilityInvocation = append(doc.CapabilityInvocation, ref)
}

// AddCapabilityDelegation adds a capability delegation relationship
func (doc *DidDocument) AddCapabilityDelegation(ref VerificationMethodRef) {
	if doc.CapabilityDelegation == nil {
		doc.CapabilityDelegation = []VerificationMethodRef{}
	}
	doc.CapabilityDelegation = append(doc.CapabilityDelegation, ref)
}

// GetRecipientKeys extracts recipient keys from DIDComm services
func (doc *DidDocument) GetRecipientKeys() []string {
	var keys []string

	for _, service := range doc.Service {
		if service.Type == ServiceTypeDIDCommMessaging || service.Type == ServiceTypeDIDComm {
			keys = append(keys, service.RecipientKeys...)
		}
	}

	return keys
}

// GetDIDCommServices returns all DIDComm services
func (doc *DidDocument) GetDIDCommServices() []*Service {
	var services []*Service

	for _, service := range doc.Service {
		if service.Type == ServiceTypeDIDCommMessaging ||
			service.Type == ServiceTypeDIDComm ||
			service.Type == ServiceTypeIndyAgent {
			services = append(services, service)
		}
	}

	return services
}

// Validate performs basic validation on the DID Document
func (doc *DidDocument) Validate() error {
	if doc.Id == "" {
		return fmt.Errorf("DID Document must have an id")
	}

	if !IsValidDid(doc.Id) {
		return fmt.Errorf("DID Document id must be a valid DID: %s", doc.Id)
	}

	// Validate verification methods
	for _, method := range doc.VerificationMethod {
		if err := method.Validate(); err != nil {
			return fmt.Errorf("invalid verification method: %w", err)
		}
	}

	// Validate services
	for _, service := range doc.Service {
		if err := service.Validate(); err != nil {
			return fmt.Errorf("invalid service: %w", err)
		}
	}

	return nil
}

// Validate validates a verification method
func (vm *VerificationMethod) Validate() error {
	if vm.Id == "" {
		return fmt.Errorf("verification method must have an id")
	}

	if vm.Type == "" {
		return fmt.Errorf("verification method must have a type")
	}

	if vm.Controller == "" {
		return fmt.Errorf("verification method must have a controller")
	}

	// Must have at least one key material field
	hasKeyMaterial := vm.PublicKeyBase58 != "" ||
		vm.PublicKeyMultibase != "" ||
		vm.PublicKeyJwk != nil ||
		vm.BlockchainAccountId != "" ||
		vm.EthereumAddress != ""

	if !hasKeyMaterial {
		return fmt.Errorf("verification method must have key material")
	}

	return nil
}

// Validate validates a service
func (s *Service) Validate() error {
	if s.Id == "" {
		return fmt.Errorf("service must have an id")
	}

	if s.Type == "" {
		return fmt.Errorf("service must have a type")
	}

	if s.ServiceEndpoint == nil {
		return fmt.Errorf("service must have a serviceEndpoint")
	}

	return nil
}

// Helper functions for creating verification method references

// NewVerificationMethodRefString creates a string reference
func NewVerificationMethodRefString(ref string) VerificationMethodRef {
	return &VerificationMethodRefString{Ref: ref}
}

// NewVerificationMethodRefEmbedded creates an embedded reference
func NewVerificationMethodRefEmbedded(method *VerificationMethod) VerificationMethodRef {
	return &VerificationMethodRefEmbedded{Method: method}
}

// JSON serialization helpers

// UnmarshalJSON handles custom unmarshaling for VerificationMethodRef
func UnmarshalVerificationMethodRef(data []byte) (VerificationMethodRef, error) {
	// Try to unmarshal as string first
	var refString string
	if err := json.Unmarshal(data, &refString); err == nil {
		return &VerificationMethodRefString{Ref: refString}, nil
	}

	// Try to unmarshal as embedded verification method
	var method VerificationMethod
	if err := json.Unmarshal(data, &method); err == nil {
		return &VerificationMethodRefEmbedded{Method: &method}, nil
	}

	return nil, fmt.Errorf("unable to unmarshal verification method reference")
}

// Clone creates a deep copy of the DID Document
func (doc *DidDocument) Clone() *DidDocument {
	clone := &DidDocument{
		Id:            doc.Id,
		VersionId:     doc.VersionId,
		NextVersionId: doc.NextVersionId,
	}

	// Clone context
	if doc.Context != nil {
		clone.Context = make([]string, len(doc.Context))
		copy(clone.Context, doc.Context)
	}

	// Clone alsoKnownAs
	if doc.AlsoKnownAs != nil {
		clone.AlsoKnownAs = make([]string, len(doc.AlsoKnownAs))
		copy(clone.AlsoKnownAs, doc.AlsoKnownAs)
	}

	// Clone controller
	if doc.Controller != nil {
		clone.Controller = make([]string, len(doc.Controller))
		copy(clone.Controller, doc.Controller)
	}

	// Clone time fields
	if doc.Created != nil {
		created := *doc.Created
		clone.Created = &created
	}
	if doc.Updated != nil {
		updated := *doc.Updated
		clone.Updated = &updated
	}
	if doc.NextUpdate != nil {
		nextUpdate := *doc.NextUpdate
		clone.NextUpdate = &nextUpdate
	}

	// Clone verification methods
	if doc.VerificationMethod != nil {
		clone.VerificationMethod = make([]*VerificationMethod, len(doc.VerificationMethod))
		for i, vm := range doc.VerificationMethod {
			clonedVm := &VerificationMethod{
				Id:                  vm.Id,
				Type:                vm.Type,
				Controller:          vm.Controller,
				PublicKeyBase58:     vm.PublicKeyBase58,
				PublicKeyMultibase:  vm.PublicKeyMultibase,
				BlockchainAccountId: vm.BlockchainAccountId,
				EthereumAddress:     vm.EthereumAddress,
			}

			// Clone PublicKeyJwk map
			if vm.PublicKeyJwk != nil {
				clonedVm.PublicKeyJwk = make(map[string]interface{})
				for k, v := range vm.PublicKeyJwk {
					clonedVm.PublicKeyJwk[k] = v
				}
			}

			clone.VerificationMethod[i] = clonedVm
		}
	}

	// Clone verification method references
	clone.Authentication = cloneVerificationMethodRefs(doc.Authentication)
	clone.AssertionMethod = cloneVerificationMethodRefs(doc.AssertionMethod)
	clone.KeyAgreement = cloneVerificationMethodRefs(doc.KeyAgreement)
	clone.CapabilityInvocation = cloneVerificationMethodRefs(doc.CapabilityInvocation)
	clone.CapabilityDelegation = cloneVerificationMethodRefs(doc.CapabilityDelegation)

	// Clone services
	if doc.Service != nil {
		clone.Service = make([]*Service, len(doc.Service))
		for i, svc := range doc.Service {
			clonedSvc := &Service{
				Id:              svc.Id,
				Type:            svc.Type,
				ServiceEndpoint: svc.ServiceEndpoint,
				Priority:        svc.Priority,
			}

			// Clone string slices
			if svc.RoutingKeys != nil {
				clonedSvc.RoutingKeys = make([]string, len(svc.RoutingKeys))
				copy(clonedSvc.RoutingKeys, svc.RoutingKeys)
			}
			if svc.Accept != nil {
				clonedSvc.Accept = make([]string, len(svc.Accept))
				copy(clonedSvc.Accept, svc.Accept)
			}
			if svc.RecipientKeys != nil {
				clonedSvc.RecipientKeys = make([]string, len(svc.RecipientKeys))
				copy(clonedSvc.RecipientKeys, svc.RecipientKeys)
			}

			// Clone properties map
			if svc.Properties != nil {
				clonedSvc.Properties = make(map[string]interface{})
				for k, v := range svc.Properties {
					clonedSvc.Properties[k] = v
				}
			}

			clone.Service[i] = clonedSvc
		}
	}

	return clone
}

// cloneVerificationMethodRefs clones a slice of verification method references
func cloneVerificationMethodRefs(refs []VerificationMethodRef) []VerificationMethodRef {
	if refs == nil {
		return nil
	}

	cloned := make([]VerificationMethodRef, len(refs))
	for i, ref := range refs {
		if ref.IsEmbedded() {
			// Clone embedded verification method
			original := ref.GetVerificationMethod()
			if original != nil {
				clonedMethod := &VerificationMethod{
					Id:                  original.Id,
					Type:                original.Type,
					Controller:          original.Controller,
					PublicKeyBase58:     original.PublicKeyBase58,
					PublicKeyMultibase:  original.PublicKeyMultibase,
					BlockchainAccountId: original.BlockchainAccountId,
					EthereumAddress:     original.EthereumAddress,
				}

				// Clone PublicKeyJwk map
				if original.PublicKeyJwk != nil {
					clonedMethod.PublicKeyJwk = make(map[string]interface{})
					for k, v := range original.PublicKeyJwk {
						clonedMethod.PublicKeyJwk[k] = v
					}
				}

				cloned[i] = &VerificationMethodRefEmbedded{Method: clonedMethod}
			}
		} else {
			// Clone string reference
			cloned[i] = &VerificationMethodRefString{Ref: ref.GetId()}
		}
	}

	return cloned
}
