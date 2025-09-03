package peer

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/core/encoding"
	"github.com/ajna-inc/essi/pkg/core/utils"
	dids "github.com/ajna-inc/essi/pkg/dids"
)

// DidPeerResolver implements DID resolution for the did:peer method
type DidPeerResolver struct {
	*dids.BaseDidResolver
}

// NewDidPeerResolver creates a new did:peer resolver
func NewDidPeerResolver() *DidPeerResolver {
	return &DidPeerResolver{
		BaseDidResolver: dids.NewBaseDidResolver([]string{dids.MethodPeer}),
	}
}

// Resolve resolves a did:peer DID to a DID document
func (r *DidPeerResolver) Resolve(ctx *context.AgentContext, did string, options *dids.DidResolutionOptions) (*dids.DidResolutionResult, error) {
	parsedDid := dids.TryParseDid(did)
	if parsedDid == nil {
		return r.CreateDidResolutionError(dids.DidResolutionErrorInvalidDid, "Invalid DID format"), nil
	}

	if parsedDid.Method != "peer" {
		return r.CreateDidResolutionError(dids.DidResolutionErrorMethodNotSupported, "DID method not supported"), nil
	}

	peerDid, err := parseDidPeer(did)
	if err != nil {
		return r.CreateDidResolutionError(dids.DidResolutionErrorInvalidDid, fmt.Sprintf("Invalid did:peer format: %s", err.Error())), nil
	}

	didDocument, err := r.createDidDocumentFromPeerDid(peerDid)
	if err != nil {
		return r.CreateDidResolutionError(dids.DidResolutionErrorInternalError, fmt.Sprintf("Failed to create DID document: %s", err.Error())), nil
	}

	return r.CreateDidResolutionResult(didDocument), nil
}

// PeerDid represents a parsed did:peer DID
type PeerDid struct {
	Did      string
	NumAlgo  int
	Elements []PeerDidElement
}

// PeerDidElement represents an element in a did:peer DID
type PeerDidElement struct {
	Purpose string // 'V' for verification method, 'E' for key agreement, 'S' for service
	Type    string // multicodec identifier or service type
	Value   string // encoded key or service data
}

// Purpose constants
const (
	PurposeVerification = "V"
	PurposeKeyAgreement = "E"
	PurposeService      = "S"
	PurposeAssertion    = "A"
)

// parseDidPeer parses a did:peer DID into its components
func parseDidPeer(did string) (*PeerDid, error) {
	// did:peer format: did:peer:<numalgo><elements>
	if !strings.HasPrefix(did, "did:peer:") {
		return nil, fmt.Errorf("not a did:peer DID")
	}

	methodSpecificId := strings.TrimPrefix(did, "did:peer:")
	if len(methodSpecificId) < 1 {
		return nil, fmt.Errorf("missing numalgo")
	}

	numAlgoStr := string(methodSpecificId[0])
	numAlgo, err := strconv.Atoi(numAlgoStr)
	if err != nil {
		return nil, fmt.Errorf("invalid numalgo: %s", numAlgoStr)
	}

	peerDid := &PeerDid{
		Did:      did,
		NumAlgo:  numAlgo,
		Elements: []PeerDidElement{},
	}

	// Parse elements based on numalgo
	elements := methodSpecificId[1:]

	switch numAlgo {
	case 0:
		// Numalgo 0: Single key
		if err := parseNumAlgo0Elements(peerDid, elements); err != nil {
			return nil, err
		}
	case 1:
		// Numalgo 1: Genesis document hash
		if err := parseNumAlgo1Elements(peerDid, elements); err != nil {
			return nil, err
		}
	case 2:
		// Numalgo 2: Multiple keys and services
		if err := parseNumAlgo2Elements(peerDid, elements); err != nil {
			return nil, err
		}
	case 4:
		// Numalgo 4: Full DID Document encoding
		if err := parseNumAlgo4Elements(peerDid, elements); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported numalgo: %d", numAlgo)
	}

	return peerDid, nil
}

// parseNumAlgo0Elements parses numalgo 0 elements (single key)
func parseNumAlgo0Elements(peerDid *PeerDid, elements string) error {
	if elements == "" {
		return fmt.Errorf("missing key data for numalgo 0")
	}

	// For numalgo 0, the entire elements string is the base58btc-encoded key
	peerDid.Elements = append(peerDid.Elements, PeerDidElement{
		Purpose: PurposeVerification,
		Type:    "Ed25519",
		Value:   elements,
	})

	return nil
}

// parseNumAlgo1Elements parses numalgo 1 elements (genesis document hash)
func parseNumAlgo1Elements(peerDid *PeerDid, elements string) error {
	if elements == "" {
		return fmt.Errorf("missing genesis hash for numalgo 1")
	}

	// For numalgo 1, we can't resolve without the genesis document
	// This is a limitation - we need the original genesis document to resolve
	return fmt.Errorf("numalgo 1 resolution requires genesis document (not supported)")
}

// parseNumAlgo2Elements parses numalgo 2 elements (multiple keys and services)
func parseNumAlgo2Elements(peerDid *PeerDid, elements string) error {
	if elements == "" {
		return fmt.Errorf("missing elements for numalgo 2")
	}

	// Parse dot-separated elements
	parts := strings.Split(elements, ".")

	for _, part := range parts {
		if len(part) < 2 {
			return fmt.Errorf("invalid element format: %s", part)
		}

		purpose := string(part[0])
		typeAndValue := part[1:]

		element := PeerDidElement{
			Purpose: purpose,
		}

		switch purpose {
		case PurposeVerification, PurposeKeyAgreement, PurposeAssertion:
			// Parse key element: <multicodec><base58btc-key>
			if err := parseKeyElement(&element, typeAndValue); err != nil {
				return fmt.Errorf("failed to parse key element: %w", err)
			}

		case PurposeService:
			// Parse service element: encoded service data
			if err := parseServiceElement(&element, typeAndValue); err != nil {
				return fmt.Errorf("failed to parse service element: %w", err)
			}

		default:
			return fmt.Errorf("unknown purpose: %s", purpose)
		}

		peerDid.Elements = append(peerDid.Elements, element)
	}

	return nil
}

// parseNumAlgo4Elements parses numalgo 4 elements (encoded DID Document)
func parseNumAlgo4Elements(peerDid *PeerDid, elements string) error {
	if elements == "" {
		return fmt.Errorf("missing encoded document for numalgo 4")
	}
	// did:peer:4 can be long-form: did:peer:4{hash}:{encodedDocument}
	// If a ':' is present, take the part AFTER the first ':'
	encoded := elements
	if idx := strings.Index(elements, ":"); idx != -1 {
		// If there's nothing after the colon, it's invalid
		if idx+1 >= len(elements) {
			return fmt.Errorf("invalid numalgo 4 format: missing encoded document")
		}
		encoded = elements[idx+1:]
	}
	// Store a single synthetic element carrying only the encoded document
	peerDid.Elements = append(peerDid.Elements, PeerDidElement{
		Purpose: PurposeService,
		Type:    "DIDDocument",
		Value:   encoded, // multibase base58btc-encoded JSON (usually starts with 'z')
	})
	return nil
}

// parseKeyElement parses a key element
func parseKeyElement(element *PeerDidElement, typeAndValue string) error {
	if len(typeAndValue) < 1 {
		return fmt.Errorf("missing key data")
	}

	// First character is the multicodec type
	codecChar := string(typeAndValue[0])
	keyValue := typeAndValue[1:]

	// Map multicodec characters to key types
	switch codecChar {
	case "z":
		element.Type = "Ed25519VerificationKey2020"
	case "6":
		element.Type = "X25519KeyAgreementKey2020"
	default:
		return fmt.Errorf("unsupported key type: %s", codecChar)
	}

	element.Value = keyValue
	return nil
}

// parseServiceElement parses a service element
func parseServiceElement(element *PeerDidElement, typeAndValue string) error {
	// Service elements are base64url-encoded JSON
	serviceData, err := utils.DecodeBase64URLString(typeAndValue)
	if err != nil {
		return fmt.Errorf("failed to decode service data: %w", err)
	}

	// Parse the service JSON to extract type
	var serviceObj map[string]interface{}
	if err := json.Unmarshal(serviceData, &serviceObj); err != nil {
		return fmt.Errorf("failed to parse service JSON: %w", err)
	}

	if serviceType, ok := serviceObj["type"].(string); ok {
		element.Type = serviceType
	} else {
		element.Type = "DIDCommMessaging"
	}

	element.Value = typeAndValue
	return nil
}

// createDidDocumentFromPeerDid creates a DID document from a parsed peer DID
func (r *DidPeerResolver) createDidDocumentFromPeerDid(peerDid *PeerDid) (*dids.DidDocument, error) {
	didDoc := dids.NewDidDocument(peerDid.Did)
	didDoc.AddContext(dids.SecurityContextV2)

	switch peerDid.NumAlgo {
	case 0:
		return r.createNumAlgo0DidDocument(didDoc, peerDid)
	case 2:
		return r.createNumAlgo2DidDocument(didDoc, peerDid)
	case 4:
		return r.createNumAlgo4DidDocument(peerDid)
	default:
		return nil, fmt.Errorf("unsupported numalgo: %d", peerDid.NumAlgo)
	}
}

// createNumAlgo0DidDocument creates a DID document for numalgo 0
func (r *DidPeerResolver) createNumAlgo0DidDocument(didDoc *dids.DidDocument, peerDid *PeerDid) (*dids.DidDocument, error) {
	if len(peerDid.Elements) != 1 {
		return nil, fmt.Errorf("numalgo 0 must have exactly one element")
	}

	element := peerDid.Elements[0]

	// Validate the key can be decoded (but don't store the result since we don't need it)
	_, err := encoding.DecodeBase58(element.Value)
	if err != nil {
		return nil, fmt.Errorf("failed to decode key: %w", err)
	}

	vmId := peerDid.Did + "#key-1"
	vm := &dids.VerificationMethod{
		Id:                 vmId,
		Type:               dids.VerificationMethodTypeEd25519VerificationKey2020,
		Controller:         peerDid.Did,
		PublicKeyMultibase: "z" + element.Value,
	}

	didDoc.AddVerificationMethod(vm)

	// Add verification relationships
	vmRef := dids.NewVerificationMethodRefString(vmId)
	didDoc.AddAuthentication(vmRef)
	didDoc.AddAssertionMethod(vmRef)
	didDoc.AddCapabilityInvocation(vmRef)
	didDoc.AddCapabilityDelegation(vmRef)

	return didDoc, nil
}

// createNumAlgo2DidDocument creates a DID document for numalgo 2
func (r *DidPeerResolver) createNumAlgo2DidDocument(didDoc *dids.DidDocument, peerDid *PeerDid) (*dids.DidDocument, error) {
	verificationMethodIndex := 1
	serviceIndex := 1

	for _, element := range peerDid.Elements {
		switch element.Purpose {
		case PurposeVerification, PurposeKeyAgreement, PurposeAssertion:
			if err := r.addKeyElement(didDoc, peerDid, &element, &verificationMethodIndex); err != nil {
				return nil, err
			}

		case PurposeService:
			if err := r.addServiceElement(didDoc, peerDid, &element, &serviceIndex); err != nil {
				return nil, err
			}
		}
	}

	return didDoc, nil
}

// createNumAlgo4DidDocument creates a DID document for numalgo 4 by decoding the embedded JSON
func (r *DidPeerResolver) createNumAlgo4DidDocument(peerDid *PeerDid) (*dids.DidDocument, error) {
	if len(peerDid.Elements) == 0 {
		return nil, fmt.Errorf("numalgo 4 requires an encoded document element")
	}
	enc := peerDid.Elements[0].Value
	// Drop optional multibase prefix 'z'
	if strings.HasPrefix(enc, "z") {
		enc = enc[1:]
	}
	var raw []byte
	var err error
	// Try base58btc decode
	if b, e := encoding.DecodeBase58(enc); e == nil {
		raw = b
	} else {
		err = e
	}
	// If base58 fails or JSON unmarshal fails, try base64url (common in some implementations)
	var doc dids.DidDocument
	if len(raw) > 0 {
		if jerr := json.Unmarshal(raw, &doc); jerr != nil {
			raw = nil
			err = jerr
		}
	}
	if len(raw) == 0 {
		if b, e := base64.RawURLEncoding.DecodeString(enc); e == nil {
			raw = b
		} else if b2, e2 := base64.StdEncoding.DecodeString(enc); e2 == nil {
			raw = b2
		}
		if len(raw) == 0 {
			return nil, fmt.Errorf("failed to decode numalgo4 document: %v", err)
		}
		if jerr := json.Unmarshal(raw, &doc); jerr != nil {
			return nil, fmt.Errorf("failed to parse did document: %w", jerr)
		}
	}
	// Ensure DID is set to the parsed DID value
	doc.Id = peerDid.Did
	return &doc, nil
}

// addKeyElement adds a key element to the DID document
func (r *DidPeerResolver) addKeyElement(didDoc *dids.DidDocument, peerDid *PeerDid, element *PeerDidElement, index *int) error {
	vmId := fmt.Sprintf("%s#key-%d", peerDid.Did, *index)
	*index++

	vm := &dids.VerificationMethod{
		Id:                 vmId,
		Type:               element.Type,
		Controller:         peerDid.Did,
		PublicKeyMultibase: "z" + element.Value,
	}

	didDoc.AddVerificationMethod(vm)

	// Add verification relationships based on purpose
	vmRef := dids.NewVerificationMethodRefString(vmId)

	switch element.Purpose {
	case PurposeVerification:
		didDoc.AddAuthentication(vmRef)
		didDoc.AddAssertionMethod(vmRef)
		didDoc.AddCapabilityInvocation(vmRef)
		didDoc.AddCapabilityDelegation(vmRef)

	case PurposeKeyAgreement:
		didDoc.AddKeyAgreement(vmRef)

	case PurposeAssertion:
		didDoc.AddAssertionMethod(vmRef)
	}

	return nil
}

// addServiceElement adds a service element to the DID document
func (r *DidPeerResolver) addServiceElement(didDoc *dids.DidDocument, peerDid *PeerDid, element *PeerDidElement, index *int) error {
	// Decode service data
	serviceData, err := utils.DecodeBase64URLString(element.Value)
	if err != nil {
		return fmt.Errorf("failed to decode service data: %w", err)
	}

	// Parse service JSON
	var serviceObj map[string]interface{}
	if err := json.Unmarshal(serviceData, &serviceObj); err != nil {
		return fmt.Errorf("failed to parse service JSON: %w", err)
	}

	serviceId := fmt.Sprintf("%s#service-%d", peerDid.Did, *index)
	if id, ok := serviceObj["id"].(string); ok && id != "" {
		serviceId = id
	}
	*index++

	service := &dids.Service{
		Id:   serviceId,
		Type: element.Type,
	}

	if endpoint, ok := serviceObj["serviceEndpoint"]; ok {
		service.ServiceEndpoint = endpoint
	}

	if accept, ok := serviceObj["accept"].([]interface{}); ok {
		acceptStrings := make([]string, len(accept))
		for i, a := range accept {
			if str, ok := a.(string); ok {
				acceptStrings[i] = str
			}
		}
		service.Accept = acceptStrings
	}

	if routingKeys, ok := serviceObj["routingKeys"].([]interface{}); ok {
		routingKeyStrings := make([]string, len(routingKeys))
		for i, rk := range routingKeys {
			if str, ok := rk.(string); ok {
				routingKeyStrings[i] = str
			}
		}
		service.RoutingKeys = routingKeyStrings
	}

	didDoc.AddService(service)
	return nil
}

// formatPeerDidElement formats a peer DID element
func formatPeerDidElement(element *PeerDidElement) (string, error) {
	switch element.Purpose {
	case PurposeVerification, PurposeKeyAgreement, PurposeAssertion:
		// Format key element
		var codecChar string
		switch element.Type {
		case dids.VerificationMethodTypeEd25519VerificationKey2020:
			codecChar = "z"
		case "X25519KeyAgreementKey2020":
			codecChar = "6"
		case dids.VerificationMethodTypeX25519KeyAgreementKey2019:
			codecChar = "6"
		default:
			return "", fmt.Errorf("unsupported key type: %s", element.Type)
		}

		return element.Purpose + codecChar + element.Value, nil

	case PurposeService:
		// Service element value should already be base64url-encoded
		return element.Purpose + element.Value, nil

	default:
		return "", fmt.Errorf("unknown purpose: %s", element.Purpose)
	}
}

// Utility functions for creating did:peer DIDs

// CreateDidPeerNumAlgo0 creates a did:peer numalgo 0 from an Ed25519 public key
func CreateDidPeerNumAlgo0(publicKey ed25519.PublicKey) (string, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return "", fmt.Errorf("invalid Ed25519 public key length")
	}

	fingerprint, err := Ed25519Fingerprint(publicKey)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("did:peer:0%s", fingerprint), nil
}

// CreateDidPeerNumAlgo2 creates a did:peer numalgo 2 from elements
func CreateDidPeerNumAlgo2(elements []PeerDidElement) (string, error) {
	if len(elements) == 0 {
		return "", fmt.Errorf("at least one element is required")
	}

	var elementStrings []string

	for _, element := range elements {
		elementStr, err := formatPeerDidElement(&element)
		if err != nil {
			return "", fmt.Errorf("failed to format element: %w", err)
		}
		elementStrings = append(elementStrings, elementStr)
	}

	methodSpecificId := "2" + strings.Join(elementStrings, ".")
	return "did:peer:" + methodSpecificId, nil
}

// CreatePeerDidElement creates a peer DID element
func CreatePeerDidElement(purpose, elementType string, value interface{}) (*PeerDidElement, error) {
	element := &PeerDidElement{
		Purpose: purpose,
		Type:    elementType,
	}

	switch purpose {
	case PurposeVerification, PurposeKeyAgreement, PurposeAssertion:
		// For keys, value should be the base58-encoded key
		if keyStr, ok := value.(string); ok {
			element.Value = keyStr
		} else {
			return nil, fmt.Errorf("key value must be a string")
		}

	case PurposeService:
		// For services, value should be a service object
		serviceBytes, err := json.Marshal(value)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal service: %w", err)
		}

		// Base64url encode the service
		element.Value = utils.EncodeBase64URLString(serviceBytes)

	default:
		return nil, fmt.Errorf("unknown purpose: %s", purpose)
	}

	return element, nil
}

// ValidateDidPeer validates a did:peer DID
func ValidateDidPeer(didPeer string) error {
	peerDid, err := parseDidPeer(didPeer)
	if err != nil {
		return fmt.Errorf("invalid did:peer: %w", err)
	}

	// Validate based on numalgo
	switch peerDid.NumAlgo {
	case 0:
		if len(peerDid.Elements) != 1 {
			return fmt.Errorf("numalgo 0 must have exactly one element")
		}

	case 2:
		if len(peerDid.Elements) == 0 {
			return fmt.Errorf("numalgo 2 must have at least one element")
		}

	case 4:
		if len(peerDid.Elements) != 1 {
			return fmt.Errorf("numalgo 4 must have exactly one encoded document element")
		}

	default:
		return fmt.Errorf("unsupported numalgo: %d", peerDid.NumAlgo)
	}

	return nil
}

// CreateDidPeerNumAlgo4FromDidDocument encodes a DID Document as a numalgo 4 peer DID.
// Returns short and long form dids, where long form contains the encoded document.
// Spec parity with Credo-TS:
// - encodedDocument = multibase(base58btc(varint(JSON_MULTICODEC=0x0200) || json(doc-without-id-and-controllers)))
// - hash = multibase(base58btc(multihash(sha-256(encodedDocument-bytes))))
// - short = did:peer:4{hash}
// - long  = did:peer:4{hash}:{encodedDocument}
func CreateDidPeerNumAlgo4FromDidDocument(doc *dids.DidDocument) (string, string, error) {
	if doc == nil {
		return "", "", fmt.Errorf("did document is required")
	}
	// Clone and clear id/alsoKnownAs, and remove controller references
	tmp := *doc
	tmp.Id = ""
	// We don't set AlsoKnownAs on our DidDocument type, so nothing to clear

	// Marshal JSON
	jsonBytes, err := json.Marshal(&tmp)
	if err != nil {
		return "", "", fmt.Errorf("failed to serialize did document: %w", err)
	}

	// Prepend multicodec varint for JSON (0x0200)
	// LEB128 varint encoding
	encodeVarint := func(v int) []byte {
		var out []byte
		for {
			b := byte(v & 0x7f)
			v >>= 7
			if v != 0 {
				b |= 0x80
			}
			out = append(out, b)
			if v == 0 {
				break
			}
		}
		return out
	}
	// 0x0200 == 512
	prefix := encodeVarint(0x0200)
	prefixed := append(prefix, jsonBytes...)

	// encodedDocument = multibase base58btc of prefixed bytes
	encodedDocument := "z" + encoding.EncodeBase58(prefixed)

	// Hash is multibase base58btc of multihash(sha-256(encodedDocument bytes))
	// multihash format: <code:0x12><len:0x20><digest32>
	h := sha256Sum([]byte(encodedDocument))
	mh := append([]byte{0x12, 0x20}, h...)
	hash := "z" + encoding.EncodeBase58(mh)

	short := "did:peer:4" + hash
	long := short + ":" + encodedDocument
	return short, long, nil
}

func sha256Sum(b []byte) []byte {
	h := sha256.New()
	_, _ = h.Write(b)
	return h.Sum(nil)
}
