package peer

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ajna-inc/essi/pkg/core/encoding"
	"github.com/ajna-inc/essi/pkg/dids"
)

// PeerDidNumAlgo represents the different peer DID method algorithms
type PeerDidNumAlgo int

const (
	PeerDidNumAlgo0 PeerDidNumAlgo = iota // InceptionKeyWithoutDoc
	PeerDidNumAlgo1                       // GenesisDoc
	PeerDidNumAlgo2                       // MultipleInceptionKeyWithoutDoc
	PeerDidNumAlgo4                       // ShortFormAndLongForm
)

// CreatePeerDid1 creates a did:peer:1 DID from a DID document
// This follows the spec at https://identity.foundation/peer-did-method-spec/#generation-method
func CreatePeerDid1(didDoc *dids.DidDocument) (string, error) {
	if didDoc == nil {
		return "", fmt.Errorf("DID document cannot be nil")
	}

	docCopy := *didDoc
	docCopy.Id = ""

	docJSON, err := json.Marshal(&docCopy)
	if err != nil {
		return "", fmt.Errorf("failed to marshal DID document: %w", err)
	}

	// Calculate SHA256 hash of the genesis version of the DID Document
	hash := sha256.Sum256(docJSON)

	multihash := append([]byte{0x12, 0x20}, hash[:]...)

	// Encode as base58btc multibase (z prefix)
	hashBase58 := encoding.EncodeBase58(multihash)

	did := fmt.Sprintf("did:peer:1z%s", hashBase58)

	return did, nil
}

// CreatePeerDid2 creates a did:peer:2 DID from services and keys
func CreatePeerDid2(publicKey ed25519.PublicKey, serviceEndpoint string) (string, error) {
	// For simplicity, we'll create a basic did:peer:2
	// Format: did:peer:2.<purpose><multibase-encoded-key>
	// Purpose: E = Encryption, V = Verification, I = Invocation, D = Delegation, S = Service

	// Add multicodec prefix for Ed25519 public key (0xed01)
	keyWithPrefix := append([]byte{0xed, 0x01}, publicKey...)

	// Encode as base58btc multibase
	encodedKey := "z" + encoding.EncodeBase58(keyWithPrefix)

	// V for verification (authentication)
	did := fmt.Sprintf("did:peer:2.V%s", encodedKey)

	if serviceEndpoint != "" {
		// Encode service as JSON
		service := map[string]interface{}{
			"t": "dm", // did-communication
			"s": serviceEndpoint,
			"r": []string{},             // routing keys
			"a": []string{"didcomm/v2"}, // accept
		}
		serviceJSON, _ := json.Marshal(service)
		serviceEncoded := "z" + encoding.EncodeBase58(serviceJSON)
		did += ".S" + serviceEncoded
	}

	return did, nil
}

// CreatePeerDid4 creates a did:peer:4 DID (short form with long form)
func CreatePeerDid4(didDoc *dids.DidDocument) (string, error) {
	if didDoc == nil {
		return "", fmt.Errorf("DID document cannot be nil")
	}

	// Convert the DID document to JSON
	docJSON, err := json.Marshal(didDoc)
	if err != nil {
		return "", fmt.Errorf("failed to marshal DID document: %w", err)
	}

	// Add multicodec prefix for JSON (0x0200)
	docWithPrefix := append([]byte{0x02, 0x00}, docJSON...)

	// Encode as base58btc multibase
	encodedDoc := "z" + encoding.EncodeBase58(docWithPrefix)

	// Calculate hash for short form
	hash := sha256.Sum256(docWithPrefix)
	hashEncoded := "z" + encoding.EncodeBase58(hash[:])

	did := fmt.Sprintf("did:peer:4%s:%s", hashEncoded, encodedDoc)

	return did, nil
}

// GetNumAlgoFromPeerDid extracts the numalgo from a peer DID
func GetNumAlgoFromPeerDid(did string) (PeerDidNumAlgo, error) {
	if !strings.HasPrefix(did, "did:peer:") {
		return 0, fmt.Errorf("not a peer DID: %s", did)
	}

	parts := strings.Split(did, ":")
	if len(parts) < 3 {
		return 0, fmt.Errorf("invalid peer DID format: %s", did)
	}

	// The character after "did:peer:" indicates the numalgo
	identifier := parts[2]
	if len(identifier) == 0 {
		return 0, fmt.Errorf("empty identifier in peer DID: %s", did)
	}

	switch identifier[0] {
	case '0':
		return PeerDidNumAlgo0, nil
	case '1':
		return PeerDidNumAlgo1, nil
	case '2':
		return PeerDidNumAlgo2, nil
	case '4':
		return PeerDidNumAlgo4, nil
	default:
		return 0, fmt.Errorf("unknown peer DID numalgo: %c", identifier[0])
	}
}

// CreatePeerDidDocument creates a DID document for a peer DID
func CreatePeerDidDocument(publicKey ed25519.PublicKey, serviceEndpoint string) *dids.DidDocument {
	tempDid := "did:peer:temp"

	keyId := "#key-1"
	verificationMethod := &dids.VerificationMethod{
		Id:              keyId,
		Type:            "Ed25519VerificationKey2018",
		Controller:      "#id",
		PublicKeyBase58: encoding.EncodeBase58(publicKey),
	}

	var services []*dids.Service
	if serviceEndpoint != "" {
		service := &dids.Service{
			Id:              "#inline-0",
			Type:            "did-communication",
			ServiceEndpoint: serviceEndpoint,
			RecipientKeys:   []string{keyId},
			RoutingKeys:     []string{},
		}
		// Priority is part of the service directly in our implementation
		services = append(services, service)
	}

	didDoc := &dids.DidDocument{
		Context:            []string{"https://w3id.org/did/v1"},
		Id:                 tempDid,
		VerificationMethod: []*dids.VerificationMethod{verificationMethod},
		Authentication: []dids.VerificationMethodRef{
			&dids.VerificationMethodRefEmbedded{Method: verificationMethod},
		},
		Service: services,
	}

	// Add key agreement for X25519 (derived from Ed25519)
	// This is a simplified version - in production you'd properly derive the X25519 key
	x25519VM := &dids.VerificationMethod{
		Id:              "#key-2",
		Type:            "X25519KeyAgreementKey2019",
		Controller:      "#id",
		PublicKeyBase58: encoding.EncodeBase58(publicKey), // This should be the X25519 key
	}
	didDoc.KeyAgreement = []dids.VerificationMethodRef{
		&dids.VerificationMethodRefEmbedded{Method: x25519VM},
	}

	return didDoc
}
