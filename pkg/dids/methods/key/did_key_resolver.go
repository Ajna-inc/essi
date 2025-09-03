package key

import (
	"crypto/ed25519"
	"fmt"
	"strings"

	"github.com/ajna-inc/essi/pkg/core/context"
	dids "github.com/ajna-inc/essi/pkg/dids"
	"github.com/ajna-inc/essi/pkg/core/encoding"
)

// DidKeyResolver implements DID resolution for the did:key method
type DidKeyResolver struct {
	*dids.BaseDidResolver
}

// NewDidKeyResolver creates a new did:key resolver
func NewDidKeyResolver() *DidKeyResolver {
	return &DidKeyResolver{
		BaseDidResolver: dids.NewBaseDidResolver([]string{dids.MethodKey}),
	}
}

// Resolve resolves a did:key DID to a DID document
func (r *DidKeyResolver) Resolve(ctx *context.AgentContext, did string, options *dids.DidResolutionOptions) (*dids.DidResolutionResult, error) {
	// Parse the DID
	parsedDid := dids.TryParseDid(did)
	if parsedDid == nil {
		return r.CreateDidResolutionError(dids.DidResolutionErrorInvalidDid, "Invalid DID format"), nil
	}

	if parsedDid.Method != "key" {
		return r.CreateDidResolutionError(dids.DidResolutionErrorMethodNotSupported, "DID method not supported"), nil
	}

	// Extract the public key from the DID
	publicKey, keyType, err := r.extractPublicKeyFromDidKey(parsedDid.Id)
	if err != nil {
		return r.CreateDidResolutionError(dids.DidResolutionErrorInvalidDid, err.Error()), nil
	}

	// Create the DID document
	didDocument := r.createDidDocumentFromKey(did, publicKey, keyType)

	return r.CreateDidResolutionResult(didDocument), nil
}

// extractKeyFromDidKey extracts the key data from a did:key identifier
func extractKeyFromDidKey(methodSpecificId string) (*KeyData, error) {
	// did:key format: did:key:<multibase-encoded-key>
	// The key is encoded using multibase with base58btc encoding (z prefix)

	if !strings.HasPrefix(methodSpecificId, "z") {
		return nil, fmt.Errorf("did:key must use base58btc encoding (z prefix)")
	}

	// Decode base58btc (remove 'z' prefix and decode)
	keyBytes, err := encoding.DecodeBase58(methodSpecificId[1:])
	if err != nil {
		return nil, fmt.Errorf("failed to decode base58: %w", err)
	}

	// Parse multicodec prefix to determine key type
	keyData, err := parseMulticodecKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse multicodec key: %w", err)
	}

	return keyData, nil
}

// KeyData represents parsed key information
type KeyData struct {
	KeyType    string
	KeyBytes   []byte
	Multicodec uint64
}

// Common multicodec prefixes for cryptographic keys
const (
	Ed25519PublicKeyMulticodec   = 0xed // Ed25519 public key
	X25519PublicKeyMulticodec    = 0xec // X25519 public key (key agreement)
	Secp256k1PublicKeyMulticodec = 0xe7 // secp256k1 public key
)

// parseMulticodecKey parses a multicodec-encoded key
func parseMulticodecKey(data []byte) (*KeyData, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("key data too short")
	}

	// Read multicodec prefix (variable-length encoding)
	codec, bytesRead := readVarint(data)
	if bytesRead == 0 {
		return nil, fmt.Errorf("invalid multicodec prefix")
	}

	keyBytes := data[bytesRead:]

	var keyType string
	switch codec {
	case Ed25519PublicKeyMulticodec:
		keyType = dids.VerificationMethodTypeEd25519VerificationKey2020
		if len(keyBytes) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid Ed25519 key length: expected %d, got %d", ed25519.PublicKeySize, len(keyBytes))
		}
	case X25519PublicKeyMulticodec:
		keyType = dids.VerificationMethodTypeX25519KeyAgreementKey2019
		if len(keyBytes) != 32 {
			return nil, fmt.Errorf("invalid X25519 key length: expected 32, got %d", len(keyBytes))
		}
	case Secp256k1PublicKeyMulticodec:
		keyType = dids.VerificationMethodTypeEcdsaSecp256k1VerificationKey2019
		if len(keyBytes) != 33 {
			return nil, fmt.Errorf("invalid secp256k1 key length: expected 33, got %d", len(keyBytes))
		}
	default:
		return nil, fmt.Errorf("unsupported key type with multicodec: 0x%x", codec)
	}

	return &KeyData{
		KeyType:    keyType,
		KeyBytes:   keyBytes,
		Multicodec: codec,
	}, nil
}

// readVarint reads a variable-length integer from the beginning of data
func readVarint(data []byte) (uint64, int) {
	var result uint64
	var shift uint
	var bytesRead int

	for i, b := range data {
		if i > 8 { // Prevent overflow
			return 0, 0
		}

		result |= uint64(b&0x7F) << shift
		bytesRead++

		if b&0x80 == 0 {
			break
		}

		shift += 7
	}

	return result, bytesRead
}

// createDidDocumentFromKey creates a DID document from key data
func createDidDocumentFromKey(did string, keyData *KeyData) (*dids.DidDocument, error) {
	didDocument := dids.NewDidDocument(did)

	// Add security context for key types
	didDocument.AddContext(dids.SecurityContextV2)

	verificationMethodId := did + "#" + strings.TrimPrefix(did, "did:key:")

	verificationMethod := &dids.VerificationMethod{
		Id:         verificationMethodId,
		Type:       keyData.KeyType,
		Controller: did,
	}

	switch keyData.KeyType {
	case dids.VerificationMethodTypeEd25519VerificationKey2020:
		// Use multibase encoding for Ed25519
		verificationMethod.PublicKeyMultibase = "z" + encoding.EncodeBase58(keyData.KeyBytes)

	case dids.VerificationMethodTypeX25519KeyAgreementKey2019:
		// Use multibase encoding for X25519
		verificationMethod.PublicKeyMultibase = "z" + encoding.EncodeBase58(keyData.KeyBytes)

	case dids.VerificationMethodTypeEcdsaSecp256k1VerificationKey2019:
		// Use multibase encoding for secp256k1
		verificationMethod.PublicKeyMultibase = "z" + encoding.EncodeBase58(keyData.KeyBytes)

	default:
		return nil, fmt.Errorf("unsupported key type: %s", keyData.KeyType)
	}

	didDocument.AddVerificationMethod(verificationMethod)

	vmRef := dids.NewVerificationMethodRefString(verificationMethodId)

	// Add appropriate verification relationships based on key type
	switch keyData.KeyType {
	case dids.VerificationMethodTypeEd25519VerificationKey2020:
		// Ed25519 keys can be used for authentication, assertion, and capability invocation
		didDocument.AddAuthentication(vmRef)
		didDocument.AddAssertionMethod(vmRef)
		didDocument.AddCapabilityInvocation(vmRef)
		didDocument.AddCapabilityDelegation(vmRef)

	case dids.VerificationMethodTypeX25519KeyAgreementKey2019:
		// X25519 keys are used for key agreement
		didDocument.AddKeyAgreement(vmRef)

	case dids.VerificationMethodTypeEcdsaSecp256k1VerificationKey2019:
		// secp256k1 keys can be used for authentication and assertion
		didDocument.AddAuthentication(vmRef)
		didDocument.AddAssertionMethod(vmRef)
		didDocument.AddCapabilityInvocation(vmRef)
		didDocument.AddCapabilityDelegation(vmRef)
	}

	return didDocument, nil
}

// Utility functions for did:key creation

// CreateDidKeyFromEd25519PublicKey creates a did:key from an Ed25519 public key
func CreateDidKeyFromEd25519PublicKey(publicKey ed25519.PublicKey) (string, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return "", fmt.Errorf("invalid Ed25519 public key length")
	}

	// Create multicodec-encoded key
	multicodecKey := append([]byte{0xed, 0x01}, publicKey...)

	// Encode with multibase (base58btc)
	encoded := "z" + encoding.EncodeBase58(multicodecKey)

	return fmt.Sprintf("did:key:%s", encoded), nil
}

// CreateDidKeyFromX25519PublicKey creates a did:key from an X25519 public key
func CreateDidKeyFromX25519PublicKey(publicKey []byte) (string, error) {
	if len(publicKey) != 32 {
		return "", fmt.Errorf("invalid X25519 public key length")
	}

	// Create multicodec-encoded key
	multicodecKey := append([]byte{0xec, 0x01}, publicKey...)

	// Encode with multibase (base58btc)
	encoded := "z" + encoding.EncodeBase58(multicodecKey)

	return fmt.Sprintf("did:key:%s", encoded), nil
}

// CreateDidKeyFromSecp256k1PublicKey creates a did:key from a secp256k1 public key
func CreateDidKeyFromSecp256k1PublicKey(publicKey []byte) (string, error) {
	if len(publicKey) != 33 {
		return "", fmt.Errorf("invalid secp256k1 public key length")
	}

	// Create multicodec-encoded key
	multicodecKey := append([]byte{0xe7, 0x01}, publicKey...)

	// Encode with multibase (base58btc)
	encoded := "z" + encoding.EncodeBase58(multicodecKey)

	return fmt.Sprintf("did:key:%s", encoded), nil
}

// ExtractPublicKeyFromDidKey extracts the raw public key bytes from a did:key
func ExtractPublicKeyFromDidKey(didKey string) ([]byte, string, error) {
	parsedDid := dids.TryParseDid(didKey)
	if parsedDid == nil || parsedDid.Method != dids.MethodKey {
		return nil, "", fmt.Errorf("invalid did:key format")
	}

	keyData, err := extractKeyFromDidKey(parsedDid.Id)
	if err != nil {
		return nil, "", err
	}

	return keyData.KeyBytes, keyData.KeyType, nil
}

// ValidateDidKey validates a did:key DID
func ValidateDidKey(didKey string) error {
	parsedDid := dids.TryParseDid(didKey)
	if parsedDid == nil {
		return fmt.Errorf("invalid DID format")
	}

	if parsedDid.Method != dids.MethodKey {
		return fmt.Errorf("not a did:key DID")
	}

	// Try to extract and validate the key
	_, err := extractKeyFromDidKey(parsedDid.Id)
	if err != nil {
		return fmt.Errorf("invalid did:key: %w", err)
	}

	return nil
}

// extractPublicKeyFromDidKey extracts the public key and key type from a did:key
func (r *DidKeyResolver) extractPublicKeyFromDidKey(methodSpecificId string) ([]byte, string, error) {
	keyData, err := extractKeyFromDidKey(methodSpecificId)
	if err != nil {
		return nil, "", err
	}

	return keyData.KeyBytes, keyData.KeyType, nil
}

// createDidDocumentFromKey creates a DID document from a public key
func (r *DidKeyResolver) createDidDocumentFromKey(did string, publicKey []byte, keyType string) *dids.DidDocument {
	keyData := &KeyData{
		KeyType:  keyType,
		KeyBytes: publicKey,
	}

	didDocument, err := createDidDocumentFromKey(did, keyData)
	if err != nil {
		// Return minimal document on error
		return &dids.DidDocument{
			Context: []string{"https://w3id.org/did/v1"},
			Id:      did,
		}
	}

	return didDocument
}
