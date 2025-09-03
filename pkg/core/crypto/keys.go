package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
)

// KeyType represents different types of cryptographic keys
type KeyType string

const (
	KeyTypeEd25519   KeyType = "Ed25519"
	KeyTypeSecp256k1 KeyType = "Secp256k1"
	KeyTypeSecp256r1 KeyType = "Secp256r1" // P-256
	KeyTypeRSA       KeyType = "RSA"
	KeyTypeX25519    KeyType = "X25519"
	KeyTypeBLS12381  KeyType = "BLS12381"
)

// KeyUsage represents the intended usage of a key
type KeyUsage string

const (
	KeyUsageSignature      KeyUsage = "signature"
	KeyUsageEncryption     KeyUsage = "encryption"
	KeyUsageKeyAgreement   KeyUsage = "keyAgreement"
	KeyUsageVerification   KeyUsage = "verification"
	KeyUsageAuthentication KeyUsage = "authentication"
)

// Key represents a cryptographic key with metadata
type Key interface {
	// GetKeyType returns the type of the key
	GetKeyType() KeyType

	// GetKeyData returns the raw key data
	GetKeyData() []byte

	// GetPublicKey returns the public key component
	GetPublicKey() ([]byte, error)

	// GetPrivateKey returns the private key component
	GetPrivateKey() ([]byte, error)

	// HasPrivateKey returns true if this key contains private key material
	HasPrivateKey() bool

	// Sign signs data with this key (if it has private key material)
	Sign(data []byte) ([]byte, error)

	// Verify verifies a signature with this key's public component
	Verify(data, signature []byte) error

	// GetUsage returns the intended usage of this key
	GetUsage() []KeyUsage

	// GetKeyID returns a unique identifier for this key
	GetKeyID() string

	// ToJWK converts the key to JSON Web Key format
	ToJWK() (map[string]interface{}, error)
}

// KeyPair represents a public/private key pair
type KeyPair struct {
	KeyType    KeyType                `json:"keyType"`
	PublicKey  []byte                 `json:"publicKey"`
	PrivateKey []byte                 `json:"privateKey,omitempty"`
	Usage      []KeyUsage             `json:"usage"`
	KeyID      string                 `json:"keyId"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// NewKeyPair creates a new key pair
func NewKeyPair(keyType KeyType, publicKey, privateKey []byte, usage []KeyUsage) *KeyPair {
	return &KeyPair{
		KeyType:    keyType,
		PublicKey:  publicKey,
		PrivateKey: privateKey,
		Usage:      usage,
		KeyID:      generateKeyID(keyType, publicKey),
		Metadata:   make(map[string]interface{}),
	}
}

// GetKeyType returns the key type
func (kp *KeyPair) GetKeyType() KeyType {
	return kp.KeyType
}

// GetKeyData returns the public key data
func (kp *KeyPair) GetKeyData() []byte {
	return kp.PublicKey
}

// GetPublicKey returns the public key
func (kp *KeyPair) GetPublicKey() ([]byte, error) {
	return kp.PublicKey, nil
}

// GetPrivateKey returns the private key
func (kp *KeyPair) GetPrivateKey() ([]byte, error) {
	if len(kp.PrivateKey) == 0 {
		return nil, fmt.Errorf("private key not available")
	}
	return kp.PrivateKey, nil
}

// HasPrivateKey returns true if private key is available
func (kp *KeyPair) HasPrivateKey() bool {
	return len(kp.PrivateKey) > 0
}

// GetUsage returns the key usage
func (kp *KeyPair) GetUsage() []KeyUsage {
	return kp.Usage
}

// GetKeyID returns the key ID
func (kp *KeyPair) GetKeyID() string {
	return kp.KeyID
}

// Sign signs data with the private key
func (kp *KeyPair) Sign(data []byte) ([]byte, error) {
	if !kp.HasPrivateKey() {
		return nil, fmt.Errorf("private key not available for signing")
	}

	switch kp.KeyType {
	case KeyTypeEd25519:
		return kp.signEd25519(data)
	default:
		return nil, fmt.Errorf("signing not implemented for key type: %s", kp.KeyType)
	}
}

// Verify verifies a signature with the public key
func (kp *KeyPair) Verify(data, signature []byte) error {
	switch kp.KeyType {
	case KeyTypeEd25519:
		return kp.verifyEd25519(data, signature)
	default:
		return fmt.Errorf("verification not implemented for key type: %s", kp.KeyType)
	}
}

// ToJWK converts the key pair to JWK format
func (kp *KeyPair) ToJWK() (map[string]interface{}, error) {
	switch kp.KeyType {
	case KeyTypeEd25519:
		return kp.toEd25519JWK()
	default:
		return nil, fmt.Errorf("JWK conversion not implemented for key type: %s", kp.KeyType)
	}
}

// Private methods for Ed25519 operations
func (kp *KeyPair) signEd25519(data []byte) ([]byte, error) {
	if len(kp.PrivateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid Ed25519 private key size")
	}

	privateKey := ed25519.PrivateKey(kp.PrivateKey)
	signature := ed25519.Sign(privateKey, data)
	return signature, nil
}

func (kp *KeyPair) verifyEd25519(data, signature []byte) error {
	if len(kp.PublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid Ed25519 public key size")
	}

	publicKey := ed25519.PublicKey(kp.PublicKey)
	if !ed25519.Verify(publicKey, data, signature) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

func (kp *KeyPair) toEd25519JWK() (map[string]interface{}, error) {
	jwk := map[string]interface{}{
		"kty": "OKP",
		"crv": "Ed25519",
		"x":   encodeBase64URL(kp.PublicKey),
	}

	if kp.HasPrivateKey() {
		jwk["d"] = encodeBase64URL(kp.PrivateKey[:32]) // Ed25519 private key is first 32 bytes
	}

	if kp.KeyID != "" {
		jwk["kid"] = kp.KeyID
	}

	// Add key operations based on usage
	var keyOps []string
	for _, usage := range kp.Usage {
		switch usage {
		case KeyUsageSignature:
			keyOps = append(keyOps, "sign")
		case KeyUsageVerification:
			keyOps = append(keyOps, "verify")
		}
	}
	if len(keyOps) > 0 {
		jwk["key_ops"] = keyOps
	}

	return jwk, nil
}

// KeyGenerator provides methods for generating cryptographic keys
type KeyGenerator interface {
	// GenerateKeyPair generates a new key pair of the specified type
	GenerateKeyPair(keyType KeyType) (*KeyPair, error)

	// GenerateKeyPairWithSeed generates a key pair using a seed
	GenerateKeyPairWithSeed(keyType KeyType, seed []byte) (*KeyPair, error)

	// SupportedKeyTypes returns the list of supported key types
	SupportedKeyTypes() []KeyType
}

// DefaultKeyGenerator implements KeyGenerator
type DefaultKeyGenerator struct{}

// NewDefaultKeyGenerator creates a new default key generator
func NewDefaultKeyGenerator() *DefaultKeyGenerator {
	return &DefaultKeyGenerator{}
}

// GenerateKeyPair generates a new key pair
func (g *DefaultKeyGenerator) GenerateKeyPair(keyType KeyType) (*KeyPair, error) {
	switch keyType {
	case KeyTypeEd25519:
		return g.generateEd25519KeyPair()
	default:
		return nil, fmt.Errorf("key generation not supported for type: %s", keyType)
	}
}

// GenerateKeyPairWithSeed generates a key pair with a seed
func (g *DefaultKeyGenerator) GenerateKeyPairWithSeed(keyType KeyType, seed []byte) (*KeyPair, error) {
	switch keyType {
	case KeyTypeEd25519:
		return g.generateEd25519KeyPairWithSeed(seed)
	default:
		return nil, fmt.Errorf("seeded key generation not supported for type: %s", keyType)
	}
}

// SupportedKeyTypes returns supported key types
func (g *DefaultKeyGenerator) SupportedKeyTypes() []KeyType {
	return []KeyType{KeyTypeEd25519}
}

// generateEd25519KeyPair generates an Ed25519 key pair
func (g *DefaultKeyGenerator) generateEd25519KeyPair() (*KeyPair, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Ed25519 key pair: %w", err)
	}

	usage := []KeyUsage{KeyUsageSignature, KeyUsageVerification}
	return NewKeyPair(KeyTypeEd25519, publicKey, privateKey, usage), nil
}

// generateEd25519KeyPairWithSeed generates an Ed25519 key pair with seed
func (g *DefaultKeyGenerator) generateEd25519KeyPairWithSeed(seed []byte) (*KeyPair, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("Ed25519 seed must be %d bytes", ed25519.SeedSize)
	}

	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)

	usage := []KeyUsage{KeyUsageSignature, KeyUsageVerification}
	return NewKeyPair(KeyTypeEd25519, publicKey, privateKey, usage), nil
}

// Helper functions
func generateKeyID(keyType KeyType, publicKey []byte) string {
	// Generate a deterministic key ID based on key type and public key
	hash := sha256.New()
	hash.Write([]byte(keyType))
	hash.Write(publicKey)
	keyHash := hash.Sum(nil)
	return fmt.Sprintf("%s_%x", keyType, keyHash[:8])
}

// Base64URL encoding without padding (for JWK)
func encodeBase64URL(data []byte) string {
	// This is a placeholder - should use the utils.EncodeBase64URL function
	// For now, implementing inline to avoid circular imports
	const base64URLAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

	// Simple base64url encoding implementation
	result := ""
	for i := 0; i < len(data); i += 3 {
		b1, b2, b3 := data[i], byte(0), byte(0)
		if i+1 < len(data) {
			b2 = data[i+1]
		}
		if i+2 < len(data) {
			b3 = data[i+2]
		}

		n := (uint32(b1) << 16) | (uint32(b2) << 8) | uint32(b3)

		result += string(base64URLAlphabet[(n>>18)&63])
		result += string(base64URLAlphabet[(n>>12)&63])
		if i+1 < len(data) {
			result += string(base64URLAlphabet[(n>>6)&63])
		}
		if i+2 < len(data) {
			result += string(base64URLAlphabet[n&63])
		}
	}

	return result
}
