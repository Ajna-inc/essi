package kms

import (
	"time"

	"github.com/Ajna-inc/askar-go"
)

// KeyType represents the type of cryptographic key
type KeyType string

const (
	KeyTypeEd25519   KeyType = "Ed25519"
	KeyTypeX25519    KeyType = "X25519"
	KeyTypeP256      KeyType = "P256"
	KeyTypeP384      KeyType = "P384"
	KeyTypeSecp256k1 KeyType = "K256"
	KeyTypeBls12381  KeyType = "Bls12381"
	KeyTypeAES128    KeyType = "AES128"
	KeyTypeAES256    KeyType = "AES256"
)

// SignatureAlgorithm represents signature algorithms
type SignatureAlgorithm string

const (
	SignatureAlgEdDSA  SignatureAlgorithm = "EdDSA"
	SignatureAlgES256  SignatureAlgorithm = "ES256"
	SignatureAlgES384  SignatureAlgorithm = "ES384"
	SignatureAlgES256K SignatureAlgorithm = "ES256K"
)

// Key represents a cryptographic key with metadata
type Key struct {
	ID          string             `json:"id"`
	Type        KeyType            `json:"type"`
	PublicKey   []byte             `json:"publicKey,omitempty"`
	Algorithm   askar.KeyAlgorithm `json:"algorithm"`
	CreatedAt   time.Time          `json:"createdAt"`
	UpdatedAt   time.Time          `json:"updatedAt"`
	Tags        map[string]string  `json:"tags,omitempty"`
}

// CreateKeyParams represents parameters for creating a new key
type CreateKeyParams struct {
	Type     KeyType           `json:"type"`
	Seed     []byte            `json:"seed,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// ImportKeyParams represents parameters for importing a key
type ImportKeyParams struct {
	Type       KeyType           `json:"type"`
	PrivateKey []byte            `json:"privateKey,omitempty"`
	PublicKey  []byte            `json:"publicKey,omitempty"`
	JWK        *JWK              `json:"jwk,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

// SignParams represents parameters for signing
type SignParams struct {
	KeyID     string             `json:"keyId"`
	Message   []byte             `json:"message"`
	Algorithm SignatureAlgorithm `json:"algorithm,omitempty"`
}

// VerifyParams represents parameters for verification
type VerifyParams struct {
	KeyID     string             `json:"keyId,omitempty"`
	PublicKey []byte             `json:"publicKey,omitempty"`
	Message   []byte             `json:"message"`
	Signature []byte             `json:"signature"`
	Algorithm SignatureAlgorithm `json:"algorithm,omitempty"`
}

// EncryptParams represents parameters for encryption
type EncryptParams struct {
	KeyID      string            `json:"keyId,omitempty"`
	PublicKey  []byte            `json:"publicKey,omitempty"`
	Plaintext  []byte            `json:"plaintext"`
	AAD        []byte            `json:"aad,omitempty"`
	Nonce      []byte            `json:"nonce,omitempty"`
	RecipientKeys [][]byte       `json:"recipientKeys,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

// DecryptParams represents parameters for decryption
type DecryptParams struct {
	KeyID      string `json:"keyId"`
	Ciphertext []byte `json:"ciphertext"`
	AAD        []byte `json:"aad,omitempty"`
	Nonce      []byte `json:"nonce,omitempty"`
	Tag        []byte `json:"tag,omitempty"`
}

// KeyAgreementParams represents parameters for key agreement
type KeyAgreementParams struct {
	MyKeyID    string  `json:"myKeyId"`
	TheirKey   []byte  `json:"theirKey"`
	Algorithm  string  `json:"algorithm,omitempty"`
}

// DeriveKeyParams represents parameters for key derivation
type DeriveKeyParams struct {
	SourceKeyID string `json:"sourceKeyId"`
	Algorithm   string `json:"algorithm"`
	Length      int    `json:"length"`
	Salt        []byte `json:"salt,omitempty"`
	Info        []byte `json:"info,omitempty"`
}

// JWK represents a JSON Web Key
type JWK struct {
	Kty string            `json:"kty"`
	Kid string            `json:"kid,omitempty"`
	Alg string            `json:"alg,omitempty"`
	Use string            `json:"use,omitempty"`
	
	// EC keys
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	D   string `json:"d,omitempty"`
	
	// RSA keys
	N string `json:"n,omitempty"`
	E string `json:"e,omitempty"`
	P string `json:"p,omitempty"`
	Q string `json:"q,omitempty"`
	
	// Symmetric keys
	K string `json:"k,omitempty"`
	
	// Additional fields
	Ext bool              `json:"ext,omitempty"`
	KeyOps []string       `json:"key_ops,omitempty"`
	X5c []string          `json:"x5c,omitempty"`
	X5t string            `json:"x5t,omitempty"`
	X5u string            `json:"x5u,omitempty"`
	X5tS256 string        `json:"x5t#S256,omitempty"`
}

// EncryptedData represents encrypted data with metadata
type EncryptedData struct {
	Ciphertext []byte            `json:"ciphertext"`
	Nonce      []byte            `json:"nonce,omitempty"`
	Tag        []byte            `json:"tag,omitempty"`
	AAD        []byte            `json:"aad,omitempty"`
	Recipients []Recipient       `json:"recipients,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

// Recipient represents an encryption recipient
type Recipient struct {
	KeyID         string `json:"keyId,omitempty"`
	EncryptedKey  []byte `json:"encryptedKey,omitempty"`
	Header        map[string]interface{} `json:"header,omitempty"`
}

// KeyAlgorithmMapping maps our KeyType to Askar KeyAlgorithm
var KeyAlgorithmMapping = map[KeyType]askar.KeyAlgorithm{
	KeyTypeEd25519:   askar.KeyAlgEd25519,
	KeyTypeX25519:    askar.KeyAlgX25519,
	KeyTypeP256:      askar.KeyAlgECP256,
	KeyTypeP384:      askar.KeyAlgECP384,
	KeyTypeSecp256k1: askar.KeyAlgECSecp256k1,
	KeyTypeBls12381:  askar.KeyAlgBls12381G1,
	KeyTypeAES128:    askar.KeyAlgAES128GCM,
	KeyTypeAES256:    askar.KeyAlgAES256GCM,
}

// SignatureAlgorithmMapping maps our SignatureAlgorithm to Askar SignatureAlgorithm
var SignatureAlgorithmMapping = map[SignatureAlgorithm]askar.SignatureAlgorithm{
	SignatureAlgEdDSA:  askar.SignatureAlgEdDSA,
	SignatureAlgES256:  askar.SignatureAlgES256,
	SignatureAlgES384:  askar.SignatureAlgES384,
	SignatureAlgES256K: askar.SignatureAlgES256K,
}

// GetAskarKeyAlgorithm converts KeyType to Askar KeyAlgorithm
func GetAskarKeyAlgorithm(keyType KeyType) (askar.KeyAlgorithm, error) {
	alg, ok := KeyAlgorithmMapping[keyType]
	if !ok {
		return "", &KeyError{
			Code:    "INVALID_KEY_TYPE",
			Message: "unsupported key type: " + string(keyType),
		}
	}
	return alg, nil
}

// GetAskarSignatureAlgorithm converts SignatureAlgorithm to Askar SignatureAlgorithm
func GetAskarSignatureAlgorithm(sigAlg SignatureAlgorithm) (askar.SignatureAlgorithm, error) {
	alg, ok := SignatureAlgorithmMapping[sigAlg]
	if !ok {
		return "", &KeyError{
			Code:    "INVALID_SIGNATURE_ALGORITHM",
			Message: "unsupported signature algorithm: " + string(sigAlg),
		}
	}
	return alg, nil
}

// KeyError represents a key management error
type KeyError struct {
	Code    string
	Message string
	Cause   error
}

func (e *KeyError) Error() string {
	if e.Cause != nil {
		return e.Message + ": " + e.Cause.Error()
	}
	return e.Message
}

func (e *KeyError) Unwrap() error {
	return e.Cause
}