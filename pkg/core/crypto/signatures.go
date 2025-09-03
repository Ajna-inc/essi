package crypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
)

// SignatureAlgorithm represents different signature algorithms
type SignatureAlgorithm string

const (
	SignatureEd25519   SignatureAlgorithm = "Ed25519"
	SignatureES256     SignatureAlgorithm = "ES256"     // ECDSA P-256 + SHA256
	SignatureES384     SignatureAlgorithm = "ES384"     // ECDSA P-384 + SHA384
	SignatureES512     SignatureAlgorithm = "ES512"     // ECDSA P-521 + SHA512
	SignatureRS256     SignatureAlgorithm = "RS256"     // RSA + SHA256
	SignaturePS256     SignatureAlgorithm = "PS256"     // RSA-PSS + SHA256
	SignatureSecp256k1 SignatureAlgorithm = "Secp256k1" // Bitcoin/Ethereum curve
)

// Signer provides methods for digital signatures
type Signer interface {
	// Sign signs the given data
	Sign(data []byte) (*Signature, error)

	// GetAlgorithm returns the signature algorithm
	GetAlgorithm() SignatureAlgorithm

	// GetPublicKey returns the public key for verification
	GetPublicKey() ([]byte, error)
}

// Verifier provides methods for signature verification
type Verifier interface {
	// Verify verifies a signature against data
	Verify(data []byte, signature *Signature) error

	// GetAlgorithm returns the signature algorithm
	GetAlgorithm() SignatureAlgorithm

	// GetPublicKey returns the public key used for verification
	GetPublicKey() ([]byte, error)
}

// Signature represents a digital signature
type Signature struct {
	Algorithm SignatureAlgorithm `json:"algorithm"`
	Value     []byte             `json:"value"`
	R         *big.Int           `json:"r,omitempty"` // For ECDSA signatures
	S         *big.Int           `json:"s,omitempty"` // For ECDSA signatures
}

// NewSignature creates a new signature
func NewSignature(algorithm SignatureAlgorithm, value []byte) *Signature {
	return &Signature{
		Algorithm: algorithm,
		Value:     value,
	}
}

// NewECDSASignature creates a new ECDSA signature with R and S components
func NewECDSASignature(algorithm SignatureAlgorithm, r, s *big.Int) *Signature {
	return &Signature{
		Algorithm: algorithm,
		R:         r,
		S:         s,
	}
}

// Ed25519Signer implements Signer for Ed25519
type Ed25519Signer struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
}

// NewEd25519Signer creates a new Ed25519 signer
func NewEd25519Signer(privateKey ed25519.PrivateKey) *Ed25519Signer {
	publicKey := privateKey.Public().(ed25519.PublicKey)
	return &Ed25519Signer{
		privateKey: privateKey,
		publicKey:  publicKey,
	}
}

// Sign signs data with Ed25519
func (s *Ed25519Signer) Sign(data []byte) (*Signature, error) {
	signature := ed25519.Sign(s.privateKey, data)
	return NewSignature(SignatureEd25519, signature), nil
}

// GetAlgorithm returns the signature algorithm
func (s *Ed25519Signer) GetAlgorithm() SignatureAlgorithm {
	return SignatureEd25519
}

// GetPublicKey returns the public key
func (s *Ed25519Signer) GetPublicKey() ([]byte, error) {
	return s.publicKey, nil
}

// Ed25519Verifier implements Verifier for Ed25519
type Ed25519Verifier struct {
	publicKey ed25519.PublicKey
}

// NewEd25519Verifier creates a new Ed25519 verifier
func NewEd25519Verifier(publicKey ed25519.PublicKey) *Ed25519Verifier {
	return &Ed25519Verifier{
		publicKey: publicKey,
	}
}

// Verify verifies an Ed25519 signature
func (v *Ed25519Verifier) Verify(data []byte, signature *Signature) error {
	if signature.Algorithm != SignatureEd25519 {
		return fmt.Errorf("algorithm mismatch: expected %s, got %s", SignatureEd25519, signature.Algorithm)
	}

	if !ed25519.Verify(v.publicKey, data, signature.Value) {
		return fmt.Errorf("Ed25519 signature verification failed")
	}

	return nil
}

// GetAlgorithm returns the signature algorithm
func (v *Ed25519Verifier) GetAlgorithm() SignatureAlgorithm {
	return SignatureEd25519
}

// GetPublicKey returns the public key
func (v *Ed25519Verifier) GetPublicKey() ([]byte, error) {
	return v.publicKey, nil
}

// ECDSASigner implements Signer for ECDSA
type ECDSASigner struct {
	privateKey *ecdsa.PrivateKey
	algorithm  SignatureAlgorithm
	curve      elliptic.Curve
}

// NewECDSASignerP256 creates a new ECDSA signer for P-256 curve
func NewECDSASignerP256(privateKey *ecdsa.PrivateKey) *ECDSASigner {
	return &ECDSASigner{
		privateKey: privateKey,
		algorithm:  SignatureES256,
		curve:      elliptic.P256(),
	}
}

// NewECDSASignerP384 creates a new ECDSA signer for P-384 curve
func NewECDSASignerP384(privateKey *ecdsa.PrivateKey) *ECDSASigner {
	return &ECDSASigner{
		privateKey: privateKey,
		algorithm:  SignatureES384,
		curve:      elliptic.P384(),
	}
}

// NewECDSASignerP521 creates a new ECDSA signer for P-521 curve
func NewECDSASignerP521(privateKey *ecdsa.PrivateKey) *ECDSASigner {
	return &ECDSASigner{
		privateKey: privateKey,
		algorithm:  SignatureES512,
		curve:      elliptic.P521(),
	}
}

// Sign signs data with ECDSA
func (s *ECDSASigner) Sign(data []byte) (*Signature, error) {
	// Hash the data based on the algorithm
	var hash []byte
	switch s.algorithm {
	case SignatureES256:
		h := sha256.Sum256(data)
		hash = h[:]
	default:
		return nil, fmt.Errorf("unsupported ECDSA algorithm: %s", s.algorithm)
	}

	r, sVal, err := ecdsa.Sign(rand.Reader, s.privateKey, hash)
	if err != nil {
		return nil, fmt.Errorf("ECDSA signing failed: %w", err)
	}

	return NewECDSASignature(s.algorithm, r, sVal), nil
}

// GetAlgorithm returns the signature algorithm
func (s *ECDSASigner) GetAlgorithm() SignatureAlgorithm {
	return s.algorithm
}

// GetPublicKey returns the public key in uncompressed format
func (s *ECDSASigner) GetPublicKey() ([]byte, error) {
	return elliptic.Marshal(s.curve, s.privateKey.PublicKey.X, s.privateKey.PublicKey.Y), nil
}

// ECDSAVerifier implements Verifier for ECDSA
type ECDSAVerifier struct {
	publicKey *ecdsa.PublicKey
	algorithm SignatureAlgorithm
	curve     elliptic.Curve
}

// NewECDSAVerifierP256 creates a new ECDSA verifier for P-256 curve
func NewECDSAVerifierP256(publicKey *ecdsa.PublicKey) *ECDSAVerifier {
	return &ECDSAVerifier{
		publicKey: publicKey,
		algorithm: SignatureES256,
		curve:     elliptic.P256(),
	}
}

// Verify verifies an ECDSA signature
func (v *ECDSAVerifier) Verify(data []byte, signature *Signature) error {
	if signature.Algorithm != v.algorithm {
		return fmt.Errorf("algorithm mismatch: expected %s, got %s", v.algorithm, signature.Algorithm)
	}

	if signature.R == nil || signature.S == nil {
		return fmt.Errorf("missing R or S components in ECDSA signature")
	}

	// Hash the data based on the algorithm
	var hash []byte
	switch v.algorithm {
	case SignatureES256:
		h := sha256.Sum256(data)
		hash = h[:]
	default:
		return fmt.Errorf("unsupported ECDSA algorithm: %s", v.algorithm)
	}

	if !ecdsa.Verify(v.publicKey, hash, signature.R, signature.S) {
		return fmt.Errorf("ECDSA signature verification failed")
	}

	return nil
}

// GetAlgorithm returns the signature algorithm
func (v *ECDSAVerifier) GetAlgorithm() SignatureAlgorithm {
	return v.algorithm
}

// GetPublicKey returns the public key in uncompressed format
func (v *ECDSAVerifier) GetPublicKey() ([]byte, error) {
	return elliptic.Marshal(v.curve, v.publicKey.X, v.publicKey.Y), nil
}

// SignatureUtils provides utility functions for signatures
type SignatureUtils struct{}

// NewSignatureUtils creates a new signature utilities instance
func NewSignatureUtils() *SignatureUtils {
	return &SignatureUtils{}
}

// CreateSigner creates a signer for the given key and algorithm
func (su *SignatureUtils) CreateSigner(keyPair *KeyPair) (Signer, error) {
	switch keyPair.KeyType {
	case KeyTypeEd25519:
		if !keyPair.HasPrivateKey() {
			return nil, fmt.Errorf("private key required for signing")
		}
		privateKey := ed25519.PrivateKey(keyPair.PrivateKey)
		return NewEd25519Signer(privateKey), nil
	case KeyTypeSecp256r1:
		return su.createECDSASignerP256(keyPair)
	default:
		return nil, fmt.Errorf("unsupported key type for signing: %s", keyPair.KeyType)
	}
}

// CreateVerifier creates a verifier for the given key and algorithm
func (su *SignatureUtils) CreateVerifier(keyPair *KeyPair) (Verifier, error) {
	switch keyPair.KeyType {
	case KeyTypeEd25519:
		publicKey := ed25519.PublicKey(keyPair.PublicKey)
		return NewEd25519Verifier(publicKey), nil
	case KeyTypeSecp256r1:
		return su.createECDSAVerifierP256(keyPair)
	default:
		return nil, fmt.Errorf("unsupported key type for verification: %s", keyPair.KeyType)
	}
}

// createECDSASignerP256 creates an ECDSA signer for P-256
func (su *SignatureUtils) createECDSASignerP256(keyPair *KeyPair) (Signer, error) {
	if !keyPair.HasPrivateKey() {
		return nil, fmt.Errorf("private key required for signing")
	}

	// Parse ECDSA private key from raw bytes
	privateKey, err := su.parseECDSAPrivateKeyP256(keyPair.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ECDSA private key: %w", err)
	}

	return NewECDSASignerP256(privateKey), nil
}

// createECDSAVerifierP256 creates an ECDSA verifier for P-256
func (su *SignatureUtils) createECDSAVerifierP256(keyPair *KeyPair) (Verifier, error) {
	// Parse ECDSA public key from raw bytes
	publicKey, err := su.parseECDSAPublicKeyP256(keyPair.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ECDSA public key: %w", err)
	}

	return NewECDSAVerifierP256(publicKey), nil
}

// parseECDSAPrivateKeyP256 parses an ECDSA private key for P-256
func (su *SignatureUtils) parseECDSAPrivateKeyP256(privateKeyBytes []byte) (*ecdsa.PrivateKey, error) {
	if len(privateKeyBytes) != 32 {
		return nil, fmt.Errorf("P-256 private key must be 32 bytes")
	}

	curve := elliptic.P256()
	d := new(big.Int).SetBytes(privateKeyBytes)

	privateKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
		},
		D: d,
	}

	// Calculate public key
	privateKey.PublicKey.X, privateKey.PublicKey.Y = curve.ScalarBaseMult(privateKeyBytes)

	return privateKey, nil
}

// parseECDSAPublicKeyP256 parses an ECDSA public key for P-256
func (su *SignatureUtils) parseECDSAPublicKeyP256(publicKeyBytes []byte) (*ecdsa.PublicKey, error) {
	curve := elliptic.P256()

	// Uncompressed format: 0x04 + X (32 bytes) + Y (32 bytes)
	if len(publicKeyBytes) == 65 && publicKeyBytes[0] == 0x04 {
		x := new(big.Int).SetBytes(publicKeyBytes[1:33])
		y := new(big.Int).SetBytes(publicKeyBytes[33:65])

		return &ecdsa.PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		}, nil
	}

	// Compressed format or other formats
	x, y := elliptic.Unmarshal(curve, publicKeyBytes)
	if x == nil || y == nil {
		return nil, fmt.Errorf("invalid ECDSA public key format")
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}

// GenerateECDSAKeyPairP256 generates a new ECDSA key pair for P-256
func (su *SignatureUtils) GenerateECDSAKeyPairP256() (*KeyPair, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECDSA key pair: %w", err)
	}

	// Extract private key bytes (32 bytes for P-256)
	privateKeyBytes := privateKey.D.Bytes()
	if len(privateKeyBytes) < 32 {
		// Pad with leading zeros if necessary
		padded := make([]byte, 32)
		copy(padded[32-len(privateKeyBytes):], privateKeyBytes)
		privateKeyBytes = padded
	}

	// Extract public key bytes (uncompressed format)
	publicKeyBytes := elliptic.Marshal(elliptic.P256(), privateKey.PublicKey.X, privateKey.PublicKey.Y)

	usage := []KeyUsage{KeyUsageSignature, KeyUsageVerification}
	return NewKeyPair(KeyTypeSecp256r1, publicKeyBytes, privateKeyBytes, usage), nil
}

// VerifySignature is a convenience function to verify a signature
func VerifySignature(data []byte, signature *Signature, publicKey []byte, keyType KeyType) error {
	// Create a temporary key pair for verification
	keyPair := &KeyPair{
		KeyType:   keyType,
		PublicKey: publicKey,
	}

	utils := NewSignatureUtils()
	verifier, err := utils.CreateVerifier(keyPair)
	if err != nil {
		return fmt.Errorf("failed to create verifier: %w", err)
	}

	return verifier.Verify(data, signature)
}

// SignData is a convenience function to sign data
func SignData(data []byte, keyPair *KeyPair) (*Signature, error) {
	utils := NewSignatureUtils()
	signer, err := utils.CreateSigner(keyPair)
	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %w", err)
	}

	return signer.Sign(data)
}
