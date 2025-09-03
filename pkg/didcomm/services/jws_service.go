package services

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/core/common"
	"github.com/ajna-inc/essi/pkg/core/encoding"
	"github.com/ajna-inc/essi/pkg/core/wallet"
)

// JwsService handles JSON Web Signature operations
type JwsService struct {
	walletService *wallet.WalletService
}

// NewJwsService creates a new JWS service
func NewJwsService(walletService *wallet.WalletService) *JwsService {
	return &JwsService{
		walletService: walletService,
	}
}

// JwsHeader represents the JWS header
type JwsHeader struct {
	Alg string                 `json:"alg"`
	Kid string                 `json:"kid,omitempty"`
	Jwk map[string]interface{} `json:"jwk,omitempty"`
}

// Jws represents a JSON Web Signature
type Jws struct {
	Protected string                 `json:"protected"`
	Signature string                 `json:"signature"`
	Header    map[string]interface{} `json:"header"`
}

// CreateJwsOptions options for creating a JWS
type CreateJwsOptions struct {
	Payload                []byte
	KeyId                  string
	Header                 map[string]interface{}
	ProtectedHeaderOptions *JwsHeader
}

// CreateJws creates a JSON Web Signature
func (s *JwsService) CreateJws(ctx *context.AgentContext, options CreateJwsOptions) (*Jws, error) {
	// Get the signing key
	key, err := s.walletService.GetKey(options.KeyId)
	if err != nil {
		return nil, fmt.Errorf("failed to get signing key: %w", err)
	}

	if key.Type != wallet.KeyTypeEd25519 {
		return nil, fmt.Errorf("only Ed25519 keys are supported for JWS signing")
	}

	protectedHeader := JwsHeader{
		Alg: "EdDSA",
	}

	if options.ProtectedHeaderOptions != nil {
		if options.ProtectedHeaderOptions.Alg != "" {
			protectedHeader.Alg = options.ProtectedHeaderOptions.Alg
		}
		if options.ProtectedHeaderOptions.Kid != "" {
			protectedHeader.Kid = options.ProtectedHeaderOptions.Kid
		}
		if options.ProtectedHeaderOptions.Jwk != nil {
			// Create JWK from the public key
			protectedHeader.Jwk = map[string]interface{}{
				"kty": "OKP",
				"crv": "Ed25519",
				"x":   base64.RawURLEncoding.EncodeToString(key.PublicKey),
			}
		}
	}

	// Encode protected header
	protectedHeaderBytes, err := json.Marshal(protectedHeader)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal protected header: %w", err)
	}
	protectedHeaderB64 := base64.RawURLEncoding.EncodeToString(protectedHeaderBytes)

	payloadB64 := base64.RawURLEncoding.EncodeToString(options.Payload)
	signingInput := protectedHeaderB64 + "." + payloadB64

	// Sign with Ed25519
	signature := ed25519.Sign(key.PrivateKey, []byte(signingInput))
	signatureB64 := base64.RawURLEncoding.EncodeToString(signature)

	jws := &Jws{
		Protected: protectedHeaderB64,
		Signature: signatureB64,
		Header:    options.Header,
	}

	return jws, nil
}

// VerifyJws verifies a JSON Web Signature
func (s *JwsService) VerifyJws(ctx *context.AgentContext, jws *Jws, payload []byte) (bool, error) {
	// Decode protected header
	protectedBytes, err := base64.RawURLEncoding.DecodeString(jws.Protected)
	if err != nil {
		return false, fmt.Errorf("failed to decode protected header: %w", err)
	}

	var protectedHeader JwsHeader
	if err := json.Unmarshal(protectedBytes, &protectedHeader); err != nil {
		return false, fmt.Errorf("failed to unmarshal protected header: %w", err)
	}

	// Only support EdDSA for now
	if protectedHeader.Alg != "EdDSA" {
		return false, fmt.Errorf("unsupported algorithm: %s", protectedHeader.Alg)
	}

	// Get public key from JWK in protected header or from kid
	var publicKey []byte
	if protectedHeader.Jwk != nil {
		// Extract public key from JWK
		if x, ok := protectedHeader.Jwk["x"].(string); ok {
			publicKey, err = base64.RawURLEncoding.DecodeString(x)
			if err != nil {
				return false, fmt.Errorf("failed to decode public key from JWK: %w", err)
			}
		}
	} else if protectedHeader.Kid != "" {
		// Extract from did:key
		if strings.HasPrefix(protectedHeader.Kid, "did:key:") {
			// Extract public key from did:key
			multibaseKey := strings.TrimPrefix(protectedHeader.Kid, "did:key:")
			if strings.HasPrefix(multibaseKey, "z6Mk") {
				// Decode multibase base58btc
				decoded, err := encoding.DecodeBase58(multibaseKey[1:])
				if err != nil {
					return false, fmt.Errorf("failed to decode did:key: %w", err)
				}
				// Skip multicodec prefix (0xed 0x01 for Ed25519)
				if len(decoded) >= 34 && decoded[0] == 0xed && decoded[1] == 0x01 {
					publicKey = decoded[2:]
				} else {
					return false, fmt.Errorf("invalid Ed25519 did:key format")
				}
			}
		}
	}

	if len(publicKey) != ed25519.PublicKeySize {
		return false, fmt.Errorf("invalid public key size")
	}

	// Recreate signing input
	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)
	signingInput := jws.Protected + "." + payloadB64

	// Decode signature
	signature, err := base64.RawURLEncoding.DecodeString(jws.Signature)
	if err != nil {
		return false, fmt.Errorf("failed to decode signature: %w", err)
	}

	// Verify signature
	valid := ed25519.Verify(publicKey, []byte(signingInput), signature)
	return valid, nil
}

// AttachmentData represents attachment data with optional JWS
type AttachmentData struct {
	Base64 string `json:"base64,omitempty"`
	Jws    *Jws   `json:"jws,omitempty"`
}

// Attachment represents a DIDComm attachment
type Attachment struct {
	Id       string          `json:"@id"`
	MimeType string          `json:"mime-type,omitempty"`
	Data     *AttachmentData `json:"data"`
}

// CreateSignedAttachment creates a signed attachment for DID exchange
func (s *JwsService) CreateSignedAttachment(
	ctx *context.AgentContext,
	data interface{},
	signingKeyId string,
	invitationKey string, // The invitation recipient key (did:key format)
) (*Attachment, error) {
	// Convert data to bytes
	var payload []byte
	var mimeType string

	switch v := data.(type) {
	case string:
		payload = []byte(v)
		mimeType = ""
	case []byte:
		payload = v
		mimeType = ""
	default:
		// Assume it's a struct/map that needs JSON encoding
		jsonBytes, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal data: %w", err)
		}
		payload = jsonBytes
		mimeType = "application/json"
	}

	// Create JWS with the signing key
	jws, err := s.CreateJws(ctx, CreateJwsOptions{
		Payload: payload,
		KeyId:   signingKeyId,
		Header: map[string]interface{}{
			"kid": invitationKey, // Use the invitation key as kid
		},
		ProtectedHeaderOptions: &JwsHeader{
			Alg: "EdDSA",
			Jwk: map[string]interface{}{}, // Will be populated with public key
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create JWS: %w", err)
	}

	attachment := &Attachment{
		Id:       common.GenerateUUID(),
		MimeType: mimeType,
		Data: &AttachmentData{
			Base64: base64.StdEncoding.EncodeToString(payload),
			Jws:    jws,
		},
	}

	return attachment, nil
}
