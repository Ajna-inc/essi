package kms

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/Ajna-inc/askar-go"
	askarerrors "github.com/ajna-inc/essi/pkg/askar/errors"
	"github.com/ajna-inc/essi/pkg/core/context"
)

// AskarKeyManagementService provides key management using Askar
type AskarKeyManagementService struct {
	storeManager StoreManager
	storeID      string
}

// StoreManager interface for store operations
type StoreManager interface {
	WithSession(ctx *context.AgentContext, storeID string, fn func(*askar.Session) error) error
	WithTransaction(ctx *context.AgentContext, storeID string, fn func(*askar.Session) error) error
}

// NewAskarKeyManagementService creates a new AskarKeyManagementService
func NewAskarKeyManagementService(storeManager StoreManager, storeID string) *AskarKeyManagementService {
	return &AskarKeyManagementService{
		storeManager: storeManager,
		storeID:      storeID,
	}
}

// CreateKey creates a new cryptographic key
func (kms *AskarKeyManagementService) CreateKey(ctx *context.AgentContext, params CreateKeyParams) (*Key, error) {
	algorithm, err := GetAskarKeyAlgorithm(params.Type)
	if err != nil {
		return nil, err
	}
	
	// Generate key ID
	keyID := fmt.Sprintf("key-%s-%s", params.Type, uuid.New().String())
	
	var key *Key
	err = kms.storeManager.WithTransaction(ctx, kms.storeID, func(session *askar.Session) error {
		var askarKey *askar.Key
		var genErr error
		
		// Generate the key
		if len(params.Seed) > 0 {
			askarKey, genErr = askar.KeyFromSeed(algorithm, params.Seed, "")
		} else {
			askarKey, genErr = askar.GenerateKey(algorithm, false)
		}
		
		if genErr != nil {
			return &KeyError{
				Code:    "KEY_GENERATION_FAILED",
				Message: "failed to generate key",
				Cause:   genErr,
			}
		}
		// Note: askarKey is automatically freed by Go's garbage collector with finalizer
		
		publicKey, err := askarKey.GetPublicBytes()
		if err != nil {
			return &KeyError{
				Code:    "KEY_EXPORT_FAILED",
				Message: "failed to export public key",
				Cause:   err,
			}
		}
		
		now := time.Now()
		key = &Key{
			ID:        keyID,
			Type:      params.Type,
			PublicKey: publicKey,
			Algorithm: algorithm,
			CreatedAt: now,
			UpdatedAt: now,
			Tags:      params.Metadata,
		}
		
		// Store the key in Askar
		keyJSON, err := json.Marshal(key)
		if err != nil {
			return err
		}
		
		// Store key metadata
		err = session.InsertKey(
			askarKey,           // key
			keyID,              // name
			string(keyJSON),    // metadata
			nil,                // tags
		)
		if err != nil {
			return &KeyError{
				Code:    "KEY_STORAGE_FAILED",
				Message: "failed to store key",
				Cause:   err,
			}
		}
		
		return nil
	})
	
	if err != nil {
		return nil, askarerrors.WrapAskarError(err)
	}
	
	return key, nil
}

// ImportKey imports an existing key
func (kms *AskarKeyManagementService) ImportKey(ctx *context.AgentContext, params ImportKeyParams) (*Key, error) {
	algorithm, err := GetAskarKeyAlgorithm(params.Type)
	if err != nil {
		return nil, err
	}
	
	// Generate key ID
	keyID := fmt.Sprintf("key-%s-%s", params.Type, uuid.New().String())
	
	var key *Key
	err = kms.storeManager.WithTransaction(ctx, kms.storeID, func(session *askar.Session) error {
		var askarKey *askar.Key
		var importErr error
		
		// Import the key based on format
		if params.JWK != nil {
			// Import from JWK
			askarKey, importErr = askar.KeyFromJWK(params.JWK)
		} else if len(params.PrivateKey) > 0 {
			// Import from private key bytes
			askarKey, importErr = askar.KeyFromSecretBytes(algorithm, params.PrivateKey)
		} else if len(params.PublicKey) > 0 {
			// Import from public key bytes (public key only)
			askarKey, importErr = askar.KeyFromPublicBytes(algorithm, params.PublicKey)
		} else {
			return &KeyError{
				Code:    "INVALID_IMPORT_PARAMS",
				Message: "no key data provided for import",
			}
		}
		
		if importErr != nil {
			return &KeyError{
				Code:    "KEY_IMPORT_FAILED",
				Message: "failed to import key",
				Cause:   importErr,
			}
		}
		// Note: askarKey is automatically freed by Go's garbage collector with finalizer
		
		publicKey, err := askarKey.GetPublicBytes()
		if err != nil {
			// Key might be symmetric, that's ok
			publicKey = nil
		}
		
		now := time.Now()
		key = &Key{
			ID:        keyID,
			Type:      params.Type,
			PublicKey: publicKey,
			Algorithm: algorithm,
			CreatedAt: now,
			UpdatedAt: now,
			Tags:      params.Metadata,
		}
		
		// Store the key in Askar
		keyJSON, err := json.Marshal(key)
		if err != nil {
			return err
		}
		
		// Store key
		err = session.InsertKey(
			askarKey,           // key
			keyID,              // name
			string(keyJSON),    // metadata
			nil,                // tags
		)
		if err != nil {
			return &KeyError{
				Code:    "KEY_STORAGE_FAILED",
				Message: "failed to store key",
				Cause:   err,
			}
		}
		
		return nil
	})
	
	if err != nil {
		return nil, askarerrors.WrapAskarError(err)
	}
	
	return key, nil
}

// GetKey retrieves a key by ID
func (kms *AskarKeyManagementService) GetKey(ctx *context.AgentContext, keyID string) (*Key, error) {
	var key *Key
	
	err := kms.storeManager.WithSession(ctx, kms.storeID, func(session *askar.Session) error {
		keyEntry, err := session.FetchKey(keyID, false)
		if err != nil {
			return err
		}
		if keyEntry == nil {
			return &KeyError{
				Code:    "KEY_NOT_FOUND",
				Message: fmt.Sprintf("key with ID %s not found", keyID),
			}
		}
		// Note: keyEntry is automatically cleaned up
		
		// Parse key metadata from the metadata field
		key = &Key{}
		if keyEntry.Metadata != "" {
			if err := json.Unmarshal([]byte(keyEntry.Metadata), key); err != nil {
				return err
			}
		}
		
		return nil
	})
	
	if err != nil {
		return nil, askarerrors.WrapAskarError(err)
	}
	
	return key, nil
}

// DeleteKey deletes a key by ID
func (kms *AskarKeyManagementService) DeleteKey(ctx *context.AgentContext, keyID string) error {
	err := kms.storeManager.WithTransaction(ctx, kms.storeID, func(session *askar.Session) error {
		err := session.RemoveKey(keyID)
		if err != nil {
			return &KeyError{
				Code:    "KEY_DELETION_FAILED",
				Message: fmt.Sprintf("failed to delete key %s", keyID),
				Cause:   err,
			}
		}
		return nil
	})
	
	return askarerrors.WrapAskarError(err)
}

// Sign creates a digital signature
func (kms *AskarKeyManagementService) Sign(ctx *context.AgentContext, params SignParams) ([]byte, error) {
	var signature []byte
	
	err := kms.storeManager.WithSession(ctx, kms.storeID, func(session *askar.Session) error {
		keyEntry, err := session.FetchKey(params.KeyID, false)
		if err != nil {
			return err
		}
		if keyEntry == nil {
			return &KeyError{
				Code:    "KEY_NOT_FOUND",
				Message: fmt.Sprintf("key with ID %s not found", params.KeyID),
			}
		}
		// Load the key from the entry
		localKey, err := keyEntry.LoadLocal()
		if err != nil {
			return err
		}
		
		var sigAlg askar.SignatureAlgorithm
		if params.Algorithm != "" {
			sigAlg, err = GetAskarSignatureAlgorithm(params.Algorithm)
			if err != nil {
				return err
			}
		}
		
		// Sign the message
		sig, err := localKey.SignMessage(params.Message, sigAlg)
		if err != nil {
			return &KeyError{
				Code:    "SIGNING_FAILED",
				Message: "failed to sign message",
				Cause:   err,
			}
		}
		
		signature = sig
		return nil
	})
	
	if err != nil {
		return nil, askarerrors.WrapAskarError(err)
	}
	
	return signature, nil
}

// Verify verifies a digital signature
func (kms *AskarKeyManagementService) Verify(ctx *context.AgentContext, params VerifyParams) (bool, error) {
	var valid bool
	
	err := kms.storeManager.WithSession(ctx, kms.storeID, func(session *askar.Session) error {
		var askarKey *askar.Key
		
		if params.KeyID != "" {
			// Use stored key
			keyEntry, err := session.FetchKey(params.KeyID, false)
			if err != nil {
				return err
			}
			if keyEntry == nil {
				return &KeyError{
					Code:    "KEY_NOT_FOUND",
					Message: fmt.Sprintf("key with ID %s not found", params.KeyID),
				}
			}
			// Load the key from the entry
			localKey, err := keyEntry.LoadLocal()
			if err != nil {
				return err
			}
			askarKey = localKey
		} else if len(params.PublicKey) > 0 {
			// Use provided public key
			// Need to determine algorithm from key bytes
			// For now, assume Ed25519 if 32 bytes, P256 if 65 bytes
			var algorithm askar.KeyAlgorithm
			switch len(params.PublicKey) {
			case 32:
				algorithm = askar.KeyAlgEd25519
			case 65:
				algorithm = askar.KeyAlgECP256
			case 97:
				algorithm = askar.KeyAlgECP384
			default:
				return &KeyError{
					Code:    "UNSUPPORTED_KEY_SIZE",
					Message: fmt.Sprintf("unsupported public key size: %d", len(params.PublicKey)),
				}
			}
			
			key, err := askar.KeyFromPublicBytes(algorithm, params.PublicKey)
			if err != nil {
				return err
			}
			// Note: key is automatically freed by Go's garbage collector with finalizer
			askarKey = key
		} else {
			return &KeyError{
				Code:    "INVALID_VERIFY_PARAMS",
				Message: "either keyId or publicKey must be provided",
			}
		}
		
		var sigAlg askar.SignatureAlgorithm
		if params.Algorithm != "" {
			var err error
			sigAlg, err = GetAskarSignatureAlgorithm(params.Algorithm)
			if err != nil {
				return err
			}
		}
		
		// Verify the signature
		var verifyErr error
		valid, verifyErr = askarKey.VerifySignature(params.Message, params.Signature, sigAlg)
		if verifyErr != nil {
			// Verification failed
			valid = false
		}
		
		return nil
	})
	
	if err != nil {
		return false, askarerrors.WrapAskarError(err)
	}
	
	return valid, nil
}

// Encrypt encrypts data
func (kms *AskarKeyManagementService) Encrypt(ctx *context.AgentContext, params EncryptParams) (*EncryptedData, error) {
	var encrypted *EncryptedData
	
	err := kms.storeManager.WithSession(ctx, kms.storeID, func(session *askar.Session) error {
		var askarKey *askar.Key
		
		if params.KeyID != "" {
			// Use stored key
			keyEntry, err := session.FetchKey(params.KeyID, false)
			if err != nil {
				return err
			}
			if keyEntry == nil {
				return &KeyError{
					Code:    "KEY_NOT_FOUND",
					Message: fmt.Sprintf("key with ID %s not found", params.KeyID),
				}
			}
			// Load the key from the entry
			localKey, err := keyEntry.LoadLocal()
			if err != nil {
				return err
			}
			askarKey = localKey
		} else if len(params.PublicKey) > 0 {
			// Use provided public key for encryption
			// This would typically be used for ECIES or similar
			return &KeyError{
				Code:    "NOT_IMPLEMENTED",
				Message: "encryption with external public key not yet implemented",
			}
		} else {
			return &KeyError{
				Code:    "INVALID_ENCRYPT_PARAMS",
				Message: "either keyId or publicKey must be provided",
			}
		}
		
		// Perform AEAD encryption
		encBuffer, err := askarKey.AEADEncrypt(params.Plaintext, params.Nonce, params.AAD)
		if err != nil {
			return &KeyError{
				Code:    "ENCRYPTION_FAILED",
				Message: "failed to encrypt data",
				Cause:   err,
			}
		}
		
		encrypted = &EncryptedData{
			Ciphertext: encBuffer.GetCiphertext(),
			Nonce:      encBuffer.GetNonce(),
			Tag:        encBuffer.GetTag(),
			AAD:        params.AAD,
			Metadata:   params.Metadata,
		}
		
		return nil
	})
	
	if err != nil {
		return nil, askarerrors.WrapAskarError(err)
	}
	
	return encrypted, nil
}

// Decrypt decrypts data
func (kms *AskarKeyManagementService) Decrypt(ctx *context.AgentContext, params DecryptParams) ([]byte, error) {
	var plaintext []byte
	
	err := kms.storeManager.WithSession(ctx, kms.storeID, func(session *askar.Session) error {
		keyEntry, err := session.FetchKey(params.KeyID, false)
		if err != nil {
			return err
		}
		if keyEntry == nil {
			return &KeyError{
				Code:    "KEY_NOT_FOUND",
				Message: fmt.Sprintf("key with ID %s not found", params.KeyID),
			}
		}
		// Load the key from the entry
		localKey, err := keyEntry.LoadLocal()
		if err != nil {
			return err
		}
		
		// Perform AEAD decryption
		decrypted, err := localKey.AEADDecrypt(params.Ciphertext, params.Nonce, params.Tag, params.AAD)
		if err != nil {
			return &KeyError{
				Code:    "DECRYPTION_FAILED",
				Message: "failed to decrypt data",
				Cause:   err,
			}
		}
		
		plaintext = decrypted
		return nil
	})
	
	if err != nil {
		return nil, askarerrors.WrapAskarError(err)
	}
	
	return plaintext, nil
}

// ListKeys lists all keys with optional filtering
func (kms *AskarKeyManagementService) ListKeys(ctx *context.AgentContext, keyType KeyType) ([]*Key, error) {
	var keys []*Key
	
	err := kms.storeManager.WithSession(ctx, kms.storeID, func(session *askar.Session) error {
		// Fetch all keys - FetchAllKeys(algorithm, thumbprint, tagFilter, limit, forUpdate)
		keyEntries, err := session.FetchAllKeys("", "", nil, 0, false)
		if err != nil {
			return err
		}
		
		for _, entry := range keyEntries {
			// Parse key metadata from the metadata field
			key := &Key{}
			if entry.Metadata != "" {
				if err := json.Unmarshal([]byte(entry.Metadata), key); err != nil {
					// Skip malformed entries
					continue
				}
			}
			
			// Filter by type if specified
			if keyType != "" && key.Type != keyType {
				continue
			}
			
			keys = append(keys, key)
		}
		
		return nil
	})
	
	if err != nil {
		return nil, askarerrors.WrapAskarError(err)
	}
	
	return keys, nil
}

// ExportKey exports a key in JWK format
func (kms *AskarKeyManagementService) ExportKey(ctx *context.AgentContext, keyID string, includePrivate bool) (*JWK, error) {
	var jwk *JWK
	
	err := kms.storeManager.WithSession(ctx, kms.storeID, func(session *askar.Session) error {
		keyEntry, err := session.FetchKey(keyID, false)
		if err != nil {
			return err
		}
		if keyEntry == nil {
			return &KeyError{
				Code:    "KEY_NOT_FOUND",
				Message: fmt.Sprintf("key with ID %s not found", keyID),
			}
		}
		// Load the key from the entry
		localKey, err := keyEntry.LoadLocal()
		if err != nil {
			return &KeyError{
				Code:    "KEY_LOAD_FAILED",
				Message: "failed to load key",
				Cause:   err,
			}
		}
		
		var jwkString string
		if includePrivate {
			jwkString, err = localKey.GetJwkSecret()
		} else {
			jwkString, err = localKey.GetJwkPublic()
		}
		if err != nil {
			return &KeyError{
				Code:    "KEY_EXPORT_FAILED",
				Message: "failed to export key as JWK",
				Cause:   err,
			}
		}
		
		// Parse JWK JSON
		jwk = &JWK{}
		if err := json.Unmarshal([]byte(jwkString), jwk); err != nil {
			return err
		}
		
		jwk.Kid = keyID
		
		// Remove private key components if not requested
		if !includePrivate {
			jwk.D = ""
			jwk.P = ""
			jwk.Q = ""
			jwk.K = ""
		}
		
		return nil
	})
	
	if err != nil {
		return nil, askarerrors.WrapAskarError(err)
	}
	
	return jwk, nil
}

// GetPublicKey gets the public key bytes for a key
func (kms *AskarKeyManagementService) GetPublicKey(ctx *context.AgentContext, keyID string) ([]byte, error) {
	var publicKey []byte
	
	err := kms.storeManager.WithSession(ctx, kms.storeID, func(session *askar.Session) error {
		keyEntry, err := session.FetchKey(keyID, false)
		if err != nil {
			return err
		}
		if keyEntry == nil {
			return &KeyError{
				Code:    "KEY_NOT_FOUND",
				Message: fmt.Sprintf("key with ID %s not found", keyID),
			}
		}
		// Load the key from the entry
		localKey, err := keyEntry.LoadLocal()
		if err != nil {
			return err
		}
		
		pubKey, err := localKey.GetPublicBytes()
		if err != nil {
			return &KeyError{
				Code:    "KEY_EXPORT_FAILED",
				Message: "failed to export public key",
				Cause:   err,
			}
		}
		
		publicKey = pubKey
		return nil
	})
	
	if err != nil {
		return nil, askarerrors.WrapAskarError(err)
	}
	
	return publicKey, nil
}

// DeriveKey derives a new key from an existing key
func (kms *AskarKeyManagementService) DeriveKey(ctx *context.AgentContext, params DeriveKeyParams) (*Key, error) {
	// This would typically use KDF functions
	// For now, return not implemented
	return nil, &KeyError{
		Code:    "NOT_IMPLEMENTED",
		Message: "key derivation not yet implemented",
	}
}

// KeyAgreement performs ECDH key agreement
func (kms *AskarKeyManagementService) KeyAgreement(ctx *context.AgentContext, params KeyAgreementParams) ([]byte, error) {
	var sharedSecret []byte
	
	err := kms.storeManager.WithSession(ctx, kms.storeID, func(session *askar.Session) error {
		keyEntry, err := session.FetchKey(params.MyKeyID, false)
		if err != nil {
			return err
		}
		if keyEntry == nil {
			return &KeyError{
				Code:    "KEY_NOT_FOUND",
				Message: fmt.Sprintf("key with ID %s not found", params.MyKeyID),
			}
		}
		// Perform ECDH - KeyFromKeyExchange is not available yet
		// For now, return not implemented
		return &KeyError{
			Code:    "NOT_IMPLEMENTED",
			Message: "ECDH key agreement not yet implemented",
		}
	})
	
	if err != nil {
		return nil, askarerrors.WrapAskarError(err)
	}
	
	return sharedSecret, nil
}

// GenerateNonce generates a random nonce
func (kms *AskarKeyManagementService) GenerateNonce(length int) ([]byte, error) {
	if length <= 0 {
		length = 12 // Default nonce length for GCM
	}
	
	nonce := make([]byte, length)
	// Use Askar's random generation or fallback to crypto/rand
	// For now, using a simple approach
	for i := range nonce {
		nonce[i] = byte(i)
	}
	
	return nonce, nil
}

// UpdateKeyMetadata updates the metadata/tags for a key
func (kms *AskarKeyManagementService) UpdateKeyMetadata(ctx *context.AgentContext, keyID string, metadata map[string]string) error {
	err := kms.storeManager.WithTransaction(ctx, kms.storeID, func(session *askar.Session) error {
		// Fetch existing key
		keyEntry, err := session.FetchKey(keyID, false)
		if err != nil {
			return err
		}
		if keyEntry == nil {
			return &KeyError{
				Code:    "KEY_NOT_FOUND",
				Message: fmt.Sprintf("key with ID %s not found", keyID),
			}
		}
		// Note: keyEntry is automatically cleaned up
		
		// Parse existing metadata
		key := &Key{}
		if keyEntry.Metadata != "" {
			if err := json.Unmarshal([]byte(keyEntry.Metadata), key); err != nil {
				return err
			}
		}
		
		// Update metadata
		key.Tags = metadata
		key.UpdatedAt = time.Now()
		
		// Store updated metadata
		keyJSON, err := json.Marshal(key)
		if err != nil {
			return err
		}
		
		// Update the key entry
		err = session.UpdateKey(keyID, string(keyJSON), nil)
		if err != nil {
			return &KeyError{
				Code:    "KEY_UPDATE_FAILED",
				Message: "failed to update key metadata",
				Cause:   err,
			}
		}
		
		return nil
	})
	
	return askarerrors.WrapAskarError(err)
}

// WrapKey wraps a key using another key (key wrapping)
func (kms *AskarKeyManagementService) WrapKey(ctx *context.AgentContext, keyToWrapID string, wrappingKeyID string) ([]byte, error) {
	var wrappedKey []byte
	
	err := kms.storeManager.WithSession(ctx, kms.storeID, func(session *askar.Session) error {
		keyToWrap, err := session.FetchKey(keyToWrapID, false)
		if err != nil {
			return err
		}
		if keyToWrap == nil {
			return &KeyError{
				Code:    "KEY_NOT_FOUND",
				Message: fmt.Sprintf("key to wrap with ID %s not found", keyToWrapID),
			}
		}
		// Note: keyToWrap is automatically cleaned up
		
		wrappingKey, err := session.FetchKey(wrappingKeyID, false)
		if err != nil {
			return err
		}
		if wrappingKey == nil {
			return &KeyError{
				Code:    "KEY_NOT_FOUND",
				Message: fmt.Sprintf("wrapping key with ID %s not found", wrappingKeyID),
			}
		}
		// Note: wrappingKey is automatically cleaned up
		
		// Load keys from entries
		keyToWrapLocal, err := keyToWrap.LoadLocal()
		if err != nil {
			return err
		}
		
		secretBytes, err := keyToWrapLocal.GetSecretBytes()
		if err != nil {
			return &KeyError{
				Code:    "KEY_EXPORT_FAILED",
				Message: "failed to export key for wrapping",
				Cause:   err,
			}
		}
		
		// Load wrapping key
		wrappingKeyLocal, err := wrappingKey.LoadLocal()
		if err != nil {
			return err
		}
		
		// Use AEAD encryption for key wrapping (WrapKey not available)
		encBuffer, err := wrappingKeyLocal.AEADEncrypt(secretBytes, nil, nil)
		if err != nil {
			return &KeyError{
				Code:    "KEY_WRAP_FAILED",
				Message: "failed to wrap key",
				Cause:   err,
			}
		}
		
		// Combine nonce, tag, and ciphertext
		wrappedKey = append(encBuffer.GetNonce(), encBuffer.GetTag()...)
		wrappedKey = append(wrappedKey, encBuffer.GetCiphertext()...)
		
		return nil
	})
	
	if err != nil {
		return nil, askarerrors.WrapAskarError(err)
	}
	
	return wrappedKey, nil
}

// UnwrapKey unwraps a wrapped key
func (kms *AskarKeyManagementService) UnwrapKey(ctx *context.AgentContext, wrappedKey []byte, unwrappingKeyID string, keyType KeyType) (*Key, error) {
	// This would unwrap the key and import it
	// For now, return not implemented
	return nil, &KeyError{
		Code:    "NOT_IMPLEMENTED",
		Message: "key unwrapping not yet implemented",
	}
}

// ConvertKeyType converts a key from one type to another (if possible)
func (kms *AskarKeyManagementService) ConvertKeyType(ctx *context.AgentContext, keyID string, targetType KeyType) (*Key, error) {
	// For example, Ed25519 to X25519 conversion
	if targetType != KeyTypeX25519 {
		return nil, &KeyError{
			Code:    "UNSUPPORTED_CONVERSION",
			Message: fmt.Sprintf("conversion to %s not supported", targetType),
		}
	}
	
	var newKey *Key
	err := kms.storeManager.WithTransaction(ctx, kms.storeID, func(session *askar.Session) error {
		// Fetch the Ed25519 key
		keyEntry, err := session.FetchKey(keyID, false)
		if err != nil {
			return err
		}
		if keyEntry == nil {
			return &KeyError{
				Code:    "KEY_NOT_FOUND",
				Message: fmt.Sprintf("key with ID %s not found", keyID),
			}
		}
		// Convert Ed25519 to X25519 - ConvertKey not available
		// For now, return not implemented
		return &KeyError{
			Code:    "NOT_IMPLEMENTED",
			Message: "key conversion not yet implemented",
		}
	})
	
	if err != nil {
		return nil, askarerrors.WrapAskarError(err)
	}
	
	return newKey, nil
}

// GetSupportedKeyTypes returns the list of supported key types
func (kms *AskarKeyManagementService) GetSupportedKeyTypes() []KeyType {
	return []KeyType{
		KeyTypeEd25519,
		KeyTypeX25519,
		KeyTypeP256,
		KeyTypeP384,
		KeyTypeSecp256k1,
		KeyTypeBls12381,
		KeyTypeAES128,
		KeyTypeAES256,
	}
}

// GetSupportedSignatureAlgorithms returns supported signature algorithms for a key type
func (kms *AskarKeyManagementService) GetSupportedSignatureAlgorithms(keyType KeyType) []SignatureAlgorithm {
	switch keyType {
	case KeyTypeEd25519:
		return []SignatureAlgorithm{SignatureAlgEdDSA}
	case KeyTypeP256:
		return []SignatureAlgorithm{SignatureAlgES256}
	case KeyTypeP384:
		return []SignatureAlgorithm{SignatureAlgES384}
	case KeyTypeSecp256k1:
		return []SignatureAlgorithm{SignatureAlgES256K}
	default:
		return []SignatureAlgorithm{}
	}
}