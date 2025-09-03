package wallet

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"

	"golang.org/x/crypto/curve25519"

	"github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/core/storage"
	"github.com/ajna-inc/essi/pkg/core/common"
)

// WalletService handles key management and cryptographic operations
type WalletService struct {
	context    *context.AgentContext
	repository KeyRepository
}

// KeyType represents supported key types
type KeyType string

const (
	KeyTypeEd25519 KeyType = "Ed25519"
	KeyTypeX25519  KeyType = "X25519"
)

// Key represents a cryptographic key
type Key struct {
	Id         string  `json:"id"`
	Type       KeyType `json:"type"`
	PublicKey  []byte  `json:"publicKey"`
	PrivateKey []byte  `json:"privateKey,omitempty"`
	CreatedAt  string  `json:"createdAt"`
}

// KeyRecord represents a stored key record
type KeyRecord struct {
	*storage.BaseRecord

	Key *Key `json:"key"`
}

// Implement storage.Record JSON methods for full serialization
func (r *KeyRecord) ToJSON() ([]byte, error) { return json.Marshal(r) }
func (r *KeyRecord) FromJSON(data []byte) error { return json.Unmarshal(data, r) }

// Implement Clone to satisfy storage.Record and preserve key data
func (r *KeyRecord) Clone() storage.Record {
	clone := &KeyRecord{}
	if r.BaseRecord != nil { clone.BaseRecord = r.BaseRecord.Clone().(*storage.BaseRecord) }
	if r.Key != nil {
		k := *r.Key
		// Deep copy slices
		if r.Key.PublicKey != nil { k.PublicKey = append([]byte(nil), r.Key.PublicKey...) }
		if r.Key.PrivateKey != nil { k.PrivateKey = append([]byte(nil), r.Key.PrivateKey...) }
		clone.Key = &k
	}
	return clone
}

// Register the "Key" record type so storage can deserialize full records
func init() {
    storage.RegisterRecordType("Key", func() storage.Record {
        return &KeyRecord{ BaseRecord: &storage.BaseRecord{ Type: "Key", Tags: make(map[string]string) } }
    })
}

// KeyRepository interface for key storage
type KeyRepository interface {
	Save(ctx *context.AgentContext, record *KeyRecord) error
	FindById(ctx *context.AgentContext, id string) (*KeyRecord, error)
	FindByPublicKey(ctx *context.AgentContext, publicKey []byte) (*KeyRecord, error)
	Delete(ctx *context.AgentContext, id string) error
	GetAll(ctx *context.AgentContext) ([]*KeyRecord, error)
}

// SimpleKeyRepository provides an in-memory key repository for development
type SimpleKeyRepository struct {
	keys map[string]*KeyRecord
}

// NewSimpleKeyRepository creates a new in-memory key repository
func NewSimpleKeyRepository() *SimpleKeyRepository {
	return &SimpleKeyRepository{
		keys: make(map[string]*KeyRecord),
	}
}

func (r *SimpleKeyRepository) Save(ctx *context.AgentContext, record *KeyRecord) error {
	r.keys[record.Key.Id] = record
	return nil
}

func (r *SimpleKeyRepository) FindById(ctx *context.AgentContext, id string) (*KeyRecord, error) {
	record, exists := r.keys[id]
	if !exists {
		return nil, fmt.Errorf("key with id %s not found", id)
	}
	return record, nil
}

func (r *SimpleKeyRepository) FindByPublicKey(ctx *context.AgentContext, publicKey []byte) (*KeyRecord, error) {
	for _, record := range r.keys {
		if common.AreSlicesEqual(record.Key.PublicKey, publicKey) {
			return record, nil
		}
	}
	return nil, fmt.Errorf("key with public key not found")
}

func (r *SimpleKeyRepository) Delete(ctx *context.AgentContext, id string) error {
	delete(r.keys, id)
	return nil
}

func (r *SimpleKeyRepository) GetAll(ctx *context.AgentContext) ([]*KeyRecord, error) {
	keys := make([]*KeyRecord, 0, len(r.keys))
	for _, record := range r.keys {
		keys = append(keys, record)
	}
	return keys, nil
}

// NewWalletService creates a new wallet service
func NewWalletService(ctx *context.AgentContext, repository KeyRepository) *WalletService {
	return &WalletService{
		context:    ctx,
		repository: repository,
	}
}

// CreateKey generates a new key of the specified type
func (w *WalletService) CreateKey(keyType KeyType) (*Key, error) {
	keyId := common.GenerateUUID()

	switch keyType {
	case KeyTypeEd25519:
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate Ed25519 key: %w", err)
		}

		key := &Key{
			Id:         keyId,
			Type:       KeyTypeEd25519,
			PublicKey:  publicKey,
			PrivateKey: privateKey,
			CreatedAt:  common.CurrentTimestamp(),
		}

		// Save the key
		record := &KeyRecord{
			BaseRecord: &storage.BaseRecord{
				ID:   keyId,
				Type: "Key",
				Tags: map[string]string{
					"keyType": string(keyType),
				},
			},
			Key: key,
		}

		if err := w.repository.Save(w.context, record); err != nil {
			return nil, fmt.Errorf("failed to save key: %w", err)
		}

		return key, nil

	case KeyTypeX25519:
		privateKey := make([]byte, 32)
		if _, err := rand.Read(privateKey); err != nil {
			return nil, fmt.Errorf("failed to generate X25519 private key: %w", err)
		}

		// Clamp the private key as per RFC 7748
		privateKey[0] &= 248
		privateKey[31] &= 127
		privateKey[31] |= 64

		publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
		if err != nil {
			return nil, fmt.Errorf("failed to derive X25519 public key: %w", err)
		}

		key := &Key{
			Id:         keyId,
			Type:       KeyTypeX25519,
			PublicKey:  publicKey,
			PrivateKey: privateKey,
			CreatedAt:  common.CurrentTimestamp(),
		}

		record := &KeyRecord{
			BaseRecord: &storage.BaseRecord{
				ID:   keyId,
				Type: "Key",
				Tags: map[string]string{
					"keyType": string(keyType),
				},
			},
			Key: key,
		}

		if err := w.repository.Save(w.context, record); err != nil {
			return nil, fmt.Errorf("failed to save key: %w", err)
		}

		return key, nil

	default:
		return nil, fmt.Errorf("unsupported key type: %s", keyType)
	}
}

// GetKey retrieves a key by ID
func (w *WalletService) GetKey(keyId string) (*Key, error) {
	record, err := w.repository.FindById(w.context, keyId)
	if err != nil {
		return nil, fmt.Errorf("failed to find key: %w", err)
	}
	return record.Key, nil
}

// GetPublicKey retrieves just the public key portion
func (w *WalletService) GetPublicKey(keyId string) ([]byte, error) {
	key, err := w.GetKey(keyId)
	if err != nil {
		return nil, err
	}
	return key.PublicKey, nil
}

// FindKeyByPublicKey finds a key by its public key
func (w *WalletService) FindKeyByPublicKey(publicKey []byte) (*Key, error) {
	record, err := w.repository.FindByPublicKey(w.context, publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to find key by public key: %w", err)
	}
	return record.Key, nil
}

// Sign signs data with the specified key
func (w *WalletService) Sign(keyId string, data []byte) ([]byte, error) {
	key, err := w.GetKey(keyId)
	if err != nil {
		return nil, fmt.Errorf("failed to get key for signing: %w", err)
	}

	if key.Type != KeyTypeEd25519 {
		return nil, fmt.Errorf("signing only supported for Ed25519 keys")
	}

	if len(key.PrivateKey) == 0 {
		return nil, fmt.Errorf("private key not available for signing")
	}

	signature := ed25519.Sign(ed25519.PrivateKey(key.PrivateKey), data)
	return signature, nil
}

// Verify verifies a signature with the specified key
func (w *WalletService) Verify(keyId string, data []byte, signature []byte) (bool, error) {
	key, err := w.GetKey(keyId)
	if err != nil {
		return false, fmt.Errorf("failed to get key for verification: %w", err)
	}

	if key.Type != KeyTypeEd25519 {
		return false, fmt.Errorf("verification only supported for Ed25519 keys")
	}

	valid := ed25519.Verify(ed25519.PublicKey(key.PublicKey), data, signature)
	return valid, nil
}

// VerifyWithPublicKey verifies a signature with a public key directly
func (w *WalletService) VerifyWithPublicKey(publicKey []byte, data []byte, signature []byte) bool {
	return ed25519.Verify(ed25519.PublicKey(publicKey), data, signature)
}

// GenerateNonce generates a random nonce
func (w *WalletService) GenerateNonce(length int) ([]byte, error) {
	nonce := make([]byte, length)
	_, err := rand.Read(nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	return nonce, nil
}

// GenerateRandomBytes generates random bytes
func (w *WalletService) GenerateRandomBytes(length int) ([]byte, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return bytes, nil
}

// DeleteKey deletes a key by ID
func (w *WalletService) DeleteKey(keyId string) error {
	return w.repository.Delete(w.context, keyId)
}

// ListKeys returns all keys
func (w *WalletService) ListKeys() ([]*Key, error) {
	records, err := w.repository.GetAll(w.context)
	if err != nil {
		return nil, fmt.Errorf("failed to list keys: %w", err)
	}

	keys := make([]*Key, len(records))
	for i, record := range records {
		keys[i] = record.Key
	}

	return keys, nil
}

// NewKeyRecord creates a new key record
func NewKeyRecord(key *Key) *KeyRecord {
	return &KeyRecord{
		BaseRecord: &storage.BaseRecord{
			ID:   key.Id,
			Type: "Key",
			Tags: map[string]string{
				"keyType": string(key.Type),
			},
		},
		Key: key,
	}
}
