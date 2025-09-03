package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// ChaCha20Poly1305 provides ChaCha20-Poly1305 AEAD encryption
type ChaCha20Poly1305 struct {
	cipher cipher.AEAD // AEAD cipher interface
}

// NewChaCha20Poly1305 creates a new ChaCha20-Poly1305 cipher with the given key
func NewChaCha20Poly1305(key []byte) (*ChaCha20Poly1305, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("key must be %d bytes, got %d", chacha20poly1305.KeySize, len(key))
	}

	cipher, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create ChaCha20-Poly1305 cipher: %w", err)
	}

	return &ChaCha20Poly1305{
		cipher: cipher,
	}, nil
}


// EncryptInput represents input for ChaCha20-Poly1305 encryption
type EncryptInput struct {
	Plaintext []byte `json:"plaintext"` // Data to encrypt
	Nonce     []byte `json:"nonce"`     // Nonce (12 bytes for ChaCha20, 24 bytes for XChaCha20)
	AAD       []byte `json:"aad"`       // Additional authenticated data (optional)
}

// EncryptOutput represents output from ChaCha20-Poly1305 encryption
type EncryptOutput struct {
	Ciphertext []byte `json:"ciphertext"` // Encrypted data (includes auth tag)
}

// Encrypt encrypts plaintext using ChaCha20-Poly1305
func (c *ChaCha20Poly1305) Encrypt(input EncryptInput) (*EncryptOutput, error) {
	if len(input.Nonce) != c.cipher.NonceSize() {
		return nil, fmt.Errorf("nonce must be %d bytes, got %d", c.cipher.NonceSize(), len(input.Nonce))
	}

	ciphertext := c.cipher.Seal(nil, input.Nonce, input.Plaintext, input.AAD)

	return &EncryptOutput{
		Ciphertext: ciphertext,
	}, nil
}

// DecryptInput represents input for ChaCha20-Poly1305 decryption
type DecryptInput struct {
	Ciphertext []byte `json:"ciphertext"` // Encrypted data (includes auth tag)
	Nonce      []byte `json:"nonce"`      // Nonce used for encryption
	AAD        []byte `json:"aad"`        // Additional authenticated data (optional)
}

// DecryptOutput represents output from ChaCha20-Poly1305 decryption
type DecryptOutput struct {
	Plaintext []byte `json:"plaintext"` // Decrypted data
}

// Decrypt decrypts ciphertext using ChaCha20-Poly1305
func (c *ChaCha20Poly1305) Decrypt(input DecryptInput) (*DecryptOutput, error) {
	if len(input.Nonce) != c.cipher.NonceSize() {
		return nil, fmt.Errorf("nonce must be %d bytes, got %d", c.cipher.NonceSize(), len(input.Nonce))
	}

	plaintext, err := c.cipher.Open(nil, input.Nonce, input.Ciphertext, input.AAD)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return &DecryptOutput{
		Plaintext: plaintext,
	}, nil
}


// EncryptChaCha20Poly1305 encrypts data using ChaCha20-Poly1305
func EncryptChaCha20Poly1305(key, plaintext, aad []byte) (nonce, ciphertext []byte, err error) {
	cipher, err := NewChaCha20Poly1305(key)
	if err != nil {
		return nil, nil, err
	}

	// Generate random nonce (12 bytes for ChaCha20)
	nonce = make([]byte, chacha20poly1305.NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	output, err := cipher.Encrypt(EncryptInput{
		Plaintext: plaintext,
		Nonce:     nonce,
		AAD:       aad,
	})
	if err != nil {
		return nil, nil, err
	}

	return nonce, output.Ciphertext, nil
}

// DecryptChaCha20Poly1305 decrypts data using ChaCha20-Poly1305
func DecryptChaCha20Poly1305(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	cipher, err := NewChaCha20Poly1305(key)
	if err != nil {
		return nil, err
	}

	output, err := cipher.Decrypt(DecryptInput{
		Ciphertext: ciphertext,
		Nonce:      nonce,
		AAD:        aad,
	})
	if err != nil {
		return nil, err
	}

	return output.Plaintext, nil
}
