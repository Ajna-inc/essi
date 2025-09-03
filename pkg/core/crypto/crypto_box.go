package crypto

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

// CryptoBox provides libsodium-compatible crypto_box operations for DIDComm v1
type CryptoBox struct{}

// NewCryptoBox creates a new CryptoBox instance
func NewCryptoBox() *CryptoBox {
	return &CryptoBox{}
}

// RandomNonce generates a 24-byte nonce for crypto_box operations
func (cb *CryptoBox) RandomNonce() ([]byte, error) {
	nonce := make([]byte, 24)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate random nonce: %w", err)
	}
	return nonce, nil
}

// SealInput represents input for the Seal operation
type SealInput struct {
	RecipientKey []byte `json:"recipientKey"` // 32-byte X25519 public key
	Message      []byte `json:"message"`      // Message to encrypt
}

// SealOutput represents the output from Seal operation
type SealOutput struct {
	Encrypted []byte `json:"encrypted"` // Encrypted message (48 bytes longer than input)
}

// Seal performs anonymous encryption using crypto_box_seal
// This generates an ephemeral keypair and encrypts the message
// Output format: ephemeral_public_key (32 bytes) + encrypted_message (message_len + 16 bytes)
func (cb *CryptoBox) Seal(input SealInput) (*SealOutput, error) {
	if len(input.RecipientKey) != 32 {
		return nil, fmt.Errorf("recipient key must be 32 bytes, got %d", len(input.RecipientKey))
	}

	// Generate ephemeral keypair
	ephemeralPublic, ephemeralPrivate, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral keypair: %w", err)
	}

	// Convert recipient key to [32]byte
	var recipientKey [32]byte
	copy(recipientKey[:], input.RecipientKey)

	// Derive deterministic nonce using BLAKE2b-24 over ephemeralPublic || recipientPublic
	nonceInput := make([]byte, 64)
	copy(nonceInput[:32], ephemeralPublic[:])
	copy(nonceInput[32:], recipientKey[:])

	nonceSum, err := BLAKE2BHash24(nonceInput)
	if err != nil {
		return nil, fmt.Errorf("failed to derive nonce: %w", err)
	}

	var nonce [24]byte
	copy(nonce[:], nonceSum)

	// Encrypt the message
	encrypted := box.Seal(nil, input.Message, &nonce, &recipientKey, ephemeralPrivate)

	// Create the output: ephemeral_public_key + encrypted_data
	output := make([]byte, 32+len(encrypted))
	copy(output[:32], ephemeralPublic[:])
	copy(output[32:], encrypted)

	return &SealOutput{
		Encrypted: output,
	}, nil
}

// SealOpenInput represents input for the SealOpen operation
type SealOpenInput struct {
	RecipientKey []byte `json:"recipientKey"` // 32-byte X25519 private key
	Ciphertext   []byte `json:"ciphertext"`   // Encrypted data from Seal
}

// SealOpenOutput represents the output from SealOpen operation
type SealOpenOutput struct {
	Message []byte `json:"message"` // Decrypted message
}

// SealOpen performs anonymous decryption using crypto_box_seal_open
func (cb *CryptoBox) SealOpen(input SealOpenInput) (*SealOpenOutput, error) {
	if len(input.RecipientKey) != 32 {
		return nil, fmt.Errorf("recipient key must be 32 bytes, got %d", len(input.RecipientKey))
	}

	if len(input.Ciphertext) < 48 {
		return nil, fmt.Errorf("ciphertext too short: expected at least 48 bytes, got %d", len(input.Ciphertext))
	}

	// Extract ephemeral public key (first 32 bytes)
	var ephemeralPublic [32]byte
	copy(ephemeralPublic[:], input.Ciphertext[:32])

	// Extract encrypted data (remaining bytes)
	encrypted := input.Ciphertext[32:]

	// Convert recipient private key to [32]byte
	var recipientPrivate [32]byte
	copy(recipientPrivate[:], input.RecipientKey)

	// Generate corresponding public key for the private key
	var recipientPublic [32]byte
	curve25519.ScalarBaseMult(&recipientPublic, &recipientPrivate)

	// For sealed box, we need to derive the nonce from the ephemeral public key and recipient public key
	// This follows the libsodium crypto_box_seal implementation
	nonceBytes := make([]byte, 64)
	copy(nonceBytes[:32], ephemeralPublic[:])
	copy(nonceBytes[32:], recipientPublic[:])

	// Hash to get deterministic 24-byte nonce using BLAKE2b-24
	nonceSum, err := BLAKE2BHash24(nonceBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to derive nonce: %w", err)
	}
	var nonce [24]byte
	copy(nonce[:], nonceSum)

	// Decrypt the message
	decrypted, ok := box.Open(nil, encrypted, &nonce, &ephemeralPublic, &recipientPrivate)
	if !ok {
		return nil, fmt.Errorf("failed to decrypt sealed box")
	}

	return &SealOpenOutput{
		Message: decrypted,
	}, nil
}

// CryptoBoxInput represents input for authenticated encryption
type CryptoBoxInput struct {
	RecipientKey []byte `json:"recipientKey"` // 32-byte X25519 public key
	SenderKey    []byte `json:"senderKey"`    // 32-byte X25519 private key
	Message      []byte `json:"message"`      // Message to encrypt
	Nonce        []byte `json:"nonce"`        // 24-byte nonce
}

// CryptoBoxOutput represents output from authenticated encryption
type CryptoBoxOutput struct {
	Encrypted []byte `json:"encrypted"` // Encrypted message
}

// CryptoBox performs authenticated encryption using crypto_box
func (cb *CryptoBox) CryptoBox(input CryptoBoxInput) (*CryptoBoxOutput, error) {
	if len(input.RecipientKey) != 32 {
		return nil, fmt.Errorf("recipient key must be 32 bytes, got %d", len(input.RecipientKey))
	}
	if len(input.SenderKey) != 32 {
		return nil, fmt.Errorf("sender key must be 32 bytes, got %d", len(input.SenderKey))
	}
	if len(input.Nonce) != 24 {
		return nil, fmt.Errorf("nonce must be 24 bytes, got %d", len(input.Nonce))
	}

	var recipientKey [32]byte
	var senderKey [32]byte
	var nonce [24]byte

	copy(recipientKey[:], input.RecipientKey)
	copy(senderKey[:], input.SenderKey)
	copy(nonce[:], input.Nonce)

	encrypted := box.Seal(nil, input.Message, &nonce, &recipientKey, &senderKey)

	return &CryptoBoxOutput{
		Encrypted: encrypted,
	}, nil
}

// OpenInput represents input for authenticated decryption
type OpenInput struct {
	RecipientKey []byte `json:"recipientKey"` // 32-byte X25519 private key
	SenderKey    []byte `json:"senderKey"`    // 32-byte X25519 public key
	Message      []byte `json:"message"`      // Encrypted message
	Nonce        []byte `json:"nonce"`        // 24-byte nonce
}

// OpenOutput represents output from authenticated decryption
type OpenOutput struct {
	Decrypted []byte `json:"decrypted"` // Decrypted message
}

// Open performs authenticated decryption using crypto_box_open
func (cb *CryptoBox) Open(input OpenInput) (*OpenOutput, error) {
	if len(input.RecipientKey) != 32 {
		return nil, fmt.Errorf("recipient key must be 32 bytes, got %d", len(input.RecipientKey))
	}
	if len(input.SenderKey) != 32 {
		return nil, fmt.Errorf("sender key must be 32 bytes, got %d", len(input.SenderKey))
	}
	if len(input.Nonce) != 24 {
		return nil, fmt.Errorf("nonce must be 24 bytes, got %d", len(input.Nonce))
	}

	var recipientKey [32]byte
	var senderKey [32]byte
	var nonce [24]byte

	copy(recipientKey[:], input.RecipientKey)
	copy(senderKey[:], input.SenderKey)
	copy(nonce[:], input.Nonce)

	decrypted, ok := box.Open(nil, input.Message, &nonce, &senderKey, &recipientKey)
	if !ok {
		return nil, fmt.Errorf("failed to decrypt message")
	}

	return &OpenOutput{
		Decrypted: decrypted,
	}, nil
}

// Global instance for easy access
var DefaultCryptoBox = NewCryptoBox()

// Convenience functions that match the Credo-TS API
func CryptoBoxSeal(recipientKey, message []byte) ([]byte, error) {
	output, err := DefaultCryptoBox.Seal(SealInput{
		RecipientKey: recipientKey,
		Message:      message,
	})
	if err != nil {
		return nil, err
	}
	return output.Encrypted, nil
}

func CryptoBoxSealOpen(recipientKey, ciphertext []byte) ([]byte, error) {
	output, err := DefaultCryptoBox.SealOpen(SealOpenInput{
		RecipientKey: recipientKey,
		Ciphertext:   ciphertext,
	})
	if err != nil {
		return nil, err
	}
	return output.Message, nil
}

func CryptoBoxRandomNonce() ([]byte, error) {
	return DefaultCryptoBox.RandomNonce()
}

// CryptoBoxWithNonce encrypts message using authenticated encryption with provided nonce
func CryptoBoxWithNonce(recipientPublicKey, senderPrivateKey, message, nonce []byte) ([]byte, error) {
	cb := NewCryptoBox()
	output, err := cb.CryptoBox(CryptoBoxInput{
		RecipientKey: recipientPublicKey,
		SenderKey:    senderPrivateKey,
		Message:      message,
		Nonce:        nonce,
	})
	if err != nil {
		return nil, err
	}
	return output.Encrypted, nil
}

// CryptoBoxOpen decrypts message using authenticated decryption
func CryptoBoxOpen(recipientPrivateKey, senderPublicKey, ciphertext, nonce []byte) ([]byte, error) {
	cb := NewCryptoBox()
	output, err := cb.Open(OpenInput{
		RecipientKey: recipientPrivateKey,
		SenderKey:    senderPublicKey,
		Message:      ciphertext,
		Nonce:        nonce,
	})
	if err != nil {
		return nil, err
	}
	return output.Decrypted, nil
}
