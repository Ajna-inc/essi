package signature

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ajna-inc/essi/pkg/core/encoding"
	"github.com/ajna-inc/essi/pkg/core/utils"
	"github.com/ajna-inc/essi/pkg/core/wallet"
	"golang.org/x/crypto/ed25519"
)

// SignatureDecorator represents a signature decorator for signed messages
type SignatureDecorator struct {
	Type          string `json:"@type"`
	SignatureData string `json:"sig_data"`
	Signer        string `json:"signer"`
	Signature     string `json:"signature"`
}

// CreateSignature creates a signature decorator for the given data
func CreateSignature(data interface{}, signingKey *wallet.Key) (*SignatureDecorator, error) {
	// Convert data to JSON
	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal data: %w", err)
	}

	// Create timestamp (8 bytes for unix timestamp in milliseconds)
	timestamp := time.Now().UnixNano() / int64(time.Millisecond)
	timestampBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timestampBytes, uint64(timestamp))

	// Concatenate timestamp and JSON data
	dataToSign := append(timestampBytes, jsonData...)

	// Sign the data
	signature := ed25519.Sign(signingKey.PrivateKey, dataToSign)

	// Create signature decorator
	return &SignatureDecorator{
		Type:          "https://didcomm.org/signature/1.0/ed25519Sha512_single",
		SignatureData: utils.EncodeBase64URLString(dataToSign),
		Signer:        encoding.EncodeBase58(signingKey.PublicKey),
		Signature:     utils.EncodeBase64URLString(signature),
	}, nil
}

// VerifySignature verifies the signature decorator
func VerifySignature(decorator *SignatureDecorator) ([]byte, error) {
	// Decode signer public key
	publicKey, err := encoding.DecodeBase58(decorator.Signer)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signer key: %w", err)
	}

	// Decode signature data
	// Credo TS uses base64url (unpadded) for signature fields
	signedData, err := utils.DecodeBase64URLString(decorator.SignatureData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature data: %w", err)
	}

	// Decode signature
	signature, err := utils.DecodeBase64URLString(decorator.Signature)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature: %w", err)
	}

	// Verify signature
	if !ed25519.Verify(publicKey, signedData, signature) {
		return nil, fmt.Errorf("signature verification failed")
	}

	// Return the JSON data (skip the first 8 timestamp bytes)
	if len(signedData) < 8 {
		return nil, fmt.Errorf("invalid signature data length")
	}

	return signedData[8:], nil
}

// UnpackAndVerifySignature unpacks and verifies signed data, returning the unmarshaled result
func UnpackAndVerifySignature(decorator *SignatureDecorator, target interface{}) error {
	jsonData, err := VerifySignature(decorator)
	if err != nil {
		return err
	}

	// Unmarshal the JSON data into the target
	decoder := json.NewDecoder(bytes.NewReader(jsonData))
	decoder.UseNumber()
	return decoder.Decode(target)
}
