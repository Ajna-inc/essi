package messages

import (
	"encoding/json"
	"fmt"

	"github.com/ajna-inc/essi/pkg/core/utils"
)

// MessageEnvelope represents a DIDComm message envelope for transport
type MessageEnvelope struct {
	// Protected header (base64url encoded)
	Protected string `json:"protected,omitempty"`

	// Unprotected header
	Unprotected map[string]interface{} `json:"unprotected,omitempty"`

	// Recipients (for encrypted messages)
	Recipients []*Recipient `json:"recipients,omitempty"`

	// Ciphertext (for encrypted messages, base64url encoded)
	Ciphertext string `json:"ciphertext,omitempty"`

	// IV/Nonce (base64url encoded)
	IV string `json:"iv,omitempty"`

	// Authentication tag (base64url encoded)
	Tag string `json:"tag,omitempty"`

	// Signatures (for signed messages)
	Signatures []*Signature `json:"signatures,omitempty"`

	// Payload (base64url encoded plaintext or ciphertext)
	Payload string `json:"payload,omitempty"`

	// Indicates the message format type
	Type EnvelopeType `json:"-"`
}

// EnvelopeType represents the type of message envelope
type EnvelopeType string

const (
	// PlaintextType for unencrypted, unsigned messages
	PlaintextType EnvelopeType = "plaintext"

	// SignedType for signed but unencrypted messages (JWS)
	SignedType EnvelopeType = "signed"

	// EncryptedType for encrypted messages (JWE)
	EncryptedType EnvelopeType = "encrypted"

	// SignedAndEncryptedType for signed and encrypted messages
	SignedAndEncryptedType EnvelopeType = "signed_encrypted"
)

// Recipient represents a recipient in an encrypted message
type Recipient struct {
	// Encrypted key (base64url encoded)
	EncryptedKey string `json:"encrypted_key,omitempty"`

	// Header specific to this recipient
	Header map[string]interface{} `json:"header,omitempty"`
}

// Signature represents a signature in a signed message
type Signature struct {
	// Protected header for this signature (base64url encoded)
	Protected string `json:"protected,omitempty"`

	// Unprotected header for this signature
	Header map[string]interface{} `json:"header,omitempty"`

	// Signature value (base64url encoded)
	Signature string `json:"signature"`
}

// ProtectedHeader represents the protected header content
type ProtectedHeader struct {
	// Encryption algorithm
	Enc string `json:"enc,omitempty"`

	// Key derivation algorithm
	Alg string `json:"alg,omitempty"`

	// Sender key ID
	Skid string `json:"skid,omitempty"`

	// Additional protected fields
	AdditionalFields map[string]interface{} `json:"-"`
}

// UnprotectedHeader represents common unprotected header fields
type UnprotectedHeader struct {
	// Content type
	Cty string `json:"cty,omitempty"`

	// Additional unprotected fields
	AdditionalFields map[string]interface{} `json:"-"`
}

// EncryptedMessage represents the structure for encrypted DIDComm messages
type EncryptedMessage struct {
	// Ciphertext of the message
	Ciphertext []byte

	// Recipients who can decrypt
	Recipients []string

	// Sender information
	SenderKey string

	// Additional authenticated data
	AAD []byte
}

// SignedMessage represents the structure for signed DIDComm messages
type SignedMessage struct {
	// Payload to be signed
	Payload []byte

	// Signatures
	Signatures []MessageSignature
}

// MessageSignature represents a single signature
type MessageSignature struct {
	// Signer key ID
	SignerKeyId string

	// Signature bytes
	Signature []byte

	// Protected header
	Protected map[string]interface{}
}

// NewMessageEnvelope creates a new message envelope
func NewMessageEnvelope(envelopeType EnvelopeType) *MessageEnvelope {
	return &MessageEnvelope{
		Type:        envelopeType,
		Unprotected: make(map[string]interface{}),
	}
}

// NewPlaintextEnvelope creates a plaintext message envelope
func NewPlaintextEnvelope(message MessageInterface) (*MessageEnvelope, error) {
	payload, err := message.ToJSON()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize message: %w", err)
	}

	return &MessageEnvelope{
		Type:    PlaintextType,
		Payload: string(payload),
	}, nil
}

// GetType returns the envelope type
func (e *MessageEnvelope) GetType() EnvelopeType {
	return e.Type
}

// SetType sets the envelope type
func (e *MessageEnvelope) SetType(envelopeType EnvelopeType) {
	e.Type = envelopeType
}

// IsEncrypted checks if the envelope contains an encrypted message
func (e *MessageEnvelope) IsEncrypted() bool {
	return e.Type == EncryptedType || e.Type == SignedAndEncryptedType
}

// IsSigned checks if the envelope contains a signed message
func (e *MessageEnvelope) IsSigned() bool {
	return e.Type == SignedType || e.Type == SignedAndEncryptedType
}

// IsPlaintext checks if the envelope contains a plaintext message
func (e *MessageEnvelope) IsPlaintext() bool {
	return e.Type == PlaintextType
}

// AddRecipient adds a recipient to an encrypted message
func (e *MessageEnvelope) AddRecipient(recipient *Recipient) {
	if e.Recipients == nil {
		e.Recipients = []*Recipient{}
	}
	e.Recipients = append(e.Recipients, recipient)
}

// AddSignature adds a signature to a signed message
func (e *MessageEnvelope) AddSignature(signature *Signature) {
	if e.Signatures == nil {
		e.Signatures = []*Signature{}
	}
	e.Signatures = append(e.Signatures, signature)
}

// GetPayload returns the decoded payload as bytes
func (e *MessageEnvelope) GetPayload() ([]byte, error) {
	if e.Payload == "" {
		return nil, fmt.Errorf("no payload in envelope")
	}

	// For plaintext messages, payload is the raw JSON
	if e.IsPlaintext() {
		return []byte(e.Payload), nil
	}

	// For other types, payload is base64url encoded
	return DecodeBase64URL(e.Payload)
}

// SetPayload sets the payload (will be encoded appropriately based on type)
func (e *MessageEnvelope) SetPayload(payload []byte) {
	if e.IsPlaintext() {
		e.Payload = string(payload)
	} else {
		e.Payload = EncodeBase64URL(payload)
	}
}

// GetMessage extracts the DIDComm message from the envelope
func (e *MessageEnvelope) GetMessage() (MessageInterface, error) {
	payload, err := e.GetPayload()
	if err != nil {
		return nil, err
	}

	// Parse as base message
	var message BaseMessage
	if err := json.Unmarshal(payload, &message); err != nil {
		return nil, fmt.Errorf("failed to parse message: %w", err)
	}

	return &message, nil
}

// ToJSON serializes the envelope to JSON
func (e *MessageEnvelope) ToJSON() ([]byte, error) {
	return json.Marshal(e)
}

// FromJSON deserializes the envelope from JSON
func (e *MessageEnvelope) FromJSON(data []byte) error {
	if err := json.Unmarshal(data, e); err != nil {
		return err
	}

	// Determine envelope type based on content
	if e.Ciphertext != "" {
		if len(e.Signatures) > 0 {
			e.Type = SignedAndEncryptedType
		} else {
			e.Type = EncryptedType
		}
	} else if len(e.Signatures) > 0 {
		e.Type = SignedType
	} else {
		e.Type = PlaintextType
	}

	return nil
}

// Validate performs basic validation on the envelope
func (e *MessageEnvelope) Validate() error {
	switch e.Type {
	case PlaintextType:
		if e.Payload == "" {
			return fmt.Errorf("plaintext envelope must have payload")
		}

	case EncryptedType:
		if e.Ciphertext == "" {
			return fmt.Errorf("encrypted envelope must have ciphertext")
		}
		if len(e.Recipients) == 0 {
			return fmt.Errorf("encrypted envelope must have recipients")
		}

	case SignedType:
		if len(e.Signatures) == 0 {
			return fmt.Errorf("signed envelope must have signatures")
		}
		if e.Payload == "" {
			return fmt.Errorf("signed envelope must have payload")
		}

	case SignedAndEncryptedType:
		if e.Ciphertext == "" {
			return fmt.Errorf("signed+encrypted envelope must have ciphertext")
		}
		if len(e.Recipients) == 0 {
			return fmt.Errorf("signed+encrypted envelope must have recipients")
		}
		if len(e.Signatures) == 0 {
			return fmt.Errorf("signed+encrypted envelope must have signatures")
		}
	}

	return nil
}

// Clone creates a deep copy of the envelope
func (e *MessageEnvelope) Clone() *MessageEnvelope {
	clone := &MessageEnvelope{
		Protected:  e.Protected,
		Ciphertext: e.Ciphertext,
		IV:         e.IV,
		Tag:        e.Tag,
		Payload:    e.Payload,
		Type:       e.Type,
	}

	// Clone unprotected header
	if e.Unprotected != nil {
		clone.Unprotected = make(map[string]interface{})
		for k, v := range e.Unprotected {
			clone.Unprotected[k] = v
		}
	}

	// Clone recipients
	if e.Recipients != nil {
		clone.Recipients = make([]*Recipient, len(e.Recipients))
		for i, recipient := range e.Recipients {
			clone.Recipients[i] = &Recipient{
				EncryptedKey: recipient.EncryptedKey,
				Header:       make(map[string]interface{}),
			}
			for k, v := range recipient.Header {
				clone.Recipients[i].Header[k] = v
			}
		}
	}

	// Clone signatures
	if e.Signatures != nil {
		clone.Signatures = make([]*Signature, len(e.Signatures))
		for i, sig := range e.Signatures {
			clone.Signatures[i] = &Signature{
				Protected: sig.Protected,
				Signature: sig.Signature,
				Header:    make(map[string]interface{}),
			}
			for k, v := range sig.Header {
				clone.Signatures[i].Header[k] = v
			}
		}
	}

	return clone
}

// Helper functions for envelope creation

// CreatePlaintextEnvelope creates a plaintext envelope from a message
func CreatePlaintextEnvelope(message MessageInterface) (*MessageEnvelope, error) {
	return NewPlaintextEnvelope(message)
}

// Helper functions for base64url encoding/decoding

// EncodeBase64URL encodes bytes to base64url string
func EncodeBase64URL(data []byte) string {
	return utils.EncodeBase64URLString(data)
}

// DecodeBase64URL decodes base64url string to bytes
func DecodeBase64URL(data string) ([]byte, error) {
	return utils.DecodeBase64URLString(data)
}

// MessageTransport represents transport metadata
type MessageTransport struct {
	// Return route for response
	ReturnRoute string `json:"return_route,omitempty"`

	// Transport-specific metadata
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// NewMessageTransport creates new transport metadata
func NewMessageTransport() *MessageTransport {
	return &MessageTransport{
		Metadata: make(map[string]interface{}),
	}
}
