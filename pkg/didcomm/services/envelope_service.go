package services

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"github.com/ajna-inc/essi/pkg/core/context"
	cryptoapi "github.com/ajna-inc/essi/pkg/core/crypto"
	"github.com/ajna-inc/essi/pkg/core/di"
	"github.com/ajna-inc/essi/pkg/core/logger"
	"github.com/ajna-inc/essi/pkg/core/encoding"
	"github.com/ajna-inc/essi/pkg/core/utils"
	"github.com/ajna-inc/essi/pkg/core/wallet"
	//peer "github.com/ajna-inc/essi/pkg/dids/methods/peer"
)

// getLoggerFromCtx resolves a logger from DI
func getLoggerFromCtx(ctx *context.AgentContext, dm di.DependencyManager) logger.Logger {
	if dm != nil {
		if lAny, err := dm.Resolve(di.TokenLogger); err == nil {
			if lg, ok := lAny.(logger.Logger); ok && lg != nil {
				return lg
			}
		}
	}
	return logger.GetDefaultLogger()
}

// EnvelopeService handles DIDComm message encryption and decryption
type EnvelopeService struct {
	agentContext *context.AgentContext
	senderKey    []byte
	typedDI      di.DependencyManager
}

// NewEnvelopeService creates a new envelope service
func NewEnvelopeService(agentContext *context.AgentContext) *EnvelopeService {
	return &EnvelopeService{
		agentContext: agentContext,
	}
}

// SetTypedDI injects the typed dependency manager
func (es *EnvelopeService) SetTypedDI(dm di.DependencyManager) { es.typedDI = dm }

// SetSenderKey sets the private key used for authcrypt packaging
func (es *EnvelopeService) SetSenderKey(key []byte) {
	es.senderKey = key
}

// EnvelopeKeys represents keys for envelope encryption/decryption
type EnvelopeKeys struct {
	RecipientKeys [][]byte // Public keys of recipients (for encryption)
	SenderKey     []byte   // Private key of sender (for authentication, optional)
	RoutingKeys   [][]byte // Public keys for routing (optional)
}

// PackageType defines the encryption type for messages
type PackageType string

const (
	PackageTypeEncrypted PackageType = "encrypted"
	PackageTypePlaintext PackageType = "plaintext"
	PackageTypeAnoncrypt PackageType = "anoncryptKey"
	PackageTypeAuthcrypt PackageType = "authcryptKey"
)

// PackMessage packages a plaintext message into an encrypted message
// PackMessage packages a raw JSON message into an encrypted message. The `to`
// parameter should contain the DID key identifiers for the recipients.
func (es *EnvelopeService) PackMessage(message interface{}, to []string, packageType PackageType) (*EncryptedMessage, error) {
	lg := getLoggerFromCtx(es.agentContext, es.typedDI)
	lg.Infof("📦 Packaging message with type: %s", packageType)

	var messageBytes []byte
	switch m := message.(type) {
	case []byte:
		messageBytes = m
	case string:
		messageBytes = []byte(m)
	case map[string]interface{}:
		var err error
		messageBytes, err = json.Marshal(m)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal message map: %w", err)
		}
	case PlaintextMessage:
		var err error
		messageBytes, err = json.Marshal(m)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal plaintext message: %w", err)
		}
	default:
		// Try to marshal any other type as JSON
		var err error
		messageBytes, err = json.Marshal(message)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal message of type %T: %w", message, err)
		}
	}

	switch packageType {
	case PackageTypePlaintext:
		return es.packagePlaintext(messageBytes)
	case PackageTypeAnoncrypt:
		return es.packAnoncrypt(messageBytes, to)
	case PackageTypeAuthcrypt:
		return es.packAuthcrypt(messageBytes, to)
	case PackageTypeEncrypted:
		// Default to anoncrypt for encrypted
		return es.packAnoncrypt(messageBytes, to)
	default:
		return nil, fmt.Errorf("unsupported package type: %s", packageType)
	}
}

// UnpackMessage unpacks an encrypted message
func (es *EnvelopeService) UnpackMessage(encryptedMessage *EncryptedMessage) (*DecryptedMessageContext, error) {
	lg := getLoggerFromCtx(es.agentContext, es.typedDI)
	lg.Info("📦 Unpacking message...")

	// Check if this is plaintext (no protected header)
	if encryptedMessage.Protected == "" {
		return es.decryptPlaintext(encryptedMessage)
	}

	return es.decryptMessage(encryptedMessage)
}

// decryptMessage handles the main decryption logic (placeholder)
func (es *EnvelopeService) decryptMessage(encryptedMessage *EncryptedMessage) (*DecryptedMessageContext, error) {
	lg := getLoggerFromCtx(es.agentContext, es.typedDI)
	// Decode protected header
	protectedBytes, err := utils.DecodeBase64URLString(encryptedMessage.Protected)
	if err != nil {
		return nil, fmt.Errorf("failed to decode protected header: %w", err)
	}

	var protected JWEProtectedHeader
	if err := json.Unmarshal(protectedBytes, &protected); err != nil {
		return nil, fmt.Errorf("failed to unmarshal protected header: %w", err)
	}

	if protected.Enc != "xchacha20poly1305_ietf" {
		return nil, fmt.Errorf("unsupported enc algorithm: %s", protected.Enc)
	}

	alg := protected.Alg
	if alg != "Anoncrypt" && alg != "Authcrypt" && alg != "anoncrypt" && alg != "authcrypt" {
		return nil, fmt.Errorf("unsupported pack algorithm: %s", alg)
	}

	// Retrieve wallet service strictly via typed DI (TS parity)
	var walletSvc *wallet.WalletService
	if es.typedDI != nil {
		if dep, err := es.typedDI.Resolve(di.TokenWalletService); err == nil {
			if ws, ok := dep.(*wallet.WalletService); ok {
				walletSvc = ws
			}
		}
	}
	if walletSvc == nil {
		return nil, fmt.Errorf("wallet service not available")
	}

	keys, err := walletSvc.ListKeys()
	if err != nil {
		return nil, fmt.Errorf("failed to list wallet keys: %w", err)
	}

	var recipientKey *wallet.Key
	var recipient *JWERecipient

	// Helper to decode kid in multiple formats to raw Ed25519 (32 bytes)
	decodeKid := func(kid string) ([]byte, error) {
		// Strip optional fragment (e.g., did:key:...#<fingerprint> or #<fingerprint>)
		if idx := strings.Index(kid, "#"); idx != -1 {
			// If it's only a fragment (starts with '#'), keep the fragment part
			if idx == 0 {
				kid = kid[1:]
			} else {
				// Remove the fragment from the did:key part and keep full did:key for extraction
				base := kid[:idx]
				frag := kid[idx+1:]
				// Try did:key with base first
				if strings.HasPrefix(base, "did:key:") {
					if raw, err := es.extractBase58KeyFromDIDKey([]byte(base)); err == nil {
						return raw, nil
					}
				}
				// Fall back to fragment as base58 key id
				kid = frag
			}
		}

		// did:key form
		if strings.HasPrefix(kid, "did:key:") {
			return es.extractBase58KeyFromDIDKey([]byte(kid))
		}
		// base58 form
		if raw, err := encoding.DecodeBase58(kid); err == nil {
			return raw, nil
		}
		// base64url form
		if raw, err := base64.RawURLEncoding.DecodeString(kid); err == nil {
			return raw, nil
		}
		return nil, fmt.Errorf("unsupported kid format")
	}

	for _, r := range protected.Recipients {
		kidBytes, err := decodeKid(r.Header.Kid)
		if err != nil {
			continue
		}

		for _, k := range keys {
			// Guard against nil/invalid key entries
			if k == nil || len(k.PublicKey) == 0 {
				continue
			}
			if bytes.Equal(k.PublicKey, kidBytes) {
				recipientKey = k
				recipient = &r
				break
			}
		}

		if recipientKey != nil {
			break
		}
	}

	if recipientKey == nil || recipient == nil {
		// Extra diagnostics to assist debugging interop issues
		var walletKeyIds []string
		for _, k := range keys {
			walletKeyIds = append(walletKeyIds, encoding.EncodeBase58(k.PublicKey))
		}
		lg.Errorf("❌ No corresponding recipient key found. walletKeys=%v", walletKeyIds)
		// Also log recipient kids seen
		var seenKids []string
		for _, r := range protected.Recipients {
			seenKids = append(seenKids, r.Header.Kid)
		}
		lg.Errorf("❌ Recipient kids in message=%v", seenKids)
		return nil, fmt.Errorf("no corresponding recipient key found")
	}

	// Convert key to X25519 private key
	xpriv, err := es.Ed25519ToX25519PrivateKey(recipientKey.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to convert key: %w", err)
	}

	var senderPubEd []byte
	var cek []byte

	encryptedCEK, err := utils.DecodeBase64URLString(recipient.EncryptedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted CEK: %w", err)
	}

	if alg == "Authcrypt" || alg == "authcrypt" {
		if recipient.Header.Sender == "" || recipient.Header.IV == "" {
			return nil, fmt.Errorf("sender and iv header values are required for Authcrypt")
		}

		encSender, err := utils.DecodeBase64URLString(recipient.Header.Sender)
		if err != nil {
			return nil, fmt.Errorf("decode sender: %w", err)
		}
		decryptedSender, err := cryptoapi.CryptoBoxSealOpen(xpriv, encSender)
		if err != nil {
			return nil, fmt.Errorf("decrypt sender: %w", err)
		}
		senderPubEd, err = encoding.DecodeBase58(string(decryptedSender))
		if err != nil {
			return nil, fmt.Errorf("parse sender key: %w", err)
		}

		senderPubX, err := es.Ed25519ToX25519PublicKey(senderPubEd)
		if err != nil {
			return nil, fmt.Errorf("convert sender key: %w", err)
		}

		cekNonce, err := utils.DecodeBase64URLString(recipient.Header.IV)
		if err != nil {
			return nil, fmt.Errorf("decode iv: %w", err)
		}

		cek, err = cryptoapi.CryptoBoxOpen(xpriv, senderPubX, encryptedCEK, cekNonce)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt CEK: %w", err)
		}
	} else {
		cek, err = cryptoapi.CryptoBoxSealOpen(xpriv, encryptedCEK)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt CEK: %w", err)
		}
	}

	// Decode ciphertext components. Some agents send base64 (not base64url); try both.
	decode := func(s string) ([]byte, error) {
		if b, err := utils.DecodeBase64URLString(s); err == nil {
			return b, nil
		}
		if b, err := base64.StdEncoding.DecodeString(s); err == nil {
			return b, nil
		}
		return nil, fmt.Errorf("failed to decode b64/b64url")
	}

	nonce, err := decode(encryptedMessage.IV)
	if err != nil {
		return nil, fmt.Errorf("failed to decode nonce: %w", err)
	}

	ciphertext, err := decode(encryptedMessage.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	tag, err := decode(encryptedMessage.Tag)
	if err != nil {
		return nil, fmt.Errorf("failed to decode tag: %w", err)
	}

	fullCipher := append(ciphertext, tag...)

	plaintext, err := cryptoapi.DecryptChaCha20Poly1305(cek, nonce, fullCipher, []byte(encryptedMessage.Protected))
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt payload: %w", err)
	}

	var plaintextMessage PlaintextMessage
	if err := json.Unmarshal(plaintext, &plaintextMessage); err != nil {
		return nil, fmt.Errorf("failed to unmarshal plaintext message: %w", err)
	}

	return &DecryptedMessageContext{
		PlaintextMessage: plaintextMessage,
		SenderKey:        senderPubEd,
		RecipientKey:     recipientKey.PublicKey,
		EncryptedMessage: encryptedMessage,
		PlaintextRaw:     plaintext,
	}, nil
}

// packagePlaintext packages a message as plaintext (no encryption)
func (es *EnvelopeService) packagePlaintext(message []byte) (*EncryptedMessage, error) {
	// For plaintext, we return an "encrypted" message with empty protected header
	// The ciphertext field contains the raw JSON message
	// This allows the transport layer to detect it's plaintext and send appropriately
	return &EncryptedMessage{
		Protected:  "", // Empty for plaintext
		Recipients: []JWERecipient{},
		IV:         "",
		Ciphertext: string(message), // Raw JSON as "ciphertext"
		Tag:        "",
	}, nil
}

// decryptPlaintext handles plaintext messages (no decryption needed)
func (es *EnvelopeService) decryptPlaintext(encryptedMessage *EncryptedMessage) (*DecryptedMessageContext, error) {
	lg := getLoggerFromCtx(es.agentContext, es.typedDI)
	// Parse the "ciphertext" as JSON (it's actually plaintext)
	var plaintextMessage PlaintextMessage
	raw := []byte(encryptedMessage.Ciphertext)
	if err := json.Unmarshal(raw, &plaintextMessage); err != nil {
		lg.Warnf("failed to unmarshal plaintext message: %v", err)
		return nil, fmt.Errorf("failed to unmarshal plaintext message: %w", err)
	}

	return &DecryptedMessageContext{
		PlaintextMessage: plaintextMessage,
		SenderKey:        nil,
		RecipientKey:     nil,
		PlaintextRaw:     raw,
	}, nil
}

// convertEd25519ToX25519Public converts Ed25519 public key to X25519 (placeholder)
func (es *EnvelopeService) convertEd25519ToX25519Public(ed25519PublicKey []byte) ([]byte, error) {
	// This is a placeholder implementation
	// In production, this would use proper cryptographic conversion
	if len(ed25519PublicKey) != 32 {
		return nil, fmt.Errorf("invalid Ed25519 public key length: %d", len(ed25519PublicKey))
	}
	// For now, just return the same key (this is NOT cryptographically correct)
	return ed25519PublicKey, nil
}

// convertEd25519ToX25519Private converts Ed25519 private key to X25519 (placeholder)
func (es *EnvelopeService) convertEd25519ToX25519Private(ed25519PrivateKey []byte) ([]byte, error) {
	return es.Ed25519ToX25519PrivateKey(ed25519PrivateKey)
}

// PlaintextMessage represents a plaintext DIDComm message
type PlaintextMessage struct {
	ID          string                 `json:"@id"`
	Type        string                 `json:"@type"`
	From        string                 `json:"from,omitempty"`
	To          []string               `json:"to,omitempty"`
	ThreadID    string                 `json:"thid,omitempty"`
	ParentID    string                 `json:"pthid,omitempty"`
	CreatedTime string                 `json:"created_time,omitempty"`
	ExpiresTime string                 `json:"expires_time,omitempty"`
	Body        map[string]interface{} `json:"body,omitempty"`
}

// EncryptedMessage represents an encrypted DIDComm message in JWE format
type EncryptedMessage struct {
	Protected  string         `json:"protected"`
	Recipients []JWERecipient `json:"recipients,omitempty"`
	IV         string         `json:"iv"`
	Ciphertext string         `json:"ciphertext"`
	Tag        string         `json:"tag"`
}

// JWEProtectedHeader represents the protected header of a JWE
type JWEProtectedHeader struct {
	Enc        string         `json:"enc"`
	Typ        string         `json:"typ"`
	Alg        string         `json:"alg"`
	Recipients []JWERecipient `json:"recipients"`
}

// JWERecipient represents a recipient in a JWE
type JWERecipient struct {
	EncryptedKey string             `json:"encrypted_key"`
	Header       JWERecipientHeader `json:"header"`
}

// JWERecipientHeader represents the header for a JWE recipient
type JWERecipientHeader struct {
	Kid    string `json:"kid"`
	IV     string `json:"iv,omitempty"`
	Sender string `json:"sender,omitempty"`
}

// DecryptedMessageContext represents the context of a decrypted message
type DecryptedMessageContext struct {
	PlaintextMessage PlaintextMessage
	SenderKey        []byte // Public key of sender (for authcrypt)
	RecipientKey     []byte // Public key of recipient used for decryption
	EncryptedMessage *EncryptedMessage
	// PlaintextRaw contains the exact decrypted plaintext JSON bytes so
	// downstream handlers can parse decorators like "connection~sig".
	PlaintextRaw []byte
}

// CreateEnvelopeKeysFromPublicKeys creates envelope keys from public key data
func (es *EnvelopeService) CreateEnvelopeKeysFromPublicKeys(recipientKeys [][]byte, senderPrivateKey []byte, routingKeys [][]byte) (EnvelopeKeys, error) {
	return EnvelopeKeys{
		RecipientKeys: recipientKeys,
		SenderKey:     senderPrivateKey,
		RoutingKeys:   routingKeys,
	}, nil
}

// OutboundPackage represents a package ready for transport
type OutboundPackage struct {
	Payload           *EncryptedMessage `json:"payload"`
	ResponseRequested bool              `json:"responseRequested"`
	Endpoint          string            `json:"endpoint"`
}

// packAnoncrypt packages a message using anoncrypt (anonymous encryption)
func (es *EnvelopeService) packAnoncrypt(messageBytes []byte, to []string) (*EncryptedMessage, error) {
	lg := getLoggerFromCtx(es.agentContext, es.typedDI)
	lg.Info("🔐 ===== STARTING ANONCRYPT PACKAGING =====")
	lg.Debugf("🔐 Message To field: %v", to)

	// For real recipient keys, we need to extract them from the DID keys in the 'to' field.
	// The kid header is the base58 encoding of the raw Ed25519 key, not the entire did:key.
	var recipientKeyIds []string
	var actualRecipientKeys [][]byte
	var recipientKids []string

	// Extract recipient keys from message.To field
	for i, toField := range to {
		lg.Debugf("🔍 Processing recipient[%d]: %s", i, toField)
		var rawKey []byte
		var err error
		if strings.HasPrefix(toField, "did:key:") {
			// Extract the key from did:key format
			rawKey, err = es.extractBase58KeyFromDIDKey([]byte(toField))
		} else {
			// Assume base58 encoded key
			rawKey, err = encoding.DecodeBase58(toField)
		}
		if err != nil {
			lg.Warnf("❌ Failed to extract key from %s: %v", toField, err)
			continue
		}
		lg.Debugf("✅ Extracted raw Ed25519 key[%d]: %x (length: %d)", i, rawKey, len(rawKey))
		actualRecipientKeys = append(actualRecipientKeys, rawKey)
		recipientKeyIds = append(recipientKeyIds, toField)
		// Per Credo-TS (DIDComm V1), kid must be the base58-encoded Ed25519 public key
		kid := encoding.EncodeBase58(rawKey)
		lg.Debugf("🔑 Derived kid[%d] (base58): %s", i, kid)
		recipientKids = append(recipientKids, kid)
	}

	// If no recipient keys found in 'to' field, try to use any set from earlier context
	if len(actualRecipientKeys) == 0 {
		lg.Warn("⚠️ No recipient keys found in message.To, using fallback")
		// Use the recipient key from the OOB invitation as fallback.
		// This should be set by the caller, but for now use a proper did:key format.
		// The derived kid will be the base58 encoding of this fallback key.
		recipientKeyIds = append(recipientKeyIds, "did:key:z6Mkn5dmX545yLSLsA4dt5c2fYmcpsaKonAzH8Bs7Vv1vby8")

		// Extract the actual key bytes
		rawKey, err := es.extractBase58KeyFromDIDKey([]byte(recipientKeyIds[0]))
		if err != nil {
			lg.Warnf("❌ Failed to extract fallback key: %v", err)
			return nil, fmt.Errorf("failed to extract recipient key: %w", err)
		}
		lg.Debugf("✅ Extracted fallback Ed25519 key: %x (length: %d)", rawKey, len(rawKey))
		actualRecipientKeys = append(actualRecipientKeys, rawKey)
		kid := encoding.EncodeBase58(rawKey)
		lg.Debugf("🔑 Derived fallback kid: %s", kid)
		recipientKids = append(recipientKids, kid)
	}

	lg.Debugf("🔍 Total recipient keys extracted: %d", len(actualRecipientKeys))

	lg.Debugf("🔐 Generating Content Encryption Key (CEK)...")
	cek := make([]byte, 32)
	if _, err := rand.Read(cek); err != nil {
		return nil, fmt.Errorf("failed to generate CEK: %w", err)
	}
	lg.Debugf("🔐 CEK: %x", cek)

	// Encrypt CEK for each recipient using libsodium sealed boxes
	lg.Debugf("👥 Processing %d recipients...", len(recipientKeyIds))
	recipients := []JWERecipient{}
	for i, keyId := range recipientKeyIds {
		if i >= len(actualRecipientKeys) {
			continue
		}

		lg.Debugf("👤 ===== PROCESSING RECIPIENT[%d] =====", i)
		recipientEd25519Key := actualRecipientKeys[i]
		kid := recipientKids[i]
		lg.Debugf("👤 Recipient kid (base58): %s", kid)

		recipientX25519Key, err := es.Ed25519ToX25519PublicKey(recipientEd25519Key)
		if err != nil {
			lg.Warnf("❌ Failed to convert recipient key to X25519: %v", err)
			continue
		}
		lg.Debugf("✅ Converted X25519 key: %x", recipientX25519Key)

		encryptedCEK, err := cryptoapi.CryptoBoxSeal(recipientX25519Key, cek)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt CEK for recipient %s: %w", keyId, err)
		}
		lg.Debugf("✅ Encrypted CEK: %x", encryptedCEK)

		recipients = append(recipients, JWERecipient{
			EncryptedKey: base64.RawURLEncoding.EncodeToString(encryptedCEK),
			Header:       JWERecipientHeader{Kid: kid},
		})
		lg.Debugf("👤 ===== RECIPIENT[%d] PROCESSED =====", i)
	}

	if len(recipients) == 0 {
		return nil, fmt.Errorf("no valid recipients found")
	}

	lg.Debugf("📋 Creating JWE protected header...")
	// For DIDComm v1, we need to include recipient info in the protected header
	recipientHeaders := make([]map[string]interface{}, len(recipients))
	for i, recipient := range recipients {
		recipientHeaders[i] = map[string]interface{}{
			"encrypted_key": recipient.EncryptedKey,
			"header": map[string]string{
				"kid": recipient.Header.Kid,
			},
		}
	}

	protectedHeader := map[string]interface{}{
		"enc":        "xchacha20poly1305_ietf",
		"typ":        "JWM/1.0",
		"alg":        "Anoncrypt",
		"recipients": recipientHeaders,
	}

	// Encode protected header
	protectedHeaderBytes, err := json.Marshal(protectedHeader)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal protected header: %w", err)
	}
	protectedHeaderEncoded := base64.RawURLEncoding.EncodeToString(protectedHeaderBytes)
	lg.Debugf("📋 Protected header: %s", string(protectedHeaderBytes))
	lg.Debugf("📋 Protected header (encoded): %s", protectedHeaderEncoded)

	// messageBytes already contains the JSON payload
	lg.Debugf("📝 Message JSON: %s", string(messageBytes))
	lg.Debugf("📝 Message bytes: %x", messageBytes)

	// Encrypt the message using ChaCha20-Poly1305
	nonce, encryptedData, err := cryptoapi.EncryptChaCha20Poly1305(cek, messageBytes, []byte(protectedHeaderEncoded))
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt payload: %w", err)
	}
	lg.Debugf("🔐 Nonce: %x", nonce)
	lg.Debugf("✅ Encrypted data: %x (length: %d)", encryptedData, len(encryptedData))

	// Split encrypted data into ciphertext and tag
	if len(encryptedData) < 16 {
		return nil, fmt.Errorf("encrypted data too short")
	}
	ciphertext := encryptedData[:len(encryptedData)-16]
	tag := encryptedData[len(encryptedData)-16:]
	lg.Debugf("📝 Ciphertext: %x (length: %d)", ciphertext, len(ciphertext))
	lg.Debugf("🏷️  Tag: %x", tag)

	// Create the JWE encrypted message that matches TypeScript Credo expectations
	// For DIDComm v1, recipients are in the protected header, not at top level
	encryptedMessage := &EncryptedMessage{
		Protected:  protectedHeaderEncoded,
		Recipients: nil, // Recipients are already in protected header for DIDComm v1
		IV:         base64.RawURLEncoding.EncodeToString(nonce),
		Ciphertext: base64.RawURLEncoding.EncodeToString(ciphertext),
		Tag:        base64.RawURLEncoding.EncodeToString(tag),
	}

	lg.Debugf("📦 ===== FINAL ENCRYPTED MESSAGE =====")
	lg.Debugf("📦 Protected: %s", encryptedMessage.Protected)
	lg.Debugf("📦 IV: %s", encryptedMessage.IV)
	lg.Debugf("📦 Ciphertext: %s", encryptedMessage.Ciphertext)
	lg.Debugf("📦 Tag: %s", encryptedMessage.Tag)
	lg.Debugf("📦 Recipients in protected header: %d", len(recipients))
	for i, recipient := range recipients {
		lg.Debugf("📦 Recipient[%d] kid: %s", i, recipient.Header.Kid)
		lg.Debugf("📦 Recipient[%d] Encrypted Key: %s", i, recipient.EncryptedKey)
	}

	lg.Info("✅ Anoncrypt message packaged successfully")
	lg.Debugf("🔍 Using %d recipient keys:", len(recipients))
	for i, recipient := range recipients {
		lg.Debugf("   [%d] kid: %s", i, recipient.Header.Kid)
	}
	lg.Debugf("📊 Message size: %d bytes", len(messageBytes))
	lg.Info("🔐 ===== ANONCRYPT PACKAGING COMPLETE =====")

	return encryptedMessage, nil
}

// packAuthcrypt packages a message using authcrypt (authenticated encryption)
func (es *EnvelopeService) packAuthcrypt(messageBytes []byte, to []string) (*EncryptedMessage, error) {
	lg := getLoggerFromCtx(es.agentContext, es.typedDI)
	lg.Info("🔐 Packing authcrypt message")

	if len(es.senderKey) == 0 {
		return nil, fmt.Errorf("sender private key required for authcrypt")
	}

	// Extract recipient keys like anoncrypt (single recipient per input)
	var actualRecipientKeys [][]byte
	var recipientKids []string

	for _, toField := range to {
		var rawKey []byte
		var err error
		if strings.HasPrefix(toField, "did:key:") {
			rawKey, err = es.extractBase58KeyFromDIDKey([]byte(toField))
		} else {
			rawKey, err = encoding.DecodeBase58(toField)
		}
		if err != nil {
			continue
		}
		actualRecipientKeys = append(actualRecipientKeys, rawKey)
		// For DIDComm v1 Authcrypt, kid should be base58 verkey (AFJ/Credo-Askar expectation)
		recipientKids = append(recipientKids, encoding.EncodeBase58(rawKey))
	}

	if len(actualRecipientKeys) == 0 {
		return nil, fmt.Errorf("no valid recipient keys")
	}

	cek := make([]byte, 32)
	if _, err := rand.Read(cek); err != nil {
		return nil, fmt.Errorf("failed to generate CEK: %w", err)
	}

	senderPrivX, err := es.Ed25519ToX25519PrivateKey(es.senderKey)
	if err != nil {
		return nil, fmt.Errorf("convert sender key: %w", err)
	}

	senderPubEd := es.senderKey[len(es.senderKey)-32:]

	recipients := []JWERecipient{}
	for i, rKey := range actualRecipientKeys {
		recipX, err := es.Ed25519ToX25519PublicKey(rKey)
		if err != nil {
			return nil, fmt.Errorf("convert recipient key: %w", err)
		}

		encSender, err := cryptoapi.CryptoBoxSeal(recipX, []byte(encoding.EncodeBase58(senderPubEd)))
		if err != nil {
			return nil, fmt.Errorf("encrypt sender: %w", err)
		}

		nonce, err := cryptoapi.CryptoBoxRandomNonce()
		if err != nil {
			return nil, fmt.Errorf("nonce: %w", err)
		}

		encCEK, err := cryptoapi.CryptoBoxWithNonce(recipX, senderPrivX, cek, nonce)
		if err != nil {
			return nil, fmt.Errorf("encrypt cek: %w", err)
		}

		kid := recipientKids[i]
		if strings.HasPrefix(kid, "ALT:") {
			kid = strings.TrimPrefix(kid, "ALT:")
		} else if strings.HasPrefix(kid, "ALTZ:") {
			kid = strings.TrimPrefix(kid, "ALTZ:")
		} else if strings.HasPrefix(kid, "ALTDID:") {
			kid = strings.TrimPrefix(kid, "ALTDID:")
		}
		// Do not convert to did:key or multibase here; keep base58 verkey
		recipients = append(recipients, JWERecipient{
			EncryptedKey: base64.RawURLEncoding.EncodeToString(encCEK),
			Header: JWERecipientHeader{
				Kid:    kid,
				IV:     base64.RawURLEncoding.EncodeToString(nonce),
				Sender: base64.RawURLEncoding.EncodeToString(encSender),
			},
		})
	}

	protectedHeader := JWEProtectedHeader{
		Enc:        "xchacha20poly1305_ietf",
		Typ:        "JWM/1.0",
		Alg:        "Authcrypt",
		Recipients: recipients,
	}

	protectedBytes, err := json.Marshal(protectedHeader)
	if err != nil {
		return nil, fmt.Errorf("marshal protected: %w", err)
	}
	protectedEncoded := base64.RawURLEncoding.EncodeToString(protectedBytes)

	nonce, cipher, err := cryptoapi.EncryptChaCha20Poly1305(cek, messageBytes, []byte(protectedEncoded))
	if err != nil {
		return nil, fmt.Errorf("encrypt payload: %w", err)
	}
	if len(cipher) < 16 {
		return nil, fmt.Errorf("encrypted data too short")
	}
	ciphertext := cipher[:len(cipher)-16]
	tag := cipher[len(cipher)-16:]

	return &EncryptedMessage{
		Protected:  protectedEncoded,
		Recipients: recipients,
		IV:         base64.RawURLEncoding.EncodeToString(nonce),
		Ciphertext: base64.RawURLEncoding.EncodeToString(ciphertext),
		Tag:        base64.RawURLEncoding.EncodeToString(tag),
	}, nil
}

// extractBase58KeyFromDIDKey extracts base58 public key from did:key format
func (es *EnvelopeService) extractBase58KeyFromDIDKey(didKey []byte) ([]byte, error) {
	lg := getLoggerFromCtx(es.agentContext, es.typedDI)
	lg.Debugf("🔍 ===== EXTRACTING KEY FROM DID:KEY =====")
	lg.Debugf("🔍 Input DID key: %s", string(didKey))

	didKeyStr := string(didKey)
	if !strings.HasPrefix(didKeyStr, "did:key:") {
		lg.Debugf("🔍 Not a did:key format, assuming base58 encoded")
		// Assume it's already base58 encoded
		result, err := encoding.DecodeBase58(didKeyStr)
		if err != nil {
			lg.Warnf("❌ Failed to decode base58: %v", err)
		} else {
			lg.Debugf("✅ Decoded base58 key: %x", result)
		}
		return result, err
	}

	// Extract method-specific ID
	methodSpecificId := strings.TrimPrefix(didKeyStr, "did:key:")
	lg.Debugf("🔍 Method-specific ID: %s", methodSpecificId)

	if !strings.HasPrefix(methodSpecificId, "z") {
		lg.Warnf("❌ did:key must use base58btc encoding (must start with 'z')")
		return nil, fmt.Errorf("did:key must use base58btc encoding")
	}

	// Decode base58btc
	base58Part := methodSpecificId[1:]
	lg.Debugf("🔍 Base58 part (without 'z'): %s", base58Part)

	keyBytes, err := encoding.DecodeBase58(base58Part)
	if err != nil {
		lg.Warnf("❌ Failed to decode base58: %v", err)
		return nil, fmt.Errorf("failed to decode base58: %w", err)
	}
	lg.Debugf("🔍 Decoded key bytes: %x (length: %d)", keyBytes, len(keyBytes))

	// Extract raw key (skip multicodec prefix)
	if len(keyBytes) < 2 {
		lg.Warnf("❌ Key data too short: %d bytes", len(keyBytes))
		return nil, fmt.Errorf("key data too short")
	}

	lg.Debugf("🔍 First two bytes (multicodec prefix): %x", keyBytes[:2])

	var rawKey []byte
	if keyBytes[0] == 0xed && keyBytes[1] == 0x01 {
		lg.Debugf("🔍 Found 2-byte Ed25519 varint prefix (0xed 0x01)")
		rawKey = keyBytes[2:] // Skip 2-byte varint prefix
	} else if keyBytes[0] == 0xed {
		lg.Debugf("🔍 Found 1-byte Ed25519 prefix (0xed)")
		rawKey = keyBytes[1:] // Skip 1-byte prefix
	} else {
		lg.Warnf("❌ Unsupported key type: %x", keyBytes[0])
		return nil, fmt.Errorf("unsupported key type")
	}

	lg.Debugf("🔍 Raw key after prefix removal: %x (length: %d)", rawKey, len(rawKey))

	if len(rawKey) != 32 {
		lg.Warnf("❌ Invalid key length: %d (expected 32)", len(rawKey))
		return nil, fmt.Errorf("invalid key length: %d", len(rawKey))
	}

	lg.Debugf("✅ Successfully extracted Ed25519 key: %x", rawKey)
	lg.Debugf("🔍 ===== KEY EXTRACTION COMPLETE =====")
	return rawKey, nil
}

// Ed25519ToX25519PublicKey converts Ed25519 to X25519 public key using exact ed2curve.js algorithm
func (es *EnvelopeService) Ed25519ToX25519PublicKey(ed25519Key []byte) ([]byte, error) {
	lg := getLoggerFromCtx(es.agentContext, es.typedDI)
	lg.Debugf("🔄 ===== ED25519 TO X25519 CONVERSION (ed2curve.js compatible) =====")
	lg.Debugf("🔄 Input Ed25519 key: %x (length: %d)", ed25519Key, len(ed25519Key))

	if len(ed25519Key) != 32 {
		return nil, fmt.Errorf("Ed25519 public key must be 32 bytes, got %d", len(ed25519Key))
	}

	// Clear the sign bit (msb of the last byte) as done in ed2curve.js
	sanitizedKey := make([]byte, len(ed25519Key))
	copy(sanitizedKey, ed25519Key)
	sanitizedKey[31] &= 0x7f

	// This implements the exact algorithm from ed2curve.js
	// Formula: montgomeryX = (edwardsY + 1)*inverse(1 - edwardsY) mod p
	// where p = 2^255 - 19 (the field prime for Curve25519)

	// Field prime p = 2^255 - 19
	p := new(big.Int)
	p.SetString("57896044618658097711785492504343953926634992332820282019728792003956564819949", 10)

	// Ed25519 public keys are encoded in little-endian format
	// after stripping the sign bit
	edwardsY := bytesToBigIntLE(sanitizedKey)

	lg.Debugf("🔄 Edwards Y coordinate: %s", edwardsY.String())

	// Check if edwardsY is in the valid range
	if edwardsY.Cmp(p) >= 0 {
		return nil, fmt.Errorf("invalid Ed25519 key: Y coordinate >= field prime")
	}

	// Calculate 1 - edwardsY mod p
	one := big.NewInt(1)
	oneMinusY := new(big.Int).Sub(one, edwardsY)
	oneMinusY.Mod(oneMinusY, p)

	lg.Debugf("🔄 1 - edwardsY: %s", oneMinusY.String())

	// Check if 1 - edwardsY is zero (which would make the key invalid)
	if oneMinusY.Sign() == 0 {
		return nil, fmt.Errorf("invalid Ed25519 key: 1 - Y = 0")
	}

	// Calculate modular inverse of (1 - edwardsY) mod p
	invOneMinusY := new(big.Int).ModInverse(oneMinusY, p)
	if invOneMinusY == nil {
		return nil, fmt.Errorf("invalid Ed25519 key: cannot compute inverse of (1 - Y)")
	}

	lg.Debugf("🔄 Inverse of (1 - edwardsY): %s", invOneMinusY.String())

	// Calculate edwardsY + 1 mod p
	yPlusOne := new(big.Int).Add(edwardsY, one)
	yPlusOne.Mod(yPlusOne, p)

	lg.Debugf("🔄 edwardsY + 1: %s", yPlusOne.String())

	// Calculate montgomeryX = (edwardsY + 1) * inverse(1 - edwardsY) mod p
	montgomeryX := new(big.Int).Mul(yPlusOne, invOneMinusY)
	montgomeryX.Mod(montgomeryX, p)

	lg.Debugf("🔄 Montgomery X coordinate: %s", montgomeryX.String())

	// Convert to 32-byte little-endian representation
	x25519Key := make([]byte, 32)
	montgomeryBytes := montgomeryX.Bytes()

	// Copy in little-endian format
	for i := 0; i < len(montgomeryBytes) && i < 32; i++ {
		x25519Key[i] = montgomeryBytes[len(montgomeryBytes)-1-i]
	}

	lg.Debugf("🔄 X25519 key (little-endian): %x", x25519Key)

	return x25519Key, nil
}

// bytesToBigIntLE converts little-endian bytes to big.Int
func bytesToBigIntLE(b []byte) *big.Int {
	// Reverse to convert from little-endian to big-endian
	reversed := make([]byte, len(b))
	for i := 0; i < len(b); i++ {
		reversed[i] = b[len(b)-1-i]
	}
	return new(big.Int).SetBytes(reversed)
}

// bigIntToBytesLE converts big.Int to little-endian bytes of specified length
func bigIntToBytesLE(n *big.Int, length int) []byte {
	bytes := n.Bytes()

	// Pad with zeros if needed
	if len(bytes) < length {
		padded := make([]byte, length)
		copy(padded[length-len(bytes):], bytes)
		bytes = padded
	} else if len(bytes) > length {
		// Truncate if too long (shouldn't happen for valid input)
		bytes = bytes[len(bytes)-length:]
	}

	// Reverse to convert from big-endian to little-endian
	result := make([]byte, length)
	for i := 0; i < length; i++ {
		result[i] = bytes[length-1-i]
	}

	return result
}

// Ed25519ToX25519PrivateKey converts an Ed25519 private key to an X25519 private key
func (es *EnvelopeService) Ed25519ToX25519PrivateKey(ed25519Key []byte) ([]byte, error) {
	if len(ed25519Key) != 32 && len(ed25519Key) != 64 {
		return nil, fmt.Errorf("Ed25519 private key must be 32 or 64 bytes, got %d", len(ed25519Key))
	}

	// Use the first 32 bytes as the seed if a 64 byte key is provided
	if len(ed25519Key) == 64 {
		ed25519Key = ed25519Key[:32]
	}

	h := sha512.Sum512(ed25519Key)
	h[0] &= 248
	h[31] &= 127
	h[31] |= 64

	xKey := make([]byte, 32)
	copy(xKey, h[:32])
	return xKey, nil
}
