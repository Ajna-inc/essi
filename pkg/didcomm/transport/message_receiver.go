package transport

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ajna-inc/essi/pkg/core/common"
	"github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/core/di"
	"github.com/ajna-inc/essi/pkg/core/encoding"
	"github.com/ajna-inc/essi/pkg/core/wallet"
	"github.com/ajna-inc/essi/pkg/didcomm/messages"
	"github.com/ajna-inc/essi/pkg/didcomm/modules/connections/services"
	envelopeServices "github.com/ajna-inc/essi/pkg/didcomm/services"
)

// MessageReceiver handles inbound DIDComm messages via HTTP
type MessageReceiver struct {
	agentContext      *context.AgentContext
	envelopeService   *envelopeServices.EnvelopeService
	connectionService *services.ConnectionService
	dispatcher        *Dispatcher
	typedDI           di.DependencyManager
	httpServer        *http.Server
	isRunning         bool
	mutex             sync.RWMutex
}

// InboundSession represents an inbound transport session
type InboundSession struct {
	ID             string                `json:"id"`
	Keys           *SessionKeys          `json:"keys,omitempty"`
	InboundMessage messages.AgentMessage `json:"inboundMessage,omitempty"`
	ConnectionID   string                `json:"connectionId,omitempty"`
	CreatedAt      time.Time             `json:"createdAt"`
}

// SessionKeys represents the cryptographic keys for a session
type SessionKeys struct {
	RecipientKeys [][]byte `json:"recipientKeys"`
	RoutingKeys   [][]byte `json:"routingKeys"`
	SenderKey     []byte   `json:"senderKey"`
}

// InboundMessageContext represents the context for processing an inbound message
type InboundMessageContext struct {
	Message      messages.AgentMessage      `json:"message"`
	Raw          []byte                     `json:"raw"`
	Connection   *services.ConnectionRecord `json:"connection,omitempty"`
	SessionID    string                     `json:"sessionId,omitempty"`
	ReceivedAt   time.Time                  `json:"receivedAt"`
	SenderKey    []byte                     `json:"senderKey,omitempty"`    // Public key of sender (for authcrypt)
	RecipientKey []byte                     `json:"recipientKey,omitempty"` // Public key used for decryption
	AgentContext *context.AgentContext      `json:"-"`
	TypedDI      di.DependencyManager       `json:"-"`
}

// NewMessageReceiver creates a new message receiver
func NewMessageReceiver(
	agentContext *context.AgentContext,
	envelopeService *envelopeServices.EnvelopeService,
	connectionService *services.ConnectionService,
	dispatcher *Dispatcher,
	dm di.DependencyManager,
) *MessageReceiver {
	return &MessageReceiver{
		agentContext:      agentContext,
		envelopeService:   envelopeService,
		connectionService: connectionService,
		dispatcher:        dispatcher,
		typedDI:           dm,
		isRunning:         false,
	}
}

// StartHTTPServer starts the HTTP server to receive inbound messages
func (mr *MessageReceiver) StartHTTPServer(host string, port int) error {
	mr.mutex.Lock()
	defer mr.mutex.Unlock()

	if mr.isRunning {
		return fmt.Errorf("HTTP server is already running")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", mr.handleInboundMessage)
	mux.HandleFunc("/didcomm", mr.handleInboundMessage)
	mux.HandleFunc("/health", mr.handleHealth)
	mux.HandleFunc("/test", mr.handleTest)

	var address string
	if host == "" || host == "0.0.0.0" {
		// Listen on all interfaces when host is empty or 0.0.0.0
		address = fmt.Sprintf(":%d", port)
	} else {
		address = fmt.Sprintf("%s:%d", host, port)
	}
	mr.httpServer = &http.Server{
		Addr:    address,
		Handler: mux,
	}

	mr.isRunning = true

	// Start server in a goroutine
	go func() {
		log.Printf("🌐 MessageReceiver HTTP server starting on %s", address)
		if err := mr.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("❌ HTTP server error: %v", err)
			mr.mutex.Lock()
			mr.isRunning = false
			mr.mutex.Unlock()
		}
	}()
	return nil
}

// StopHTTPServer stops the HTTP server
func (mr *MessageReceiver) StopHTTPServer() error {
	mr.mutex.Lock()
	defer mr.mutex.Unlock()

	if !mr.isRunning || mr.httpServer == nil {
		return fmt.Errorf("HTTP server is not running")
	}

	log.Printf("🛑 Stopping MessageReceiver HTTP server...")
	if err := mr.httpServer.Close(); err != nil {
		return fmt.Errorf("failed to stop HTTP server: %w", err)
	}

	mr.isRunning = false
	mr.httpServer = nil
	log.Printf("✅ MessageReceiver HTTP server stopped")
	return nil
}

// IsRunning returns whether the HTTP server is running
func (mr *MessageReceiver) IsRunning() bool {
	mr.mutex.RLock()
	defer mr.mutex.RUnlock()
	return mr.isRunning
}

// handleInboundMessage handles incoming DIDComm messages
func (mr *MessageReceiver) handleInboundMessage(w http.ResponseWriter, r *http.Request) {
	log.Printf("📥 Received inbound message: %s %s", r.Method, r.URL.Path)
	log.Printf("📋 Content-Type: %s", r.Header.Get("Content-Type"))
	log.Printf("📋 User-Agent: %s", r.Header.Get("User-Agent"))

	// Only handle POST requests
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read the request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("❌ Failed to read request body: %v", err)
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	log.Printf("📦 Received message size: %d bytes", len(body))

	// Log more details for encrypted messages
	if len(body) > 0 {
		// Try to determine if it's an encrypted message
		var testMsg map[string]interface{}
		if err := json.Unmarshal(body, &testMsg); err == nil {
			if _, hasProtected := testMsg["protected"]; hasProtected {
				log.Printf("🔐 Detected encrypted message with protected header")
			}
			if msgType, hasType := testMsg["@type"]; hasType {
				log.Printf("📨 Message type: %v", msgType)
			}
		}
		log.Printf("🔍 First 500 chars: %s", string(body)[:min(len(body), 500)])
	}

	// Process the message based on content type
	contentType := r.Header.Get("Content-Type")

	var response interface{}
	var statusCode int

	switch contentType {
	case "application/didcomm-envelope-enc":
		response, statusCode = mr.processEncryptedMessage(body)
	case "application/didcomm-encrypted+json", "application/didcomm+json":
		// Common Aries/Credo content types for encrypted payloads
		response, statusCode = mr.processEncryptedMessage(body)
	case "application/json":
		response, statusCode = mr.processPlaintextMessage(body)
	case "application/ssi-agent-wire":
		response, statusCode = mr.processAgentWireMessage(body)
	default:
		// If no content type specified, try to auto-detect
		if contentType == "" {
			log.Printf("⚠️ No content type specified, attempting auto-detection")
			var testMsg map[string]interface{}
			if err := json.Unmarshal(body, &testMsg); err == nil {
				if _, hasProtected := testMsg["protected"]; hasProtected {
					log.Printf("🔐 Auto-detected encrypted message")
					response, statusCode = mr.processEncryptedMessage(body)
				} else {
					log.Printf("📝 Auto-detected plaintext message")
					response, statusCode = mr.processPlaintextMessage(body)
				}
			} else {
				response = map[string]string{"error": "Invalid message format"}
				statusCode = http.StatusBadRequest
			}
		} else {
			log.Printf("⚠️ Unsupported content type: %s", contentType)
			response = map[string]string{
				"error":     "Unsupported content-type",
				"supported": "application/didcomm-envelope-enc, application/json, application/ssi-agent-wire",
			}
			statusCode = http.StatusUnsupportedMediaType
		}
	}

	// Send response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if response != nil {
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Printf("❌ Failed to encode response: %v", err)
		}
	}

	log.Printf("📤 Sent response: %d", statusCode)
}

// processEncryptedMessage processes an encrypted DIDComm message
func (mr *MessageReceiver) processEncryptedMessage(messageData []byte) (interface{}, int) {
	log.Printf("🔓 Processing encrypted message")

	// Parse the encrypted message
	var encryptedMessage envelopeServices.EncryptedMessage
	if err := json.Unmarshal(messageData, &encryptedMessage); err != nil {
		log.Printf("❌ Failed to parse encrypted message: %v", err)
		return map[string]string{"error": "Invalid encrypted message format"}, http.StatusBadRequest
	}

	// Attempt to decrypt the message
	decryptedContext, err := mr.envelopeService.UnpackMessage(&encryptedMessage)
	if err != nil {
		log.Printf("❌ Failed to decrypt message: %v", err)
		// If this message was not for us (no matching recipient key), silently ACK to avoid TS error logs
		if strings.Contains(err.Error(), "no corresponding recipient key found") {
			return nil, http.StatusOK
		}
		return map[string]string{"error": "Failed to decrypt message"}, http.StatusBadRequest
	}

	log.Printf("✅ Message decrypted successfully: %s", decryptedContext.PlaintextMessage.Type)

	// Process the decrypted message
	return mr.processDecryptedMessage(decryptedContext)
}

// processPlaintextMessage processes a plaintext DIDComm message
func (mr *MessageReceiver) processPlaintextMessage(messageData []byte) (interface{}, int) {
	log.Printf("📝 Processing plaintext message")

	var plaintextMessage envelopeServices.PlaintextMessage
	if err := json.Unmarshal(messageData, &plaintextMessage); err != nil {
		log.Printf("❌ Failed to parse plaintext message: %v", err)
		return map[string]string{"error": "Invalid plaintext message format"}, http.StatusBadRequest
	}

	log.Printf("✅ Plaintext message parsed: %s", plaintextMessage.Type)

	// Create a mock decrypted context for processing
	decryptedContext := &envelopeServices.DecryptedMessageContext{
		PlaintextMessage: plaintextMessage,
		SenderKey:        nil,
		RecipientKey:     nil,
		EncryptedMessage: nil,
	}

	return mr.processDecryptedMessage(decryptedContext)
}

// processAgentWireMessage processes an agent wire format message
func (mr *MessageReceiver) processAgentWireMessage(messageData []byte) (interface{}, int) {
	log.Printf("🔌 Processing agent wire message")
	// For now, treat as plaintext
	return mr.processPlaintextMessage(messageData)
}

// processDecryptedMessage processes a decrypted message based on its type
func (mr *MessageReceiver) processDecryptedMessage(ctx *envelopeServices.DecryptedMessageContext) (interface{}, int) {
	// Use the raw plaintext if available so decorators like connection~sig are preserved
	raw := ctx.PlaintextRaw
	if len(raw) == 0 {
		// Fallback to re-marshal if raw not set
		var err error
		raw, err = json.Marshal(ctx.PlaintextMessage)
		if err != nil {
			log.Printf("❌ failed to marshal plaintext: %v", err)
			return map[string]string{"error": "invalid message"}, http.StatusBadRequest
		}
	}

	var base messages.BaseMessage
	if err := json.Unmarshal(raw, &base); err != nil {
		log.Printf("❌ failed to parse base message: %v", err)
		return map[string]string{"error": "invalid message"}, http.StatusBadRequest
	}

	// Log encryption metadata
	if ctx.RecipientKey != nil {
		log.Printf("🔑 Message decrypted with recipient key: %s", encoding.EncodeBase58(ctx.RecipientKey))
	}
	if ctx.SenderKey != nil {
		log.Printf("🔑 Message from sender key: %s", encoding.EncodeBase58(ctx.SenderKey))
	}

	// Try to associate message to a known connection using keys (TS-like):
	// 1) authcrypt sender key -> peer's known keys (TheirRecipientKey normalized OR InvitationKey)
	// 2) recipient key (our key) -> our stored MyKeyId public key
	var associatedConn *services.ConnectionRecord
	conns, err := mr.connectionService.GetAllConnections()
	if err == nil {
		if ctx.SenderKey != nil {
			senderB58 := encoding.EncodeBase58(ctx.SenderKey)
			for _, c := range conns {
				if c == nil {
					continue
				}
				// Normalize TheirRecipientKey to base58 if it's a did:key
				candidate := normalizeKeyToBase58(c.TheirRecipientKey)
				if candidate == senderB58 || c.InvitationKey == senderB58 {
					associatedConn = c
					break
				}
			}
		}
		// Fallback: match by our recipient key (the key we decrypted with) against our stored MyKeyId
		if associatedConn == nil && ctx.RecipientKey != nil && mr.typedDI != nil {
			recB58 := encoding.EncodeBase58(ctx.RecipientKey)
			if dep, derr := mr.typedDI.Resolve(di.TokenWalletService); derr == nil {
				if ws, ok := dep.(*wallet.WalletService); ok && ws != nil {
					for _, c := range conns {
						if c == nil || c.MyKeyId == "" {
							continue
						}
						if key, kerr := ws.GetKey(c.MyKeyId); kerr == nil && key != nil {
							if encoding.EncodeBase58(key.PublicKey) == recB58 {
								associatedConn = c
								break
							}
						}
					}
				}
			}
		}
	}

	inboundCtx := &InboundMessageContext{
		Message:      &base,
		Raw:          raw,
		Connection:   associatedConn,
		SessionID:    "",
		ReceivedAt:   time.Now(),
		SenderKey:    ctx.SenderKey,
		RecipientKey: ctx.RecipientKey,
		AgentContext: mr.agentContext,
		TypedDI:      mr.typedDI,
	}

	// Dispatch now handles sending the response via OutboundMessageContext
	err = mr.dispatcher.Dispatch(inboundCtx)
	if err != nil {
		log.Printf("❌ dispatcher error: %v", err)
		return map[string]string{"error": err.Error()}, http.StatusBadRequest
	}

	// Dispatcher handles all message sending now, we just return 200 OK
	return nil, http.StatusOK
}

// normalizeKeyToBase58 converts a did:key Ed25519 fingerprint to base58 verkey.
// If input is already base58 (no did:key prefix), it is returned as-is.
func normalizeKeyToBase58(k string) string {
	if k == "" {
		return ""
	}
	if strings.HasPrefix(k, "did:key:") {
		msid := strings.TrimPrefix(k, "did:key:")
		if strings.HasPrefix(msid, "z") {
			// Decode multibase base58btc without the leading 'z'
			rawWithCodec, err := encoding.DecodeBase58(msid[1:])
			if err != nil || len(rawWithCodec) < 2 {
				return k
			}
			// Strip 0xed 0x01 (ed25519-pub multicodec) prefix if present
			if rawWithCodec[0] == 0xed && len(rawWithCodec) >= 2 {
				if rawWithCodec[1] == 0x01 && len(rawWithCodec) >= 34 {
					return encoding.EncodeBase58(rawWithCodec[2:])
				}
				// Some encoders may use single-byte 0xed (defensive)
				return encoding.EncodeBase58(rawWithCodec[1:])
			}
			// If no known prefix, fallback
			return k
		}
		return k
	}
	return k
}

// handleHealth handles health check requests
func (mr *MessageReceiver) handleHealth(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"status":  "healthy",
		"service": "Essi-Go-message-receiver",
		"running": mr.IsRunning(),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Failed to encode health response", http.StatusInternalServerError)
	}
}

// handleTest handles test requests
func (mr *MessageReceiver) handleTest(w http.ResponseWriter, r *http.Request) {
	log.Printf("🧪 Test endpoint called: %s %s", r.Method, r.URL.Path)

	response := map[string]interface{}{
		"status":  "ok",
		"service": "Essi-Go-message-receiver",
		"running": mr.IsRunning(),
		"method":  r.Method,
		"headers": r.Header,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Failed to encode test response", http.StatusInternalServerError)
	}
}

// generateMessageID generates a unique message ID
func generateMessageID() string {
	return common.GenerateUUID()
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ReceiveEncrypted allows injecting an encrypted DIDComm message for processing (e.g., return-route responses)
func (mr *MessageReceiver) ReceiveEncrypted(messageData []byte) (interface{}, int) {
	return mr.processEncryptedMessage(messageData)
}
