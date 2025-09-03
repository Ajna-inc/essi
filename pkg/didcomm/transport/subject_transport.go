package transport

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"

	"github.com/ajna-inc/essi/pkg/core/common"
	"github.com/ajna-inc/essi/pkg/didcomm/models"
	connmessages "github.com/ajna-inc/essi/pkg/didcomm/modules/connections/messages"
	connservices "github.com/ajna-inc/essi/pkg/didcomm/modules/connections/services"
	envelopeServices "github.com/ajna-inc/essi/pkg/didcomm/services"
)

// SubjectHandler is a callback that handles an encrypted DIDComm message for a given endpoint.
// It returns HTTP-like status, response body (optional), and content type.
type SubjectHandler func(payload []byte) (int, []byte, string)

var (
	subjectMu   sync.RWMutex
	subjectSubs = map[string]SubjectHandler{}
)

// RegisterSubjectEndpoint registers a handler for an in-memory subject endpoint (e.g., wss://subject/alice)
func RegisterSubjectEndpoint(endpoint string, handler SubjectHandler) {
	subjectMu.Lock()
	defer subjectMu.Unlock()
	subjectSubs[normalizeSubjectEndpoint(endpoint)] = handler
}

// UnregisterSubjectEndpoint removes a subject handler
func UnregisterSubjectEndpoint(endpoint string) {
	subjectMu.Lock()
	defer subjectMu.Unlock()
	delete(subjectSubs, normalizeSubjectEndpoint(endpoint))
}

func normalizeSubjectEndpoint(endpoint string) string {
	// Treat endpoints consistently: lowercase scheme/host, preserve path
	u, err := url.Parse(endpoint)
	if err != nil {
		return strings.ToLower(endpoint)
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	return u.String()
}

// SubjectOutboundTransport delivers encrypted DIDComm messages to in-memory handlers keyed by endpoint
type SubjectOutboundTransport struct{}

func NewSubjectOutboundTransport() *SubjectOutboundTransport { return &SubjectOutboundTransport{} }

// CanSend returns true for wss://subject/... and ws://subject/...
func (t *SubjectOutboundTransport) CanSend(endpoint string) bool {
	u, err := url.Parse(endpoint)
	if err != nil {
		return false
	}
	if u.Host != "subject" {
		return false
	}
	return u.Scheme == "wss" || u.Scheme == "ws"
}

// Send dispatches the encrypted message to the registered subject handler
func (t *SubjectOutboundTransport) Send(encryptedMessage *envelopeServices.EncryptedMessage, endpoint string) (int, []byte, string, error) {
	subjectMu.RLock()
	handler, ok := subjectSubs[normalizeSubjectEndpoint(endpoint)]
	subjectMu.RUnlock()
	if !ok {
		return 0, nil, "", fmt.Errorf("no subject handler for endpoint %s", endpoint)
	}
	// Serialize to JSON bytes
	payload, err := json.Marshal(encryptedMessage)
	if err != nil {
		return 0, nil, "", fmt.Errorf("failed to marshal encrypted message: %w", err)
	}
	status, body, ctype := handler(payload)
	return status, body, ctype, nil
}

// ConnectionRequestHandler handles a connections/1.0 request in tests
func ConnectionRequestHandler(inbound *InboundMessageContext) (*models.OutboundMessageContext, error) {
	if inbound == nil || inbound.Message == nil {
		return nil, fmt.Errorf("invalid inbound context")
	}
	// Build a minimal response and outbound context
	rec := connservices.NewConnectionRecord("temp")
	rec.State = connservices.ConnectionStateResponded
	resp := connmessages.NewConnectionResponseMessage()
	resp.SetThreadId(common.GenerateUUID())
	out := models.NewOutboundMessageContext(resp, models.OutboundMessageContextParams{AgentContext: inbound.AgentContext, Connection: rec})
	return out, nil
}

// DidExchangeResponseHandler handles a didexchange/1.1 response in tests
func DidExchangeResponseHandler(inbound *InboundMessageContext) (*models.OutboundMessageContext, error) {
	if inbound == nil || inbound.Message == nil {
		return nil, fmt.Errorf("invalid inbound context")
	}
	return &models.OutboundMessageContext{AgentContext: inbound.AgentContext}, nil
}
