package transport

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	envelopeServices "github.com/ajna-inc/essi/pkg/didcomm/services"
)

// OutboundTransport defines how to send encrypted DIDComm messages to endpoints
type OutboundTransport interface {
    CanSend(endpoint string) bool
    // Send returns response status, body and content type if any
    Send(encryptedMessage *envelopeServices.EncryptedMessage, endpoint string) (int, []byte, string, error)
}

// HttpOutboundTransport sends messages over HTTP(S)
type HttpOutboundTransport struct{}

func NewHttpOutboundTransport() *HttpOutboundTransport { return &HttpOutboundTransport{} }

func (t *HttpOutboundTransport) CanSend(endpoint string) bool {
	return len(endpoint) > 0 && (startsWith(endpoint, "http://") || startsWith(endpoint, "https://"))
}

func (t *HttpOutboundTransport) Send(encryptedMessage *envelopeServices.EncryptedMessage, endpoint string) (int, []byte, string, error) {
	messageData, err := json.Marshal(encryptedMessage)
    if err != nil {
        return 0, nil, "", fmt.Errorf("failed to marshal encrypted message: %w", err)
    }

	log.Printf("📮 [http] Sending encrypted message to: %s", endpoint)
	log.Printf("📦 Message size: %d bytes", len(messageData))

	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(messageData))
    if err != nil {
        return 0, nil, "", fmt.Errorf("failed to create request: %w", err)
    }

	req.Header.Set("Content-Type", "application/didcomm-envelope-enc")
	req.Header.Set("User-Agent", "Essi-Go/1.0")

	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
    if err != nil {
        return 0, nil, "", fmt.Errorf("failed to send message: %w", err)
    }
	defer resp.Body.Close()

	// Read response (best effort)
	responseBody, _ := io.ReadAll(resp.Body)
	log.Printf("📥 [http] Received response: %d", resp.StatusCode)
    ctype := resp.Header.Get("Content-Type")
    if len(responseBody) > 0 {
        log.Printf("📋 [http] Response body: %s", string(responseBody))
    }

    if resp.StatusCode >= 400 {
        return resp.StatusCode, responseBody, ctype, fmt.Errorf("received error status code: %d, body: %s", resp.StatusCode, string(responseBody))
    }
    return resp.StatusCode, responseBody, ctype, nil
}

func startsWith(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

