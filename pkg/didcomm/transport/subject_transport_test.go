package transport

import (
    "encoding/json"
    "testing"

    envelopeServices "github.com/ajna-inc/essi/pkg/didcomm/services"
)

func TestSubjectOutboundTransport_SendAndReceive(t *testing.T) {
    endpoint := "wss://subject/alice"
    received := make(chan *envelopeServices.EncryptedMessage, 1)

    // Register handler
    RegisterSubjectEndpoint(endpoint, func(payload []byte) (int, []byte, string) {
        var env envelopeServices.EncryptedMessage
        _ = json.Unmarshal(payload, &env)
        received <- &env
        // Echo 200 OK, no body
        return 200, nil, ""
    })
    defer UnregisterSubjectEndpoint(endpoint)

    // Create a dummy encrypted message
    msg := &envelopeServices.EncryptedMessage{ Protected: "hdr", IV: "iv", Ciphertext: "ct", Tag: "tag" }

    // Send
    tr := NewSubjectOutboundTransport()
    if !tr.CanSend(endpoint) { t.Fatalf("transport should be able to send to %s", endpoint) }
    status, body, ctype, err := tr.Send(msg, endpoint)
    if err != nil { t.Fatalf("send failed: %v", err) }
    if status != 200 { t.Fatalf("unexpected status: %d", status) }
    if len(body) != 0 || ctype != "" { t.Fatalf("unexpected response: body=%v ctype=%s", body, ctype) }

    // Verify handler received payload
    select {
    case got := <-received:
        if got.Ciphertext != msg.Ciphertext || got.Tag != msg.Tag { t.Fatalf("unexpected payload: %#v", got) }
    default:
        t.Fatalf("handler did not receive payload")
    }
}

