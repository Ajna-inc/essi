package transport_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	envelopeServices "github.com/ajna-inc/essi/pkg/didcomm/services"
	transport "github.com/ajna-inc/essi/pkg/didcomm/transport"
)

func TestHttpOutboundTransport_Send_Success(t *testing.T) {
	// Create a test server that validates content type and echoes 200
	var gotCT string
	var gotBody envelopeServices.EncryptedMessage
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCT = r.Header.Get("Content-Type")
		defer r.Body.Close()
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	tr := transport.NewHttpOutboundTransport()
	if !tr.CanSend(srv.URL) {
		t.Fatalf("expected CanSend true for %s", srv.URL)
	}

	msg := &envelopeServices.EncryptedMessage{Protected: "hdr", IV: "iv", Ciphertext: "ct", Tag: "tag"}
	status, body, ctype, err := tr.Send(msg, srv.URL)
	if err != nil {
		t.Fatalf("Send failed: %v", err)
	}
	if status != 200 {
		t.Fatalf("unexpected status: %d", status)
	}
	if gotCT != "application/didcomm-envelope-enc" {
		t.Fatalf("unexpected Content-Type header: %s", gotCT)
	}
	if string(body) != "ok" || ctype != "text/plain" {
		t.Fatalf("unexpected response body/ctype: %q / %q", string(body), ctype)
	}
	if gotBody.Ciphertext != msg.Ciphertext || gotBody.Tag != msg.Tag {
		t.Fatalf("server received unexpected message: %#v", gotBody)
	}
}

func TestHttpOutboundTransport_Send_ErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(418)
		_, _ = w.Write([]byte("teapot"))
	}))
	defer srv.Close()

	tr := transport.NewHttpOutboundTransport()
	msg := &envelopeServices.EncryptedMessage{Protected: "hdr", IV: "iv", Ciphertext: "ct", Tag: "tag"}
	status, body, _, err := tr.Send(msg, srv.URL)
	if err == nil {
		t.Fatalf("expected error for non-2xx status")
	}
	if status != 418 || string(body) != "teapot" {
		t.Fatalf("unexpected status/body: %d %q", status, string(body))
	}
}
