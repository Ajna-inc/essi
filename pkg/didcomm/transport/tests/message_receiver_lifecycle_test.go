package transport_test

import (
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"testing"
    "time"

	transport "github.com/ajna-inc/essi/pkg/didcomm/transport"
)

// pickFreePort returns a free TCP port by binding to :0 temporarily
func pickFreePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen :0: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func TestMessageReceiver_LifecycleAndHealth(t *testing.T) {
	d := transport.NewDispatcher()
	mr := transport.NewMessageReceiver(nil, nil, nil, d, nil)

	port := pickFreePort(t)
	if err := mr.StartHTTPServer("127.0.0.1", port); err != nil {
		t.Fatalf("start http server: %v", err)
	}
	if !mr.IsRunning() {
		t.Fatalf("expected running after start")
	}

    // Wait for health endpoint to come up instead of sleeping
    url := "http://127.0.0.1:" + strconv.Itoa(port) + "/health"
    deadline := time.Now().Add(2 * time.Second)
    for {
        resp, err := http.Get(url)
        if err == nil && resp != nil {
            resp.Body.Close()
            break
        }
        if time.Now().After(deadline) {
            t.Fatalf("receiver health endpoint did not become ready: %v", err)
        }
        time.Sleep(20 * time.Millisecond)
    }
	// Health endpoint
	// reuse url from above
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("/health status: %d", resp.StatusCode)
	}
	var body map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode health json: %v", err)
	}
	if body["service"] == "" || body["status"] != "healthy" {
		t.Fatalf("unexpected /health body: %#v", body)
	}

	// Test endpoint
	resp2, err := http.Get("http://127.0.0.1:" + strconv.Itoa(port) + "/test")
	if err != nil {
		t.Fatalf("GET /test: %v", err)
	}
	resp2.Body.Close()

	// Stop
	if err := mr.StopHTTPServer(); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if mr.IsRunning() {
		t.Fatalf("expected not running after stop")
	}
}
