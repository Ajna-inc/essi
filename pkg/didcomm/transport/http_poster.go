package transport

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	corectx "github.com/ajna-inc/essi/pkg/core/context"
	envsvc "github.com/ajna-inc/essi/pkg/didcomm/services"
)

type HTTPPoster struct{}

func NewHTTPPoster() *HTTPPoster { return &HTTPPoster{} }

func (p *HTTPPoster) Post(ctx *corectx.AgentContext, payload *envsvc.EncryptedMessage, endpoint string) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx.Context, "POST", endpoint, bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	// Prefer the modern DIDComm v2 media type; most agents accept both
	req.Header.Set("Content-Type", "application/didcomm-encrypted+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("http %d", resp.StatusCode)
	}
	return nil
}
