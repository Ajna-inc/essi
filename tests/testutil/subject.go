package testutil

import (
	"encoding/json"

	"github.com/ajna-inc/essi/pkg/core/di"
	transport "github.com/ajna-inc/essi/pkg/didcomm/transport"
)

// SetupSubjectTransports wires two agents to deliver DIDComm envelopes in-memory via subject endpoints.
// For each endpoint, a subject handler is registered that calls the respective agent's MessageReceiver.ReceiveEncrypted.
func SetupSubjectTransports(aDM di.DependencyManager, aEndpoint string, bDM di.DependencyManager, bEndpoint string) {
	// Ensure outbound transports registered on senders happens outside (NewTestAgent can do it)
    if aEndpoint != "" {
        transport.RegisterSubjectEndpoint(aEndpoint, func(payload []byte) (int, []byte, string) {
            if dep, err := aDM.Resolve(di.TokenMessageReceiver); err == nil {
                if mr, ok := dep.(*transport.MessageReceiver); ok && mr != nil {
                    // Deliver encrypted payload and honor inline return-route responses
                    resp, status := mr.ReceiveEncrypted(cloneBytes(payload))
                    if hr, ok := resp.(*transport.HttpResponse); ok && hr != nil && len(hr.Body) > 0 {
                        return status, hr.Body, hr.ContentType
                    }
                    return status, nil, ""
                }
            }
            return 500, nil, ""
        })
    }
    if bEndpoint != "" {
        transport.RegisterSubjectEndpoint(bEndpoint, func(payload []byte) (int, []byte, string) {
            if dep, err := bDM.Resolve(di.TokenMessageReceiver); err == nil {
                if mr, ok := dep.(*transport.MessageReceiver); ok && mr != nil {
                    resp, status := mr.ReceiveEncrypted(cloneBytes(payload))
                    if hr, ok := resp.(*transport.HttpResponse); ok && hr != nil && len(hr.Body) > 0 {
                        return status, hr.Body, hr.ContentType
                    }
                    return status, nil, ""
                }
            }
            return 500, nil, ""
        })
    }
}

func cloneBytes(b []byte) []byte { c := make([]byte, len(b)); copy(c, b); return c }

// EncodeJSON is a small helper to marshal to []byte with panic-free fallback
func EncodeJSON(v interface{}) []byte { b, _ := json.Marshal(v); return b }
