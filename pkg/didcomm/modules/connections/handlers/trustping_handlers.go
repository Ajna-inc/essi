package handlers

import (
	"encoding/json"
	"fmt"
	"log"

	coreevents "github.com/ajna-inc/essi/pkg/core/events"
	"github.com/ajna-inc/essi/pkg/didcomm/messages"
	"github.com/ajna-inc/essi/pkg/didcomm/models"
	services "github.com/ajna-inc/essi/pkg/didcomm/modules/connections/services"
	outboundServices "github.com/ajna-inc/essi/pkg/didcomm/services"
	"github.com/ajna-inc/essi/pkg/didcomm/transport"
)

type TrustPingMessage struct {
	*messages.BaseMessage
	Comment           string `json:"comment,omitempty"`
	ResponseRequested bool   `json:"response_requested,omitempty"`
}

type TrustPingResponseMessage struct {
	*messages.BaseMessage
	Comment string `json:"comment,omitempty"`
}

// Per Credo TS, the canonical types use underscore: trust_ping
const TrustPingType = "https://didcomm.org/trust_ping/1.0/ping"
const TrustPingResponseType = "https://didcomm.org/trust_ping/1.0/ping_response"

// Also support legacy hyphenated variants (some agents use these)
const TrustPingTypeHyphen = "https://didcomm.org/trust-ping/1.0/ping"
const TrustPingResponseTypeHyphen = "https://didcomm.org/trust-ping/1.0/ping_response"

// TrustPingHandlerFunc replies with a ping_response if requested
func TrustPingHandlerFunc(ctx *transport.InboundMessageContext) (*models.OutboundMessageContext, error) {
	var ping TrustPingMessage
	if err := json.Unmarshal(ctx.Raw, &ping); err != nil {
		return nil, fmt.Errorf("failed to parse trust ping: %w", err)
	}
	log.Printf("🏓 TrustPing received (response_requested=%v)", ping.ResponseRequested)

	if !ping.ResponseRequested {
		// Even if no response was requested, treat receipt of a ping as successful liveness
		// and mark the connection as complete if we can correlate it by thread id.
		if connectionSvc := getConnectionService(ctx); connectionSvc != nil {
			threadID := ping.GetThreadId()
			if threadID != "" {
				if conns, err := connectionSvc.GetAllConnections(); err == nil {
					for _, rec := range conns {
						if rec != nil && rec.Tags != nil && rec.Tags["threadId"] == threadID {
							// Update state to complete
							_ = connectionSvc.UpdateConnectionState(rec.ID, services.ConnectionStateComplete)
							// Emit event
							if bus := getEventBus(ctx); bus != nil {
								bus.Publish(coreevents.EventConnectionStateChanged, map[string]interface{}{
									"connectionId": rec.ID,
									"state":        string(services.ConnectionStateComplete),
								})
							}
							break
						}
					}
				}
			}
		}
		return nil, nil
	}

	// Build response threaded to the ping
	resp := &TrustPingResponseMessage{
		BaseMessage: messages.NewBaseMessage(TrustPingResponseType),
		Comment:     "pong",
	}
	resp.SetThreadId(ping.GetThreadId())

	// Find connection to use - prefer the connection from inbound context
	var connection *services.ConnectionRecord
	if ctx.Connection != nil {
		connection = ctx.Connection
	} else {
		// Fallback: find a connection to send the response
		connectionSvc := getConnectionService(ctx)
		if connectionSvc == nil {
			return nil, fmt.Errorf("connection service not configured")
		}

		// Try to find by thread ID first
		threadID := ping.GetThreadId()
		if threadID != "" {
			if conns, err := connectionSvc.GetAllConnections(); err == nil {
				for _, rec := range conns {
					if rec != nil && rec.Tags != nil && rec.Tags["threadId"] == threadID {
						connection = rec
						break
					}
				}
			}
		}

		// If still no connection, pick the most recent with an endpoint
		if connection == nil {
			conns, err := connectionSvc.GetAllConnections()
			if err != nil || len(conns) == 0 {
				return nil, fmt.Errorf("no connections available to send trust ping response")
			}
			for _, c := range conns {
				if c.TheirEndpoint != "" {
					connection = c
				}
			}
			if connection == nil {
				connection = conns[len(conns)-1]
			}
		}
	}

	// Create outbound context for the response
	outboundCtx, err := outboundServices.GetOutboundMessageContext(
		ctx.AgentContext,
		outboundServices.GetOutboundMessageContextParams{
			Message:             resp,
			ConnectionRecord:    connection,
			AssociatedRecord:    nil,
			LastReceivedMessage: &ping,
		},
	)
	if err != nil {
		log.Printf("❌ Failed to create outbound context for trust ping response: %v", err)
		return nil, err
	}

	// After successfully creating response, mark connection as complete
	if connection != nil {
		_ = getConnectionService(ctx).UpdateConnectionState(connection.ID, services.ConnectionStateComplete)
		if bus := getEventBus(ctx); bus != nil {
			bus.Publish(coreevents.EventConnectionStateChanged, map[string]interface{}{
				"connectionId": connection.ID,
				"state":        string(services.ConnectionStateComplete),
			})
		}
	}

	// Emit message sent event (will be sent by dispatcher)
	if bus := getEventBus(ctx); bus != nil {
		bus.Publish(coreevents.EventMessageSent, map[string]interface{}{
			"type": resp.GetType(),
			"thid": resp.GetThreadId(),
		})
	}

	return outboundCtx, nil
}

// TrustPingResponseHandlerFunc logs receipt of ping response
func TrustPingResponseHandlerFunc(ctx *transport.InboundMessageContext) (*models.OutboundMessageContext, error) {
	var resp TrustPingResponseMessage
	if err := json.Unmarshal(ctx.Raw, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse trust ping response: %w", err)
	}
	log.Printf("🏓✅ TrustPingResponse received")
	// On receiving a ping response, mark the related connection as complete
	if connectionSvc := getConnectionService(ctx); connectionSvc != nil {
		threadID := resp.GetThreadId()
		if threadID != "" {
			if conns, err := connectionSvc.GetAllConnections(); err == nil {
				for _, rec := range conns {
					if rec != nil && rec.Tags != nil && rec.Tags["threadId"] == threadID {
						_ = connectionSvc.UpdateConnectionState(rec.ID, services.ConnectionStateComplete)
						if bus := getEventBus(ctx); bus != nil {
							bus.Publish(coreevents.EventConnectionStateChanged, map[string]interface{}{
								"connectionId": rec.ID,
								"state":        string(services.ConnectionStateComplete),
							})
						}
						break
					}
				}
			}
		}
	}
	return nil, nil
}