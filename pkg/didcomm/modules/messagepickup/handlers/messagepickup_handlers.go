package handlers

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/ajna-inc/essi/pkg/core/di"
	"github.com/ajna-inc/essi/pkg/didcomm/messages"
	"github.com/ajna-inc/essi/pkg/didcomm/models"
	connservices "github.com/ajna-inc/essi/pkg/didcomm/modules/connections/services"
	mpv1 "github.com/ajna-inc/essi/pkg/didcomm/modules/messagepickup/v1"
	mpv2 "github.com/ajna-inc/essi/pkg/didcomm/modules/messagepickup/v2"
	envelopeServices "github.com/ajna-inc/essi/pkg/didcomm/services"
	"github.com/ajna-inc/essi/pkg/didcomm/transport"
)

// V1BatchHandlerFunc unpacks messages from a pickup batch and feeds them to dispatcher
func V1BatchHandlerFunc(ctx *transport.InboundMessageContext) (*models.OutboundMessageContext, error) {
	var batch V1Batch
	if err := json.Unmarshal(ctx.Raw, &batch); err != nil {
		return nil, fmt.Errorf("parse v1 batch: %w", err)
	}
	// Resolve dependencies
	connectionSvc := getConnectionService(ctx)
	if connectionSvc == nil {
		return nil, nil
	}
	var env *envelopeServices.EnvelopeService
	if ctx != nil && ctx.TypedDI != nil {
		if dep, err := ctx.TypedDI.Resolve(di.TokenEnvelopeService); err == nil {
			env, _ = dep.(*envelopeServices.EnvelopeService)
		}
	}
	if env == nil {
		return nil, nil
	}
	for _, att := range batch.Messages {
		// Marshal message to EncryptedMessage and decrypt
		b, _ := json.Marshal(att.Message)
		var enc envelopeServices.EncryptedMessage
		if err := json.Unmarshal(b, &enc); err != nil {
			continue
		}
		dec, err := env.UnpackMessage(&enc)
		if err != nil {
			continue
		}
		// Dispatch decrypted plaintext
		var base messages.BaseMessage
		raw := dec.PlaintextRaw
		if len(raw) == 0 {
			raw, _ = json.Marshal(dec.PlaintextMessage)
		}
		if err := json.Unmarshal(raw, &base); err != nil {
			continue
		}
		inbound := &transport.InboundMessageContext{Message: &base, Raw: raw, SenderKey: dec.SenderKey, RecipientKey: dec.RecipientKey, AgentContext: ctx.AgentContext, TypedDI: ctx.TypedDI}
		if d := transport.GetDispatcher(); d != nil {
			_ = d.Dispatch(inbound)
		}
	}
	// No synchronous response
	return nil, nil
}

// V1BatchPickupHandlerFunc creates a minimal batch response (no attached messages yet)
func V1BatchPickupHandlerFunc(ctx *transport.InboundMessageContext) (*models.OutboundMessageContext, error) {
	var pickup mpv1.V1BatchPickup
	if err := json.Unmarshal(ctx.Raw, &pickup); err != nil {
		return nil, fmt.Errorf("parse v1 batch-pickup: %w", err)
	}
	// Pull queued messages for this connection
	// Pop up to batchSize queued messages for this connection
	n := pickup.BatchSize
	if n < 0 {
		n = 0
	}
	popped := transport.GetGlobalQueueRepository().PopByConnection(ctx.Connection.ID, n)
	attaches := make([]mpv1.V1BatchAttachment, 0, len(popped))
	for i := 0; i < len(popped); i++ {
		em := popped[i].Payload
		attaches = append(attaches, mpv1.V1BatchAttachment{Id: messages.NewBaseMessage("id").GetId(), Message: em})
	}
	// Build batch response
	batch := mpv1.V1Batch{BaseMessage: messages.NewBaseMessage(mpv1.V1BatchType), Messages: attaches}
	batch.SetThreadId(pickup.GetThreadId())
	out := models.NewOutboundMessageContext(batch, models.OutboundMessageContextParams{AgentContext: ctx.AgentContext, Connection: ctx.Connection})
	return out, nil
}

// V2DeliveryHandlerFunc unpacks attachments and dispatches
func V2DeliveryHandlerFunc(ctx *transport.InboundMessageContext) (*models.OutboundMessageContext, error) {
	var del mpv2.V2Delivery
	if err := json.Unmarshal(ctx.Raw, &del); err != nil {
		return nil, fmt.Errorf("parse v2 delivery: %w", err)
	}
	// Resolve envelope service
	var env2 *envelopeServices.EnvelopeService
	if ctx != nil && ctx.TypedDI != nil {
		if dep, err := ctx.TypedDI.Resolve(di.TokenEnvelopeService); err == nil {
			env2, _ = dep.(*envelopeServices.EnvelopeService)
		}
	}
	if env2 == nil {
		return nil, nil
	}
	ackIds := []string{}
	for _, att := range del.Attachments {
		// Prefer json payload for encrypted message
		if att.Data.Json != nil {
			b, _ := json.Marshal(att.Data.Json)
			var enc envelopeServices.EncryptedMessage
			if err := json.Unmarshal(b, &enc); err != nil {
				continue
			}
			if dec, err := env2.UnpackMessage(&enc); err == nil {
				var base messages.BaseMessage
				raw := dec.PlaintextRaw
				if len(raw) == 0 {
					raw, _ = json.Marshal(dec.PlaintextMessage)
				}
				if err := json.Unmarshal(raw, &base); err == nil {
					inbound := &transport.InboundMessageContext{Message: &base, Raw: raw, SenderKey: dec.SenderKey, RecipientKey: dec.RecipientKey, AgentContext: ctx.AgentContext, TypedDI: ctx.TypedDI}
					if d := transport.GetDispatcher(); d != nil {
						_ = d.Dispatch(inbound)
					}
					ackIds = append(ackIds, att.Id)
				}
			}
		}
	}
	// Send messages-received ack (no direct response body expected; will be sent outbound by caller if needed)
	// We return nil to avoid HTTP inline response in this handler.
	return nil, nil
}

// V2StatusRequestHandlerFunc returns the number of queued messages for the connection
func V2StatusRequestHandlerFunc(ctx *transport.InboundMessageContext) (*models.OutboundMessageContext, error) {
	var req mpv2.V2StatusRequest
	if err := json.Unmarshal(ctx.Raw, &req); err != nil {
		return nil, fmt.Errorf("parse v2 status-request: %w", err)
	}
	repo := transport.GetGlobalQueueRepository()
	list := repo.GetByConnection(ctx.Connection.ID)
	// Count queued and delivered (not acked). Ready if queued > 0
	queued := 0
	delivered := 0
	var oldest, newest int64
	totalBytes := 0
	for _, m := range list {
		if m == nil {
			continue
		}
		if m.Status == transport.QueueStatusQueued {
			queued++
			ts := m.CreatedAt.Unix()
			if oldest == 0 || ts < oldest {
				oldest = ts
			}
			if newest == 0 || ts > newest {
				newest = ts
			}
			if m.Payload != nil {
				if b, err := json.Marshal(m.Payload); err == nil {
					totalBytes += len(b)
				}
			}
		} else if m.Status == transport.QueueStatusDelivered {
			delivered++
		}
	}
	// Build status payload matching Credo-TS DidCommStatusV2Message
	// - message_count: number of queued (not yet delivered) messages
	// - longest_waited_seconds: seconds since oldest queued message
	// - newest_received_time / oldest_received_time: RFC3339 timestamps
	// - live_delivery: mediator live-delivery support (false for queue-only)
	var oldestTimeStr, newestTimeStr string
	var longestWaited int
	if oldest > 0 {
		oldestTime := time.Unix(oldest, 0).UTC()
		oldestTimeStr = oldestTime.Format(time.RFC3339)
		longestWaited = int(time.Since(oldestTime).Seconds())
	}
	if newest > 0 {
		newestTime := time.Unix(newest, 0).UTC()
		newestTimeStr = newestTime.Format(time.RFC3339)
	}
	status := struct {
		*messages.BaseMessage
		MessageCount         int    `json:"message_count"`
		RecipientKey         string `json:"recipient_key,omitempty"`
		LongestWaitedSeconds int    `json:"longest_waited_seconds,omitempty"`
		NewestReceivedTime   string `json:"newest_received_time,omitempty"`
		OldestReceivedTime   string `json:"oldest_received_time,omitempty"`
		TotalBytes           int    `json:"total_bytes,omitempty"`
		LiveDelivery         bool   `json:"live_delivery,omitempty"`
	}{BaseMessage: messages.NewBaseMessage(mpv2.V2StatusType), MessageCount: queued, RecipientKey: req.RecipientKey, LongestWaitedSeconds: longestWaited, NewestReceivedTime: newestTimeStr, OldestReceivedTime: oldestTimeStr, TotalBytes: totalBytes, LiveDelivery: false}
	status.SetThreadId(req.GetThreadId())
	out := models.NewOutboundMessageContext(status, models.OutboundMessageContextParams{AgentContext: ctx.AgentContext, Connection: ctx.Connection})
	return out, nil
}

// V2DeliveryRequestHandlerFunc returns up to limit queued messages as attachments
func V2DeliveryRequestHandlerFunc(ctx *transport.InboundMessageContext) (*models.OutboundMessageContext, error) {
	var req mpv2.V2DeliveryRequest
	if err := json.Unmarshal(ctx.Raw, &req); err != nil {
		return nil, fmt.Errorf("parse v2 delivery-request: %w", err)
	}
	repo := transport.GetGlobalQueueRepository()
	// select up to limit from queued items; mark delivered in repo implementation
	popped := repo.PopByConnection(ctx.Connection.ID, req.Limit)
	sel := popped
	atts := make([]mpv2.Attachment, 0, len(sel))
	for _, qm := range sel {
		b, _ := json.Marshal(qm.Payload)
		var jsonMap map[string]interface{}
		_ = json.Unmarshal(b, &jsonMap)
		atts = append(atts, mpv2.Attachment{Id: qm.ID, Data: mpv2.AttachmentData{Json: jsonMap}})
	}
	del := mpv2.V2Delivery{BaseMessage: messages.NewBaseMessage(mpv2.V2DeliveryType), RecipientKey: req.RecipientKey, Attachments: atts}
	del.SetThreadId(req.GetThreadId())
	out := models.NewOutboundMessageContext(del, models.OutboundMessageContextParams{AgentContext: ctx.AgentContext, Connection: ctx.Connection})
	return out, nil
}

// V2MessagesReceivedHandlerFunc acknowledges delivered message ids (no response)
func V2MessagesReceivedHandlerFunc(ctx *transport.InboundMessageContext) (*models.OutboundMessageContext, error) {
	var ack mpv2.V2MessagesReceived
	if err := json.Unmarshal(ctx.Raw, &ack); err != nil {
		return nil, fmt.Errorf("parse v2 messages-received: %w", err)
	}
	// Delete acknowledged messages from queue
	if len(ack.MessageIdList) > 0 {
		_ = transport.GetGlobalQueueRepository().DeleteByIDs(ack.MessageIdList)
	}
	return nil, nil
}

// getConnectionService resolves connection service from DI context
func getConnectionService(ctx *transport.InboundMessageContext) *connservices.ConnectionService {
	if ctx != nil && ctx.TypedDI != nil {
		if dep, err := ctx.TypedDI.Resolve(di.TokenConnectionService); err == nil {
			if svc, ok := dep.(*connservices.ConnectionService); ok {
				return svc
			}
		}
	}
	return nil
}
