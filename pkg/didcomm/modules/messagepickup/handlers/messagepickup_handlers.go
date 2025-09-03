package handlers

import (
	"encoding/json"
	"fmt"

	"github.com/ajna-inc/essi/pkg/core/di"
	"github.com/ajna-inc/essi/pkg/didcomm/messages"
	"github.com/ajna-inc/essi/pkg/didcomm/models"
	"github.com/ajna-inc/essi/pkg/didcomm/transport"
	connservices "github.com/ajna-inc/essi/pkg/didcomm/modules/connections/services"
	mpv2 "github.com/ajna-inc/essi/pkg/didcomm/modules/messagepickup/v2"
	envelopeServices "github.com/ajna-inc/essi/pkg/didcomm/services"
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