package handlers

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/ajna-inc/essi/pkg/didcomm/models"
	services "github.com/ajna-inc/essi/pkg/didcomm/modules/connections/services"
	outboundServices "github.com/ajna-inc/essi/pkg/didcomm/services"
	"github.com/ajna-inc/essi/pkg/didcomm/transport"
)

func DidRotateHandlerFunc(ctx *transport.InboundMessageContext) (*models.OutboundMessageContext, error) {
	log.Printf("🔄 (dispatcher) processing did-rotate/1.0/rotate")
	rotateSvc := getDidRotateService(ctx)
	if rotateSvc == nil {
		return nil, fmt.Errorf("did rotate service not configured")
	}
	var msg services.DidRotateMessage
	if err := json.Unmarshal(ctx.Raw, &msg); err != nil {
		return nil, fmt.Errorf("parse did-rotate: %w", err)
	}
	// Find connection by thread id
	connectionSvc := getConnectionService(ctx)
	if connectionSvc == nil {
		return nil, fmt.Errorf("connection service not configured")
	}
	var rec *services.ConnectionRecord
	if conns, err := connectionSvc.GetAllConnections(); err == nil {
		for _, c := range conns {
			if c != nil && c.Tags != nil && c.Tags["threadId"] == msg.GetThreadId() {
				rec = c
				break
			}
		}
	}
	if rec == nil {
		return nil, fmt.Errorf("connection for thread not found")
	}
	ack, err := rotateSvc.ProcessRotate(ctx.AgentContext, &msg, rec)
	if err != nil {
		return nil, err
	}
	if ack != nil {
		outboundCtx, err := outboundServices.GetOutboundMessageContext(ctx.AgentContext, outboundServices.GetOutboundMessageContextParams{
			Message:             ack,
			ConnectionRecord:    rec,
			AssociatedRecord:    rec,
			LastReceivedMessage: &msg,
		})
		if err != nil {
			return nil, err
		}
		return outboundCtx, nil
	}
	return nil, nil
}

func DidRotateAckHandlerFunc(ctx *transport.InboundMessageContext) (*models.OutboundMessageContext, error) {
	log.Printf("✅ (dispatcher) processing did-rotate/1.0/ack")
	rotateSvc := getDidRotateService(ctx)
	if rotateSvc == nil {
		return nil, fmt.Errorf("did rotate service not configured")
	}
	var ack services.DidRotateAckMessage
	if err := json.Unmarshal(ctx.Raw, &ack); err != nil {
		return nil, fmt.Errorf("parse did-rotate ack: %w", err)
	}
	connectionSvc := getConnectionService(ctx)
	if connectionSvc == nil {
		return nil, fmt.Errorf("connection service not configured")
	}
	var rec *services.ConnectionRecord
	if conns, err := connectionSvc.GetAllConnections(); err == nil {
		for _, c := range conns {
			if c != nil && c.Tags != nil && c.Tags["threadId"] == ack.GetThreadId() {
				rec = c
				break
			}
		}
	}
	if rec == nil {
		return nil, fmt.Errorf("connection for thread not found")
	}
	if err := rotateSvc.ProcessRotateAck(ctx.AgentContext, &ack, rec); err != nil {
		return nil, err
	}
	return nil, nil
}

func DidRotateHangupHandlerFunc(ctx *transport.InboundMessageContext) (*models.OutboundMessageContext, error) {
	log.Printf("📞 (dispatcher) processing did-rotate/1.0/hangup")
	rotateSvc := getDidRotateService(ctx)
	if rotateSvc == nil {
		return nil, fmt.Errorf("did rotate service not configured")
	}
	var hang services.HangupMessage
	if err := json.Unmarshal(ctx.Raw, &hang); err != nil {
		return nil, fmt.Errorf("parse hangup: %w", err)
	}
	connectionSvc := getConnectionService(ctx)
	if connectionSvc == nil {
		return nil, fmt.Errorf("connection service not configured")
	}
	var rec *services.ConnectionRecord
	if conns, err := connectionSvc.GetAllConnections(); err == nil {
		for _, c := range conns {
			if c != nil && c.Tags != nil && c.Tags["threadId"] == hang.GetThreadId() {
				rec = c
				break
			}
		}
	}
	if rec == nil {
		return nil, fmt.Errorf("connection for thread not found")
	}
	if err := rotateSvc.ProcessHangup(ctx.AgentContext, &hang, rec); err != nil {
		return nil, err
	}
	return nil, nil
}