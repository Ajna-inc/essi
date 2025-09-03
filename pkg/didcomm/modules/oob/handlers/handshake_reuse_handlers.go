package handlers

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/ajna-inc/essi/pkg/core/di"
	"github.com/ajna-inc/essi/pkg/didcomm/models"
	"github.com/ajna-inc/essi/pkg/didcomm/modules/connections/services"
	oob "github.com/ajna-inc/essi/pkg/didcomm/modules/oob"
	oobmsgs "github.com/ajna-inc/essi/pkg/didcomm/modules/oob/messages"
	outboundServices "github.com/ajna-inc/essi/pkg/didcomm/services"
	"github.com/ajna-inc/essi/pkg/didcomm/transport"
)

// OobHandshakeReuseHandlerFunc handles OOB handshake-reuse messages
func OobHandshakeReuseHandlerFunc(ctx *transport.InboundMessageContext) (*models.OutboundMessageContext, error) {
	log.Printf("🔁 Processing oob/1.1/handshake-reuse")
	var reuse oobmsgs.HandshakeReuseMessage
	if err := json.Unmarshal(ctx.Raw, &reuse); err != nil {
		return nil, fmt.Errorf("parse handshake-reuse: %w", err)
	}
	if ctx.Connection == nil {
		return nil, fmt.Errorf("handshake-reuse requires an associated ready connection")
	}
	parentThreadId := reuse.GetParentThreadId()
	if parentThreadId == "" {
		return nil, fmt.Errorf("handshake-reuse message must have a parent thread id")
	}
	log.Printf("🔁 Handshake reuse for invitation %s via connection %s", parentThreadId, ctx.Connection.ID)
	// Prefer dedicated service if available
	if ctx != nil && ctx.TypedDI != nil {
		if dep, err := ctx.TypedDI.Resolve(di.TokenHandshakeReuseService); err == nil {
			if svc, ok := dep.(*services.HandshakeReuseService); ok && svc != nil {
				if accepted, err := svc.ProcessHandshakeReuse(ctx.AgentContext, &reuse, ctx.Connection); err == nil && accepted != nil {
					outboundCtx, err := outboundServices.GetOutboundMessageContext(
						ctx.AgentContext,
						outboundServices.GetOutboundMessageContextParams{
							Message:             accepted,
							ConnectionRecord:    ctx.Connection,
							AssociatedRecord:    ctx.Connection,
							LastReceivedMessage: &reuse,
						},
					)
					if err != nil {
						return nil, err
					}
					// Sender-side state transition: non-reusable invitations move to done
					if depRepo, err := ctx.TypedDI.Resolve(di.TokenOutOfBandRepository); err == nil {
						if repo, ok := depRepo.(*oob.OutOfBandRepository); ok && repo != nil {
							if rec := repo.FindByCreatedInvitationId(ctx.AgentContext, parentThreadId); rec != nil {
								if rec.Role == oob.OutOfBandRoleSender && !rec.ReusableConnection && rec.State != oob.OutOfBandStateDone {
									if depSvc, e2 := ctx.TypedDI.Resolve(di.TokenOutOfBandService); e2 == nil {
										if oobSvc, ok := depSvc.(*oob.OutOfBandService); ok && oobSvc != nil {
											_ = oobSvc.UpdateState(ctx.AgentContext, repo, getEventBus(ctx), rec, oob.OutOfBandStateDone)
										}
									}
								}
							}
						}
					}
					return outboundCtx, nil
				}
			}
		}
	}
	accepted := oobmsgs.NewHandshakeReuseAcceptedMessage(reuse.GetThreadId(), parentThreadId)
	outboundCtx, err := outboundServices.GetOutboundMessageContext(
		ctx.AgentContext,
		outboundServices.GetOutboundMessageContextParams{
			Message:             accepted,
			ConnectionRecord:    ctx.Connection,
			AssociatedRecord:    ctx.Connection,
			LastReceivedMessage: &reuse,
		},
	)
	if err != nil {
		return nil, err
	}
	// Sender-side state transition for non-reusable invitations
	if ctx != nil && ctx.TypedDI != nil {
		if depRepo, err := ctx.TypedDI.Resolve(di.TokenOutOfBandRepository); err == nil {
			if repo, ok := depRepo.(*oob.OutOfBandRepository); ok && repo != nil {
				if rec := repo.FindByCreatedInvitationId(ctx.AgentContext, parentThreadId); rec != nil {
					if rec.Role == oob.OutOfBandRoleSender && !rec.ReusableConnection && rec.State != oob.OutOfBandStateDone {
						if depSvc, e2 := ctx.TypedDI.Resolve(di.TokenOutOfBandService); e2 == nil {
							if oobSvc, ok := depSvc.(*oob.OutOfBandService); ok && oobSvc != nil {
								_ = oobSvc.UpdateState(ctx.AgentContext, repo, getEventBus(ctx), rec, oob.OutOfBandStateDone)
							}
						}
					}
				}
			}
		}
	}
	return outboundCtx, nil
}

// OobHandshakeReuseAcceptedHandlerFunc handles OOB handshake-reuse-accepted messages
func OobHandshakeReuseAcceptedHandlerFunc(ctx *transport.InboundMessageContext) (*models.OutboundMessageContext, error) {
	log.Printf("✅ Processing oob/1.1/handshake-reuse-accepted")
	var accepted oobmsgs.HandshakeReuseAcceptedMessage
	if err := json.Unmarshal(ctx.Raw, &accepted); err != nil {
		return nil, fmt.Errorf("parse handshake-reuse-accepted: %w", err)
	}
	// Publish a reuse event so outbound waiters can proceed
	if bus := getEventBus(ctx); bus != nil {
		payload := map[string]interface{}{
			"reuseThreadId":  accepted.GetThreadId(),
			"parentThreadId": accepted.GetParentThreadId(),
		}
		if ctx.Connection != nil {
			payload["connectionId"] = ctx.Connection.ID
		}
		if ctx.AgentContext != nil {
			payload["contextCorrelationId"] = ctx.AgentContext.GetCorrelationId()
		}
		// Try to enrich with OOB record id (non-mutating)
		if ctx != nil && ctx.TypedDI != nil && ctx.AgentContext != nil {
			if dep, err := ctx.TypedDI.Resolve(di.TokenOutOfBandRepository); err == nil {
				if repo, ok := dep.(*oob.OutOfBandRepository); ok && repo != nil {
					if rec := repo.FindByInvitationThreadId(ctx.AgentContext, accepted.GetParentThreadId()); rec != nil {
						payload["oobRecordId"] = rec.ID
					}
				}
			}
		}
		bus.Publish(oob.OutOfBandEventHandshakeReused, payload)
	}
	// Receiver-side transition to done
	if ctx != nil && ctx.TypedDI != nil && ctx.AgentContext != nil {
		if depRepo, err := ctx.TypedDI.Resolve(di.TokenOutOfBandRepository); err == nil {
			if repo, ok := depRepo.(*oob.OutOfBandRepository); ok && repo != nil {
				if rec := repo.FindByInvitationThreadId(ctx.AgentContext, accepted.GetParentThreadId()); rec != nil {
					if rec.Role == oob.OutOfBandRoleReceiver && rec.State == oob.OutOfBandStatePrepareResponse {
						if depSvc, e2 := ctx.TypedDI.Resolve(di.TokenOutOfBandService); e2 == nil {
							if oobSvc, ok := depSvc.(*oob.OutOfBandService); ok && oobSvc != nil {
								_ = oobSvc.UpdateState(ctx.AgentContext, repo, getEventBus(ctx), rec, oob.OutOfBandStateDone)
							}
						}
					}
				}
			}
		}
	}
	return nil, nil
}
