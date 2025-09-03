package services

import (
    "fmt"
    "time"
    
    "github.com/ajna-inc/essi/pkg/core/context"
    "github.com/ajna-inc/essi/pkg/core/events"
    oob "github.com/ajna-inc/essi/pkg/didcomm/modules/oob"
    oobmsgs "github.com/ajna-inc/essi/pkg/didcomm/modules/oob/messages"
)

// HandshakeReuseService encapsulates OOB handshake reuse logic
type HandshakeReuseService struct {
    oobRepository *oob.OutOfBandRepository
    eventBus      events.Bus
}

func NewHandshakeReuseService(oobRepository *oob.OutOfBandRepository, eventBus events.Bus) *HandshakeReuseService {
    return &HandshakeReuseService{oobRepository: oobRepository, eventBus: eventBus}
}

// ProcessHandshakeReuse handles a handshake-reuse message and returns an accepted response
func (s *HandshakeReuseService) ProcessHandshakeReuse(
    agentCtx *context.AgentContext,
    reuse *oobmsgs.HandshakeReuseMessage,
    connection *ConnectionRecord,
) (*oobmsgs.HandshakeReuseAcceptedMessage, error) {
    if reuse == nil {
        return nil, fmt.Errorf("handshake-reuse message is required")
    }
    if connection == nil {
        return nil, fmt.Errorf("no connection associated with incoming message %s", reuse.GetType())
    }
    // Validate required pthid
    parentThreadId := reuse.GetParentThreadId()
    if parentThreadId == "" {
        return nil, fmt.Errorf("handshake-reuse message must have a parent thread id")
    }
    if parentThreadId != "" && s.oobRepository != nil {
        if rec := s.oobRepository.FindByInvitationThreadId(agentCtx, parentThreadId); rec != nil {
            // Credo-TS validations: role=sender, state=await-response, no requests
            if rec.Role != oob.OutOfBandRoleSender {
                return nil, fmt.Errorf("invalid out-of-band record role %s, expected is sender", rec.Role)
            }
            if rec.State != oob.OutOfBandStateAwaitResponse {
                return nil, fmt.Errorf("invalid out-of-band record state %s, valid states are: await-response", rec.State)
            }
            // If invitation has requests, reuse is not allowed
            if inv, ok := rec.OutOfBandInvitation.(interface{ GetRequests() []interface{} }); ok && inv != nil {
                if reqs := inv.GetRequests(); len(reqs) > 0 {
                    return nil, fmt.Errorf("handshake reuse should only be used when no requests are present")
                }
            }
            if !rec.ReusableConnection {
                // Mark OOB record as done
                rec.State = oob.OutOfBandStateDone
                if rec.BaseRecord != nil {
                    rec.BaseRecord.Type = "OutOfBandRecord"
                    if rec.BaseRecord.Tags == nil { rec.BaseRecord.Tags = map[string]string{} }
                    rec.BaseRecord.Tags["state"] = oob.OutOfBandStateDone
                }
                _ = s.oobRepository.Update(agentCtx, rec)
                if s.eventBus != nil {
                    s.eventBus.Publish(oob.OutOfBandEventStateChanged, map[string]interface{}{
                        "outOfBandRecord": rec,
                        "previousState": oob.OutOfBandStateAwaitResponse,
                        "state":         rec.State,
                    })
                }
            }
            // Emit a simple event for parity
            if s.eventBus != nil {
                s.eventBus.Publish(oob.OutOfBandEventHandshakeReused, map[string]interface{}{
                    "reuseThreadId":   reuse.GetThreadId(),
                    "connectionRecord": connection,
                    "outOfBandRecord":  rec,
                })
            }
        }
        if s.oobRepository.FindByInvitationThreadId(agentCtx, parentThreadId) == nil {
            return nil, fmt.Errorf("no out of band record found for handshake-reuse message")
        }
    }
    // Create accepted response threaded to reuse thread and pthid to invitation
    accepted := oobmsgs.NewHandshakeReuseAcceptedMessage(reuse.GetThreadId(), parentThreadId)
    return accepted, nil
}

// CreateHandshakeReuse creates a handshake-reuse message for an existing connection
func (s *HandshakeReuseService) CreateHandshakeReuse(
    agentCtx *context.AgentContext,
    outOfBandRecord *oob.OutOfBandRecord,
    connectionRecord *ConnectionRecord,
) (*oobmsgs.HandshakeReuseMessage, error) {
    if outOfBandRecord == nil {
        return nil, fmt.Errorf("out-of-band record is required")
    }
    if connectionRecord == nil {
        return nil, fmt.Errorf("connection record is required")
    }
    
    // Get invitation ID from OOB record
    invitationId := ""
    if inv, ok := outOfBandRecord.OutOfBandInvitation.(interface{ GetId() string }); ok {
        invitationId = inv.GetId()
    }
    if invitationId == "" {
        return nil, fmt.Errorf("out-of-band invitation must have an ID")
    }
    
    // Store the reuse connection ID on the OOB record (Credo-TS parity)
    outOfBandRecord.ReuseConnectionId = connectionRecord.ID
    outOfBandRecord.UpdatedAt = time.Now()
    if s.oobRepository != nil {
        if err := s.oobRepository.Update(agentCtx, outOfBandRecord); err != nil {
            return nil, fmt.Errorf("failed to update out-of-band record: %w", err)
        }
    }
    
    // Create handshake-reuse message with parent thread ID pointing to invitation
    reuseMessage := oobmsgs.NewHandshakeReuseMessage(invitationId)
    return reuseMessage, nil
}

// ProcessHandshakeReuseAccepted processes a handshake-reuse-accepted message
func (s *HandshakeReuseService) ProcessHandshakeReuseAccepted(
    agentCtx *context.AgentContext,
    accepted *oobmsgs.HandshakeReuseAcceptedMessage,
    connection *ConnectionRecord,
) error {
    if accepted == nil {
        return fmt.Errorf("handshake-reuse-accepted message is required")
    }
    if connection == nil {
        return fmt.Errorf("no connection associated with incoming message")
    }
    
    // Validate required parent thread ID
    parentThreadId := accepted.GetParentThreadId()
    if parentThreadId == "" {
        return fmt.Errorf("handshake-reuse-accepted message must have a parent thread id")
    }
    
    // Find the OOB record
    if s.oobRepository == nil {
        return fmt.Errorf("out-of-band repository not available")
    }
    
    rec := s.oobRepository.FindByInvitationThreadId(agentCtx, parentThreadId)
    if rec == nil {
        return fmt.Errorf("no out of band record found for handshake-reuse-accepted message")
    }
    
    // Assert role and state
    if err := rec.AssertRole(oob.OutOfBandRoleReceiver); err != nil {
        return err
    }
    if err := rec.AssertState(oob.OutOfBandStatePrepareResponse); err != nil {
        return err
    }
    
    // CRITICAL: Validate that the connection matches the one we stored (Credo-TS parity)
    if rec.ReuseConnectionId != connection.ID {
        return fmt.Errorf("handshake-reuse-accepted is not in response to a handshake-reuse message")
    }
    
    // Emit handshake reused event
    if s.eventBus != nil {
        s.eventBus.Publish(oob.OutOfBandEventHandshakeReused, map[string]interface{}{
            "reuseThreadId":    accepted.GetThreadId(),
            "connectionRecord": connection,
            "outOfBandRecord":  rec,
        })
    }
    
    // Update state to done (receiver role is never reusable)
    rec.State = oob.OutOfBandStateDone
    rec.UpdatedAt = time.Now()
    if err := s.oobRepository.Update(agentCtx, rec); err != nil {
        return fmt.Errorf("failed to update out-of-band record: %w", err)
    }
    
    // Emit state changed event
    if s.eventBus != nil {
        s.eventBus.Publish(oob.OutOfBandEventStateChanged, map[string]interface{}{
            "outOfBandRecord": rec,
            "previousState":   oob.OutOfBandStatePrepareResponse,
            "state":          rec.State,
        })
    }
    
    return nil
}


