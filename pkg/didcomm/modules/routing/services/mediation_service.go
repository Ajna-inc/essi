package routingservices

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	corectx "github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/core/wallet"
	base "github.com/ajna-inc/essi/pkg/didcomm/messages"
	connsvc "github.com/ajna-inc/essi/pkg/didcomm/modules/connections/services"
	routeMsgs "github.com/ajna-inc/essi/pkg/didcomm/modules/routing/messages"
	routeRecs "github.com/ajna-inc/essi/pkg/didcomm/modules/routing/records"
	envsvc "github.com/ajna-inc/essi/pkg/didcomm/services"
	transport "github.com/ajna-inc/essi/pkg/didcomm/transport"
)

// Import records package for types
// MediationRole, MediationState, and MediationRecord are now defined in records package

// MediatorService handles RFC 0094 forward and RFC 0211 keylist updates
type MediatorService struct {
	ctx           *corectx.AgentContext
	connSvc       *connsvc.ConnectionService
	envSvc        *envsvc.EnvelopeService
	walletSvc     *wallet.WalletService
	mediationRepo routeRecs.Repository
}

func NewMediatorService(ctx *corectx.AgentContext, conn *connsvc.ConnectionService, env *envsvc.EnvelopeService, wal *wallet.WalletService, repo routeRecs.Repository) *MediatorService {
	return &MediatorService{ctx: ctx, connSvc: conn, envSvc: env, walletSvc: wal, mediationRepo: repo}
}

// ProcessForward processes routing/1.0/forward by delivering, or queuing (queue not yet implemented)
func (s *MediatorService) ProcessForward(forward *routeMsgs.Forward, inbound *connsvc.ConnectionRecord) (base.AgentMessage, error) {
	if forward == nil || forward.Msg == nil {
		return nil, fmt.Errorf("invalid forward message")
	}
	// Find recipient connection by key from mediation records
	if s.mediationRepo == nil {
		return nil, fmt.Errorf("mediation repo unavailable")
	}
	recs, err := s.mediationRepo.GetAll(s.ctx)
	if err != nil {
		return nil, err
	}
	var target *routeRecs.MediationRecord
	for _, r := range recs {
		for _, k := range r.RecipientKeys {
			if normalizeBase58(k) == normalizeBase58(forward.To) {
				target = r
				break
			}
		}
		if target != nil {
			break
		}
	}
	if target == nil {
		// Unknown recipient key; drop silently
		log.Printf("⚠️ Mediator has no recipient for key: %s", forward.To)
		return nil, nil
	}
	// Queue the message for pickup tied to the recipient connection
	repo := transport.GetGlobalQueueRepository()
	repo.Add(&transport.QueuedMessage{ConnectionId: target.ConnectionId, Payload: forward.Msg, CreatedAt: time.Now()})
	log.Printf("📥 Queued message for recipient connection %s", target.ConnectionId)
	return nil, nil
}

// ProcessMediationRequest auto-accepts (configurable later) and returns grant
func (s *MediatorService) ProcessMediationRequest(req *routeMsgs.MediationRequest, inbound *connsvc.ConnectionRecord) (base.AgentMessage, error) {
	if inbound == nil {
		return nil, fmt.Errorf("no inbound connection context")
	}
	// Create or update mediation record
	rec := &routeRecs.MediationRecord{
		ID:           inbound.ID,
		Role:         routeRecs.MediationRoleMediator,
		State:        routeRecs.MediationStateRequested,
		ConnectionId: inbound.ID,
		ThreadId:     req.GetThreadId(),
	}
	_ = s.mediationRepo.Save(s.ctx, rec)
	// For now, auto-accept and grant
	// Routing info: use mediator own endpoint and routing keys (none yet)
	endpoint := s.connSvc.GetDefaultServiceEndpoint()
	grant := routeMsgs.NewMediationGrant(req.GetThreadId(), endpoint, []string{})
	rec.State = routeRecs.MediationStateGranted
	rec.Endpoint = endpoint
	_ = s.mediationRepo.Update(s.ctx, rec)
	return grant, nil
}

// ProcessKeylistUpdate handles recipient key add/remove and returns response
func (s *MediatorService) ProcessKeylistUpdate(msg *routeMsgs.KeylistUpdate, inbound *connsvc.ConnectionRecord) (base.AgentMessage, error) {
	if inbound == nil {
		return nil, fmt.Errorf("no inbound connection context")
	}
	// Lookup mediation record
	rec, _ := s.mediationRepo.FindByConnectionId(s.ctx, inbound.ID)
	updated := []routeMsgs.KeylistUpdateResponseItem{}
	for _, u := range msg.Updates {
		switch u.Action {
		case routeMsgs.KeylistUpdateAdd:
			rec.RecipientKeys = append(rec.RecipientKeys, u.RecipientKey)
			updated = append(updated, routeMsgs.KeylistUpdateResponseItem{RecipientKey: u.RecipientKey, Action: u.Action, Result: routeMsgs.KeylistUpdateResultSuccess})
		case routeMsgs.KeylistUpdateRemove:
			// simple remove
			kept := []string{}
			for _, k := range rec.RecipientKeys {
				if k != u.RecipientKey {
					kept = append(kept, k)
				}
			}
			rec.RecipientKeys = kept
			updated = append(updated, routeMsgs.KeylistUpdateResponseItem{RecipientKey: u.RecipientKey, Action: u.Action, Result: routeMsgs.KeylistUpdateResultSuccess})
		default:
			updated = append(updated, routeMsgs.KeylistUpdateResponseItem{RecipientKey: u.RecipientKey, Action: u.Action, Result: routeMsgs.KeylistUpdateResultError})
		}
	}
	_ = s.mediationRepo.Update(s.ctx, rec)
	resp := routeMsgs.NewKeylistUpdateResponse(msg.GetThreadId(), updated)
	return resp, nil
}

// routeMessageSender sends an already packed message to a connection endpoint
func (s *MediatorService) postEncrypted(payload *envsvc.EncryptedMessage, endpoint string) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(s.ctx.Context, "POST", endpoint, bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/didcomm-envelope-enc")
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

// normalizeBase58 returns base58 kid from did:key or base58 input (best-effort)
func normalizeBase58(k string) string {
	if k == "" {
		return ""
	}
	if strings.HasPrefix(k, "did:key:") {
		// did:key:z.. fingerprint; strip prefix 'did:key:' and leading 'z' multibase
		msid := strings.TrimPrefix(k, "did:key:")
		if strings.HasPrefix(msid, "z") {
			// keep as fingerprint; upper layers compare fingerprints too
			return msid
		}
		return msid
	}
	return k
}
