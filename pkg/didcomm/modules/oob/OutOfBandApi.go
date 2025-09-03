package oob

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/core/di"
	"github.com/ajna-inc/essi/pkg/core/events"
	"github.com/ajna-inc/essi/pkg/core/logger"
	"github.com/ajna-inc/essi/pkg/core/storage"
	"github.com/ajna-inc/essi/pkg/core/common"
	"github.com/ajna-inc/essi/pkg/core/encoding"
	"github.com/ajna-inc/essi/pkg/core/utils"
	"github.com/ajna-inc/essi/pkg/core/wallet"
	didcommmsgs "github.com/ajna-inc/essi/pkg/didcomm/messages"
	conmsg "github.com/ajna-inc/essi/pkg/didcomm/modules/connections/messages"
	messages_oob "github.com/ajna-inc/essi/pkg/didcomm/modules/oob/messages"
	"github.com/ajna-inc/essi/pkg/dids"
	keyresolver "github.com/ajna-inc/essi/pkg/dids/methods/key"
)

// OutOfBandApi provides the public API for out-of-band invitations
// This is a placeholder implementation to avoid import cycles
// Full implementation will be added when all dependencies are ready
type OutOfBandApi struct {
	eventEmitter events.Bus
	logger       logger.Logger
	agentContext *context.AgentContext
}

// NewOutOfBandApi creates a new OutOfBandApi instance
func NewOutOfBandApi(
	eventEmitter events.Bus,
	logger logger.Logger,
	agentContext *context.AgentContext,
) *OutOfBandApi {
	return &OutOfBandApi{
		eventEmitter: eventEmitter,
		logger:       logger,
		agentContext: agentContext,
	}
}

// CreateInvitation creates an out-of-band invitation
func (api *OutOfBandApi) CreateInvitation(config CreateOutOfBandInvitationConfig) (*OutOfBandRecord, error) {
	if api == nil || api.agentContext == nil {
		return nil, fmt.Errorf("agent context not available")
	}
	// Build invitation message
	label := config.Label
	inv := messages_oob.NewOutOfBandInvitationMessage(label)
	if config.ImageUrl != "" {
		inv.SetImageUrl(config.ImageUrl)
	}
	// Validations (Credo-TS parity)
	hasMessages := len(config.Messages) > 0
	handshakeEnabled := true
	if config.Handshake != nil {
		handshakeEnabled = *config.Handshake
	}
	if !handshakeEnabled && !hasMessages {
		return nil, fmt.Errorf("one or both of handshake_protocols and requests~attach MUST be included in the message")
	}
	if !handshakeEnabled && len(config.HandshakeProtocols) > 0 {
		return nil, fmt.Errorf("attribute 'handshake' can not be 'false' when 'handshakeProtocols' is defined")
	}
	if hasMessages && config.MultiUseInvitation != nil && *config.MultiUseInvitation {
		return nil, fmt.Errorf("attribute 'multiUseInvitation' can not be 'true' when 'messages' is defined")
	}

	// Handshake protocols
	if handshakeEnabled && len(config.HandshakeProtocols) > 0 {
		for _, p := range config.HandshakeProtocols {
			inv.AddHandshakeProtocol(string(p), []string{})
		}
	} else if handshakeEnabled {
		// default to didexchange 1.1
		inv.AddHandshakeProtocol(string(HandshakeProtocolDidExchange), []string{})
	}

	// Validate mutual exclusivity of InvitationDid and Routing (parity with TS)
	if config.InvitationDid != "" && config.Routing != nil {
		return nil, fmt.Errorf("both 'routing' and 'invitationDid' cannot be provided at the same time")
	}

	// Determine services to include
	var inlineGeneratedKeyId string
	if config.InvitationDid != "" {
		// DID-based invitation
		if err := inv.AddDidService(config.InvitationDid); err != nil {
			return nil, err
		}
	} else {
		// Prefer explicit routing config -> else agent endpoints -> else no inline service
		var endpoint string
		if config.Routing != nil && len(config.Routing.Endpoints) > 0 {
			endpoint = config.Routing.Endpoints[0]
		} else if api.agentContext.Config != nil && len(api.agentContext.Config.Endpoints) > 0 {
			endpoint = api.agentContext.Config.Endpoints[0]
		}

		// If endpoint is a DID, keep DID-based service (no recipient keys)
		if endpoint != "" && utils.IsValidDid(endpoint) {
			_ = inv.AddDidService(endpoint)
		}

		// If endpoint is a URL, add inline service and ensure recipient key is present (did:key)
		if endpoint != "" && utils.IsValidURL(endpoint) {
			// Track pending key id for inline service keys mapping after record creation
			recipientDidKey, keyId, err := api.ensureRecipientDidKey(config)
			if err != nil {
				return nil, fmt.Errorf("failed to prepare recipient key: %w", err)
			}
			serviceId := "#inline-0"
			if config.Routing != nil && len(config.Routing.RoutingKeys) > 0 {
				if err := inv.AddInlineServiceWithRouting(serviceId, endpoint, []string{recipientDidKey}, config.Routing.RoutingKeys); err != nil {
					return nil, err
				}
			} else {
				if err := inv.AddInlineService(serviceId, endpoint, []string{recipientDidKey}); err != nil {
					return nil, err
				}
			}
			// Remember generated KMS key id to store mapping on the record later
			inlineGeneratedKeyId = keyId
		}
	}

	// Optional: include attachments/messages as Aries attachments
	if len(config.Messages) > 0 {
		for _, raw := range config.Messages {
			switch v := raw.(type) {
			case interface{ ToJSON() ([]byte, error) }:
				if buf, err := v.ToJSON(); err == nil {
					enc := base64.StdEncoding.EncodeToString(buf)
					att := Attachment{Id: common.GenerateUUID(), MimeType: "application/json", Data: map[string]interface{}{"base64": enc}}
					inv.Requests = append(inv.Requests, att)
				}
			case map[string]interface{}:
				if buf, err := json.Marshal(v); err == nil {
					enc := base64.StdEncoding.EncodeToString(buf)
					att := Attachment{Id: common.GenerateUUID(), MimeType: "application/json", Data: map[string]interface{}{"base64": enc}}
					inv.Requests = append(inv.Requests, att)
				}
			default:
				if buf, err := json.Marshal(v); err == nil {
					enc := base64.StdEncoding.EncodeToString(buf)
					att := Attachment{Id: common.GenerateUUID(), MimeType: "application/json", Data: map[string]interface{}{"base64": enc}}
					inv.Requests = append(inv.Requests, att)
				}
			}
		}
	}
	if len(config.AppendedAttachments) > 0 {
		for _, a := range config.AppendedAttachments {
			inv.Requests = append(inv.Requests, a)
		}
	}
	rec := &OutOfBandRecord{
		BaseRecord:          storage.NewBaseRecord("OutOfBandRecord"),
		ID:                  "",
		Role:                OutOfBandRoleSender,
		State:               OutOfBandStateAwaitResponse,
		OutOfBandInvitation: inv,
		ReusableConnection:  config.MultiUseInvitation != nil && *config.MultiUseInvitation,
		Tags:                map[string]string{"threadId": inv.GetId()},
		CreatedAt:           time.Now(),
		UpdatedAt:           time.Now(),
	}
	rec.ID = rec.BaseRecord.GetId()
	// If inline service key was created, set mapping now
	if config.InvitationDid == "" && inv != nil {
		svcs := inv.GetServices()
		if len(svcs) > 0 {
			svc := svcs[0]
			if len(svc.RecipientKeys) > 0 {
				fp := FingerprintFromKeyString(svc.RecipientKeys[0])
				rec.InvitationInlineServiceKeys = append(rec.InvitationInlineServiceKeys, OutOfBandInlineServiceKey{
					RecipientKeyFingerprint: fp,
					KmsKeyId:                inlineGeneratedKeyId,
				})
			}
		}
	}

	// Populate tags for queries (role, state, invitationId, threadId, recipientKeyFingerprints)
	setOobRecordTags(rec)
	// Persist
	if repo := api.getRepository(); repo != nil {
		if err := repo.Save(api.agentContext, rec); err != nil {
			return nil, err
		}
	}
	return rec, nil
}

// CreateLegacyInvitation creates a legacy connection invitation
func (api *OutOfBandApi) CreateLegacyInvitation(config CreateLegacyInvitationConfig) (*OutOfBandRecord, error) {
	// For parity: create an OOB 1.1 with connections 1.0 handshake only
	hp := []HandshakeProtocol{HandshakeProtocolConnections}
	rec, err := api.CreateInvitation(CreateOutOfBandInvitationConfig{
		Label:              config.Label,
		Alias:              config.Alias,
		ImageUrl:           config.ImageUrl,
		HandshakeProtocols: hp,
		MultiUseInvitation: config.MultiUseInvitation,
	})

	if err != nil {
		return nil, err
	}

	// Set legacy invitation metadata
	rec.SetMetadata(MetadataKeyLegacyInvitation, &LegacyInvitationMetadata{
		LegacyInvitationType: LegacyInvitationTypeConnection,
	})

	// Update the record to save metadata
	if repo := api.getRepository(); repo != nil {
		_ = repo.Update(api.agentContext, rec)
	}

	return rec, nil
}

// ReceiveInvitation processes a received out-of-band invitation
func (api *OutOfBandApi) ReceiveInvitation(
	invitation interface{},
	config ReceiveOutOfBandInvitationConfig,
) (*OutOfBandRecord, error) {
	if api == nil || api.agentContext == nil {
		return nil, fmt.Errorf("agent context not available")
	}
	// Normalize invitation type
	var inv *messages_oob.OutOfBandInvitationMessage
	switch v := invitation.(type) {
	case *messages_oob.OutOfBandInvitationMessage:
		inv = v
	case map[string]interface{}:
		b, _ := json.Marshal(v)
		tmp := &messages_oob.OutOfBandInvitationMessage{}
		if err := json.Unmarshal(b, tmp); err == nil {
			inv = tmp
		}
	default:
		return nil, fmt.Errorf("unsupported invitation type")
	}
	if inv == nil {
		return nil, fmt.Errorf("invalid invitation")
	}
	if !config.IsImplicit {
		// Check if we've already received this invitation
		if repo := api.getRepository(); repo != nil {
			existing := repo.FindByInvitationThreadId(api.agentContext, inv.GetId())
			if existing != nil && existing.Role == OutOfBandRoleReceiver {
				return nil, fmt.Errorf("an out of band record with invitation %s has already been received. Invitations should have a unique id", inv.GetId())
			}
		}
	}

	// Create OOB record with Initial state (matching Credo-TS)
	rec := &OutOfBandRecord{
		BaseRecord:           storage.NewBaseRecord("OutOfBandRecord"),
		ID:                   "",
		Role:                 OutOfBandRoleReceiver,
		State:                OutOfBandStateInitial, // Start with Initial state
		OutOfBandInvitation:  inv,
		ReusableConnection:   false,
		AutoAcceptConnection: config.AutoAcceptConnection != nil && *config.AutoAcceptConnection,
		Alias:                config.Alias,
		Tags:                 map[string]string{"threadId": inv.GetId()},
		CreatedAt:            time.Now(),
		UpdatedAt:            time.Now(),
	}
	rec.ID = rec.BaseRecord.GetId()
	setOobRecordTags(rec)
	if repo := api.getRepository(); repo != nil {
		_ = repo.Save(api.agentContext, rec)
	}
	return rec, nil
}

// CreateFromImplicitInvitation creates an OOB record from a public DID
// This is used when another agent initiates a connection to our public DID
func (api *OutOfBandApi) CreateFromImplicitInvitation(config CreateFromImplicitInvitationConfig) (*OutOfBandRecord, error) {
	if api == nil || api.agentContext == nil {
		return nil, fmt.Errorf("agent context not available")
	}

	// Verify the DID is valid and exists in our wallet
	if config.Did == "" {
		return nil, fmt.Errorf("DID is required for implicit invitation")
	}

	// TODO: In a complete implementation, we would verify the DID exists in wallet
	// For now, we'll create the invitation assuming the DID is valid

	// Create an implicit invitation with the DID as service
	invitation := messages_oob.NewOutOfBandInvitationMessageWithId(config.Did, api.agentContext.Config.Label)
	invitation.Services = []messages_oob.OutOfBandService{
		{ServiceEndpoint: config.Did}, // DID-based service
	}

	// Set handshake protocols
	if len(config.HandshakeProtocols) > 0 {
		for _, protocol := range config.HandshakeProtocols {
			invitation.Handshake = append(invitation.Handshake, messages_oob.HandshakeProtocol{
				ProtocolId: string(protocol),
			})
		}
	} else {
		// Default to DID Exchange
		invitation.Handshake = []messages_oob.HandshakeProtocol{
			{ProtocolId: string(HandshakeProtocolDidExchange)},
		}
	}

	if config.ThreadId != "" {
		invitation.SetThreadId(config.ThreadId)
	}

	// Create OOB record
	rec := &OutOfBandRecord{
		BaseRecord:           storage.NewBaseRecord("OutOfBandRecord"),
		ID:                   common.GenerateUUID(),
		Role:                 OutOfBandRoleSender,
		State:                OutOfBandStateAwaitResponse,
		OutOfBandInvitation:  invitation,
		ReusableConnection:   true, // Implicit invitations are always reusable
		AutoAcceptConnection: config.AutoAcceptConnection,
		Tags:                 make(map[string]string),
		CreatedAt:            time.Now(),
		UpdatedAt:            time.Now(),
	}
	setOobRecordTags(rec)

	// Add recipient key fingerprint to tags if provided
	if config.RecipientKey != nil {
		if rec.Tags == nil {
			rec.Tags = make(map[string]string)
		}
		// TODO: Add proper key fingerprint when wallet.Key has Fingerprint method
		// For now, use a placeholder
		rec.Tags["recipientKeyFingerprints"] = "key-fingerprint"
	}

	// Save the record
	if repo := api.getRepository(); repo != nil {
		if err := repo.Save(api.agentContext, rec); err != nil {
			return nil, fmt.Errorf("failed to save implicit invitation record: %w", err)
		}
	}

	// Emit state changed event
	if api.eventEmitter != nil {
		api.eventEmitter.Publish(OutOfBandEventStateChanged, map[string]interface{}{
			"outOfBandRecord": rec,
			"previousState":   nil,
			"state":           rec.State,
		})
	}

	return rec, nil
}

// ReceiveImplicitInvitation receives an implicit invitation using only a public DID
func (api *OutOfBandApi) ReceiveImplicitInvitation(config ReceiveImplicitInvitationConfig) (*OutOfBandRecord, error) {
	if api == nil || api.agentContext == nil {
		return nil, fmt.Errorf("agent context not available")
	}

	if config.Did == "" {
		return nil, fmt.Errorf("DID is required for implicit invitation")
	}

	// Create an OOB invitation from the DID
	invitation := messages_oob.NewOutOfBandInvitationMessageWithId(config.Did, config.Label)
	invitation.Services = []messages_oob.OutOfBandService{
		{ServiceEndpoint: config.Did}, // DID-based service
	}

	// Set handshake protocols
	if len(config.HandshakeProtocols) > 0 {
		for _, protocol := range config.HandshakeProtocols {
			invitation.Handshake = append(invitation.Handshake, messages_oob.HandshakeProtocol{
				ProtocolId: string(protocol),
			})
		}
	} else {
		// Default to DID Exchange
		invitation.Handshake = []messages_oob.HandshakeProtocol{
			{ProtocolId: string(HandshakeProtocolDidExchange)},
		}
	}

	// Create OOB record with Initial state
	rec := &OutOfBandRecord{
		BaseRecord:           storage.NewBaseRecord("OutOfBandRecord"),
		ID:                   common.GenerateUUID(),
		Role:                 OutOfBandRoleReceiver,
		State:                OutOfBandStateInitial,
		OutOfBandInvitation:  invitation,
		ReusableConnection:   false,
		AutoAcceptConnection: config.AutoAcceptConnection,
		Alias:                config.Alias,
		Tags:                 map[string]string{"threadId": invitation.GetId()},
		CreatedAt:            time.Now(),
		UpdatedAt:            time.Now(),
	}

	setOobRecordTags(rec)

	// Note: For implicit invitations, we don't check for duplicates
	// This allows multiple connections to the same public DID

	// Save the record
	if repo := api.getRepository(); repo != nil {
		if err := repo.Save(api.agentContext, rec); err != nil {
			return nil, fmt.Errorf("failed to save implicit invitation record: %w", err)
		}
	}

	// Auto-accept if configured
	if config.AutoAcceptInvitation {
		acceptConfig := AcceptInvitationConfig{
			Label:                config.Label,
			Alias:                config.Alias,
			ImageUrl:             config.ImageUrl,
			AutoAcceptConnection: config.AutoAcceptConnection,
			ReuseConnection:      false, // Don't reuse for implicit invitations
			Routing:              config.Routing,
			OurDid:               config.OurDid,
		}

		return api.AcceptInvitation(rec.ID, acceptConfig)
	}

	return rec, nil
}

// AcceptInvitation accepts a received out-of-band invitation
func (api *OutOfBandApi) AcceptInvitation(outOfBandId string, config AcceptInvitationConfig) (*OutOfBandRecord, error) {
	if api == nil || api.agentContext == nil {
		return nil, fmt.Errorf("agent context not available")
	}

	// Get the OOB record
	repo := api.getRepository()
	if repo == nil {
		return nil, fmt.Errorf("repository not available")
	}

	rec, err := repo.GetById(api.agentContext, outOfBandId)
	if err != nil {
		return nil, fmt.Errorf("failed to get OOB record: %w", err)
	}

	// Assert role and state
	if err := rec.AssertRole(OutOfBandRoleReceiver); err != nil {
		return nil, err
	}
	if err := rec.AssertState(OutOfBandStateInitial); err != nil {
		return nil, err
	}

	// Update state to PrepareResponse
	if api.agentContext != nil && api.agentContext.DependencyManager != nil {
		if dm, ok := api.agentContext.DependencyManager.(di.DependencyManager); ok {
			if svc, err := di.ResolveAs[*OutOfBandService](dm, di.TokenOutOfBandService); err == nil && svc != nil {
				if err := svc.UpdateState(api.agentContext, repo, api.eventEmitter, rec, OutOfBandStatePrepareResponse); err != nil {
					return nil, fmt.Errorf("failed to update OOB record: %w", err)
				}
			}
		}
	}

	// Emit state changed event
	if api.eventEmitter != nil {
		api.eventEmitter.Publish(OutOfBandEventStateChanged, map[string]interface{}{
			"outOfBandRecord": rec,
			"previousState":   OutOfBandStateInitial,
			"state":           rec.State,
		})
	}

	return rec, nil
}

// ReceiveInvitationFromUrl receives an invitation from a URL
func (api *OutOfBandApi) ReceiveInvitationFromUrl(
	urlStr string,
	config ReceiveOutOfBandInvitationConfig,
) (*OutOfBandRecord, error) {
	// Parse invitation from URL
	if inv, err := messages_oob.ParseOutOfBandInvitationFromUrl(urlStr); err == nil {
		return api.ReceiveInvitation(inv, config)
	}
	if legacy, err := conmsg.ParseInvitationFromUrl(urlStr); err == nil {
		if oobInv, err2 := ConvertToNewInvitation(legacy); err2 == nil {
			return api.ReceiveInvitation(oobInv, config)
		}
	}
	return nil, fmt.Errorf("invalid invitation URL: no recognizable parameters")
}

// FindById finds an out-of-band record by ID
func (api *OutOfBandApi) FindById(id string) (*OutOfBandRecord, error) {
	if repo := api.getRepository(); repo != nil {
		return repo.FindById(api.agentContext, id)
	}
	return nil, fmt.Errorf("repository not available")
}

// GetAll returns all out-of-band records
func (api *OutOfBandApi) GetAll() ([]*OutOfBandRecord, error) {
	if repo := api.getRepository(); repo != nil {
		return repo.GetAll(api.agentContext)
	}
	return []*OutOfBandRecord{}, nil
}

// DeleteById deletes an out-of-band record by ID
func (api *OutOfBandApi) DeleteById(id string) error {
	if repo := api.getRepository(); repo != nil {
		return repo.Delete(api.agentContext, id)
	}
	return fmt.Errorf("repository not available")
}

// The actual OutOfBandRecord type is defined in types.go

// setOobRecordTags populates standard tags used for queries and parity with Credo-TS
func setOobRecordTags(rec *OutOfBandRecord) {
	if rec == nil {
		return
	}
	if rec.Tags == nil {
		rec.Tags = map[string]string{}
	}
	// role, state
	rec.Tags["role"] = string(rec.Role)
	rec.Tags["state"] = rec.State
	// invitation id and thread id
	invId := ""
	if inv, ok := rec.OutOfBandInvitation.(interface{ GetId() string }); ok && inv != nil {
		invId = inv.GetId()
	}
	if invId != "" {
		rec.Tags["invitationId"] = invId
	}
	if _, ok := rec.Tags["threadId"]; !ok && invId != "" {
		rec.Tags["threadId"] = invId
	}
	// recipient key fingerprints from inline services if present
	if inv, ok := rec.OutOfBandInvitation.(*messages_oob.OutOfBandInvitationMessage); ok && inv != nil {
		svcs := inv.GetServices()
		if len(svcs) > 0 {
			svc := svcs[0]
			if len(svc.RecipientKeys) > 0 {
				fps := make([]string, 0, len(svc.RecipientKeys))
				for _, k := range svc.RecipientKeys {
					fps = append(fps, FingerprintFromKeyString(k))
				}
				rec.Tags["recipientKeyFingerprints"] = strings.Join(fps, ",")
			}
		}

		// Index attached request thread ids for parity with Credo-TS (invitationRequestsThreadIds)
		// We store each thread id as a separate tag key: invreq:<thid> = "1"
		if reqs := inv.GetRequests(); len(reqs) > 0 {
			for _, r := range reqs {
				// Try to extract base64 payload from various shapes
				var base64Payload string
				switch v := r.(type) {
				case Attachment:
					if dm, ok := v.Data.(map[string]interface{}); ok {
						if b, ok := dm["base64"].(string); ok {
							base64Payload = b
						}
					}
				case *Attachment:
					if v != nil {
						if dm, ok := v.Data.(map[string]interface{}); ok {
							if b, ok := dm["base64"].(string); ok {
								base64Payload = b
							}
						}
					}
				case map[string]interface{}:
					if d, ok := v["data"].(map[string]interface{}); ok {
						if b, ok := d["base64"].(string); ok {
							base64Payload = b
						}
					}
				}

				if base64Payload == "" {
					continue
				}
				// Decode (try URL-safe first, then standard)
				var payload []byte
				if buf, err := base64.RawURLEncoding.DecodeString(base64Payload); err == nil {
					payload = buf
				} else if buf, err2 := base64.StdEncoding.DecodeString(base64Payload); err2 == nil {
					payload = buf
				}
				if len(payload) == 0 {
					continue
				}
				// Parse plaintext message and extract thread id (~thread.thid) or fallback to @id
				var m map[string]interface{}
				if err := json.Unmarshal(payload, &m); err != nil {
					continue
				}
				thid := ""
				if th, ok := m["~thread"].(map[string]interface{}); ok {
					if t, ok := th["thid"].(string); ok {
						thid = t
					}
				}
				if thid == "" {
					if id, ok := m["@id"].(string); ok {
						thid = id
					}
				}
				if thid != "" {
					rec.Tags["invreq:"+thid] = "1"
				}
			}
		}
	}
	if rec.BaseRecord != nil {
		rec.BaseRecord.Tags = rec.Tags
	}
}

// CreateLegacyConnectionlessInvitation creates an OOB with attached message and returns a connection-less URL (d_m=...)
func (api *OutOfBandApi) CreateLegacyConnectionlessInvitation(cfg CreateLegacyConnectionlessConfig) (didcommmsgs.AgentMessage, string, *OutOfBandRecord, error) {
	if api == nil || api.agentContext == nil {
		return nil, "", nil, fmt.Errorf("agent context not available")
	}
	if cfg.Message == nil {
		return nil, "", nil, fmt.Errorf("message is required")
	}
	domain := cfg.Domain
	if domain == "" {
		domain = api.getBaseEndpoint()
	}

	// Create an OOB invitation with the message attached
	rec, err := api.CreateInvitation(CreateOutOfBandInvitationConfig{
		Messages: []interface{}{cfg.Message},
		Routing:  cfg.Routing,
	})
	if err != nil {
		return nil, "", nil, err
	}

	// Mark legacy invitation type as connectionless
	rec.SetMetadata(MetadataKeyLegacyInvitation, &LegacyInvitationMetadata{LegacyInvitationType: LegacyInvitationTypeConnectionless})
	if repo := api.getRepository(); repo != nil {
		_ = repo.Update(api.agentContext, rec)
	}

	// Build service decorator fields from first resolvable service in the invitation
	var svcEndpoint string
	var svcRecipientKeys []string
	var svcRoutingKeys []string
	if inv, ok := rec.OutOfBandInvitation.(*messages_oob.OutOfBandInvitationMessage); ok && inv != nil {
		svcs := inv.GetServices()
		if len(svcs) > 0 {
			s := svcs[0]
			if endpoint, ok := s.ServiceEndpoint.(string); ok {
				if utils.IsValidURL(endpoint) && len(s.RecipientKeys) > 0 {
					svcEndpoint = endpoint
					svcRecipientKeys = s.RecipientKeys
					svcRoutingKeys = s.RoutingKeys
				} else if utils.IsValidDid(endpoint) {
					if api.agentContext != nil && api.agentContext.DependencyManager != nil {
						if dm, ok := api.agentContext.DependencyManager.(di.DependencyManager); ok {
							if dep, err := dm.Resolve(di.TokenDidResolverService); err == nil {
								if resolver, ok := dep.(*dids.DidResolverService); ok && resolver != nil {
									if doc, err := resolver.ResolveDidDocument(api.agentContext, endpoint); err == nil && doc != nil {
										for _, ds := range doc.Service {
											if ds == nil {
												continue
											}
											if ds.Type == dids.ServiceTypeDIDCommMessaging || (svcEndpoint == "" && (ds.Type == dids.ServiceTypeDIDComm || ds.Type == dids.ServiceTypeIndyAgent) && len(ds.RecipientKeys) > 0) {
												ep := ""
												if se, ok := ds.ServiceEndpoint.(string); ok {
													ep = se
												}
												if ep != "" {
													svcEndpoint = ep
													svcRecipientKeys = ds.RecipientKeys
													svcRoutingKeys = ds.RoutingKeys
													if ds.Type == dids.ServiceTypeDIDCommMessaging {
														break
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}

	// Prepare message JSON with ~service decorator fields
	msgJson, err := cfg.Message.ToJSON()
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to serialize message: %w", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(msgJson, &m); err != nil {
		return nil, "", nil, fmt.Errorf("failed to parse message json: %w", err)
	}
	if svcEndpoint != "" && len(svcRecipientKeys) > 0 {
		// Use Credo-TS compatible camelCase keys
		m["~service"] = map[string]interface{}{
			"recipientKeys":   svcRecipientKeys,
			"routingKeys":     svcRoutingKeys,
			"serviceEndpoint": svcEndpoint,
		}
	}

	// Base64URL encode and create the d_m URL
	buf, _ := json.Marshal(m)
	enc := base64.RawURLEncoding.EncodeToString(buf)
	invitationUrl := fmt.Sprintf("%s?d_m=%s", domain, enc)

	return cfg.Message, invitationUrl, rec, nil
}

// Configuration types

type CreateOutOfBandInvitationConfig struct {
	Label                string
	Alias                string
	ImageUrl             string
	GoalCode             string
	Goal                 string
	Handshake            *bool
	HandshakeProtocols   []HandshakeProtocol
	Messages             []interface{}
	MultiUseInvitation   *bool
	AutoAcceptConnection *bool
	Routing              *Routing
	AppendedAttachments  []Attachment
	InvitationDid        string
}

type CreateLegacyInvitationConfig struct {
	Label                string
	Alias                string
	ImageUrl             string
	MultiUseInvitation   *bool
	AutoAcceptConnection *bool
	Routing              *Routing
}

// CreateLegacyConnectionlessConfig mirrors Credo-TS API for connection-less invitations
type CreateLegacyConnectionlessConfig struct {
	Message didcommmsgs.AgentMessage
	Domain  string
	Routing *Routing
}

type ReceiveOutOfBandInvitationConfig struct {
	Label                     string
	Alias                     string
	ImageUrl                  string
	AutoAcceptInvitation      *bool
	AutoAcceptConnection      *bool
	ReuseConnection           *bool
	Routing                   *Routing
	AcceptInvitationTimeoutMs int
	OurDid                    string
	IsImplicit                bool // Set to true for implicit invitations to skip duplicate check
}

// AcceptInvitationConfig represents configuration for accepting an OOB invitation
type AcceptInvitationConfig struct {
	Label                string
	Alias                string
	ImageUrl             string
	AutoAcceptConnection bool
	ReuseConnection      bool
	Routing              *Routing
	TimeoutMs            int
	OurDid               string
}

// CreateFromImplicitInvitationConfig represents configuration for creating an implicit invitation
type CreateFromImplicitInvitationConfig struct {
	Did                  string              // Public DID
	ThreadId             string              // Thread ID for the invitation
	HandshakeProtocols   []HandshakeProtocol // Supported handshake protocols
	AutoAcceptConnection bool                // Auto-accept connections
	RecipientKey         *wallet.Key         // Recipient key for the invitation
}

// ReceiveImplicitInvitationConfig represents configuration for receiving an implicit invitation
type ReceiveImplicitInvitationConfig struct {
	Did                  string              // Public DID to connect to
	Label                string              // Label for the connection
	Alias                string              // Alias for the connection
	ImageUrl             string              // Optional image URL
	HandshakeProtocols   []HandshakeProtocol // Handshake protocols to use
	AutoAcceptConnection bool                // Auto-accept the connection
	AutoAcceptInvitation bool                // Auto-accept the invitation
	OurDid               string              // Our DID to use (optional)
	Routing              *Routing            // Routing configuration
}

type HandshakeProtocol string

const (
	HandshakeProtocolConnections HandshakeProtocol = "https://didcomm.org/connections/1.0"
	HandshakeProtocolDidExchange HandshakeProtocol = "https://didcomm.org/didexchange/1.1"
)

type Routing struct {
	Endpoints    []string
	RoutingKeys  []string
	RecipientKey string
	MediatorId   string
}

type Attachment struct {
	Id          string      `json:"@id"`
	Description string      `json:"description,omitempty"`
	Filename    string      `json:"filename,omitempty"`
	MimeType    string      `json:"mime-type,omitempty"`
	LastModTime string      `json:"lastmod_time,omitempty"`
	ByteCount   int         `json:"byte_count,omitempty"`
	Data        interface{} `json:"data"`
}

// URL helpers
func (api *OutOfBandApi) InvitationToUrl(inv *messages_oob.OutOfBandInvitationMessage) (string, error) {
	if inv == nil {
		return "", fmt.Errorf("nil invitation")
	}
	b, err := json.Marshal(inv)
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding.EncodeToString(b)
	return fmt.Sprintf("%s?oob=%s", api.getBaseEndpoint(), enc), nil
}

func (api *OutOfBandApi) InvitationFromUrl(u string) (*messages_oob.OutOfBandInvitationMessage, error) {
	parsed, err := url.Parse(u)
	if err != nil {
		return nil, err
	}
	q := parsed.Query()
	val := q.Get("oob")
	if val == "" {
		val = q.Get("c_i")
	}
	if val == "" {
		return nil, fmt.Errorf("no invitation payload in url")
	}
	b, err := base64.RawURLEncoding.DecodeString(val)
	if err != nil {
		// try padded base64
		b, err = base64.StdEncoding.DecodeString(val)
		if err != nil {
			return nil, err
		}
	}
	inv := &messages_oob.OutOfBandInvitationMessage{}
	if err := json.Unmarshal(b, inv); err != nil {
		return nil, err
	}
	return inv, nil
}

// helpers
func (api *OutOfBandApi) getRepository() *OutOfBandRepository {
	if api.agentContext != nil && api.agentContext.DependencyManager != nil {
		if dm, ok := api.agentContext.DependencyManager.(di.DependencyManager); ok {
			if dep, err := dm.Resolve(di.TokenOutOfBandRepository); err == nil {
				if repo, ok := dep.(*OutOfBandRepository); ok {
					return repo
				}
			}
		}
	}
	return nil
}

func (api *OutOfBandApi) getBaseEndpoint() string {
	if api.agentContext != nil && api.agentContext.Config != nil && len(api.agentContext.Config.Endpoints) > 0 {
		ep := api.agentContext.Config.Endpoints[0]
		if strings.HasSuffix(ep, "/") {
			ep = strings.TrimRight(ep, "/")
		}
		return ep
	}
	return "http://localhost:3001"
}

// ensureRecipientDidKey returns a did:key for the recipient. It uses provided routing RecipientKey if present (did:key or base58),
// otherwise generates a fresh Ed25519 key using the WalletService.
func (api *OutOfBandApi) ensureRecipientDidKey(config CreateOutOfBandInvitationConfig) (string, string, error) {
	// If caller provided a did:key already, use it
	if config.Routing != nil && config.Routing.RecipientKey != "" {
		if strings.HasPrefix(config.Routing.RecipientKey, "did:key:") {
			return config.Routing.RecipientKey, "", nil
		}
		// If provided as base58 verkey, convert to did:key
		if raw, err := encoding.DecodeBase58(config.Routing.RecipientKey); err == nil && len(raw) == 32 {
			did, err := keyresolver.CreateDidKeyFromEd25519PublicKey(raw)
			return did, "", err
		}
	}

	// Resolve wallet and create a new Ed25519 key
	var walletSvc *wallet.WalletService
	if api.agentContext != nil && api.agentContext.DependencyManager != nil {
		if dm, ok := api.agentContext.DependencyManager.(di.DependencyManager); ok {
			if dep, err := dm.Resolve(di.TokenWalletService); err == nil {
				walletSvc, _ = dep.(*wallet.WalletService)
			}
		}
	}
	if walletSvc == nil {
		return "", "", fmt.Errorf("wallet service not available for generating recipient key")
	}
	key, err := walletSvc.CreateKey(wallet.KeyTypeEd25519)
	if err != nil {
		return "", "", fmt.Errorf("failed to create key: %w", err)
	}
	did, err := keyresolver.CreateDidKeyFromEd25519PublicKey(key.PublicKey)
	if err != nil {
		return "", "", err
	}
	return did, key.Id, nil
}
