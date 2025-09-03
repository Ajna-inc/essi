package oob

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	ctxstd "context"

	agentctx "github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/core/events"
	"github.com/ajna-inc/essi/pkg/core/storage"
	oobmessages "github.com/ajna-inc/essi/pkg/didcomm/modules/oob/messages"
)

// OutOfBandRole represents the role in an out-of-band exchange
type OutOfBandRole string

const (
	OutOfBandRoleSender   OutOfBandRole = "sender"
	OutOfBandRoleReceiver OutOfBandRole = "receiver"
)

// Out-of-band states (parity with Credo-TS)
const (
	OutOfBandStateInitial         = "initial"          // When invitation is first received
	OutOfBandStateAwaitResponse   = "await-response"   // Sender waiting for response
	OutOfBandStatePrepareResponse = "prepare-response" // Receiver preparing response
	OutOfBandStateDone            = "done"             // Exchange complete
)

// Out-of-band event names (parity intent with Credo-TS)
const (
	OutOfBandEventHandshakeReused = "oob.handshakeReused"
	OutOfBandEventStateChanged    = "oob.stateChanged"
)

// OutOfBandInlineServiceKey represents a key associated with an inline service
type OutOfBandInlineServiceKey struct {
	RecipientKeyFingerprint string `json:"recipientKeyFingerprint"`
	KmsKeyId                string `json:"kmsKeyId"`
}

// OutOfBandRecord represents an out-of-band invitation record
type OutOfBandRecord struct {
	*storage.BaseRecord
	ID                  string            `json:"id"`
	Role                OutOfBandRole     `json:"role"`
	State               string            `json:"state"`
	OutOfBandInvitation interface{}       `json:"outOfBandInvitation"`
	ReusableConnection  bool              `json:"reusableConnection"`
	Tags                map[string]string `json:"tags"`
	CreatedAt           time.Time         `json:"createdAt"`
	UpdatedAt           time.Time         `json:"updatedAt"`
	// Parity extras
	Alias                       string                      `json:"alias,omitempty"`
	MediatorId                  string                      `json:"mediatorId,omitempty"`
	AutoAcceptConnection        bool                        `json:"autoAcceptConnection,omitempty"`
	ReuseConnectionId           string                      `json:"reuseConnectionId,omitempty"` // Connection ID for reuse validation
	InvitationInlineServiceKeys []OutOfBandInlineServiceKey `json:"invitationInlineServiceKeys,omitempty"`
	metadata                    map[string]interface{}
}

// Register OutOfBandRecord with storage factory
func init() {
	storage.RegisterRecordType("OutOfBandRecord", func() storage.Record {
		return &OutOfBandRecord{BaseRecord: storage.NewBaseRecord("OutOfBandRecord")}
	})
}

func (r *OutOfBandRecord) ToJSON() ([]byte, error)    { return json.Marshal(r) }
func (r *OutOfBandRecord) FromJSON(data []byte) error { return json.Unmarshal(data, r) }

// SetMetadata sets metadata on the record
func (r *OutOfBandRecord) SetMetadata(key string, value interface{}) {
	if r.metadata == nil {
		r.metadata = make(map[string]interface{})
	}
	r.metadata[key] = value
}

// GetMetadata gets metadata from the record
func (r *OutOfBandRecord) GetMetadata(key string) interface{} {
	if r.metadata == nil {
		return nil
	}
	return r.metadata[key]
}

// Typed metadata helpers
func (r *OutOfBandRecord) SetRecipientRouting(meta RecipientRoutingMetadata) {
	r.SetMetadata(MetadataKeyRecipientRouting, map[string]interface{}{
		"recipientKeyFingerprint": meta.RecipientKeyFingerprint,
		"recipientKeyId":          meta.RecipientKeyId,
		"routingKeyFingerprints":  meta.RoutingKeyFingerprints,
		"endpoints":               meta.Endpoints,
		"mediatorId":              meta.MediatorId,
	})
}

func (r *OutOfBandRecord) GetRecipientRouting() (*RecipientRoutingMetadata, bool) {
	if r.metadata == nil {
		return nil, false
	}
	raw, ok := r.metadata[MetadataKeyRecipientRouting]
	if !ok || raw == nil {
		return nil, false
	}
	m, ok := raw.(map[string]interface{})
	if !ok {
		return nil, false
	}
	out := &RecipientRoutingMetadata{}
	if v, ok := m["recipientKeyFingerprint"].(string); ok {
		out.RecipientKeyFingerprint = v
	}
	if v, ok := m["recipientKeyId"].(string); ok {
		out.RecipientKeyId = v
	}
	if v, ok := m["mediatorId"].(string); ok {
		out.MediatorId = v
	}
	if arr, ok := m["routingKeyFingerprints"].([]interface{}); ok {
		for _, it := range arr {
			if s, ok := it.(string); ok {
				out.RoutingKeyFingerprints = append(out.RoutingKeyFingerprints, s)
			}
		}
	}
	if arr, ok := m["endpoints"].([]interface{}); ok {
		for _, it := range arr {
			if s, ok := it.(string); ok {
				out.Endpoints = append(out.Endpoints, s)
			}
		}
	}
	return out, true
}

// SetRecipientKeyFingerprints sets the recipient key fingerprints in tags
func (r *OutOfBandRecord) SetRecipientKeyFingerprints(fingerprints []string) {
	if r.Tags == nil {
		r.Tags = make(map[string]string)
	}
	if len(fingerprints) > 0 {
		r.Tags["recipientKeyFingerprints"] = strings.Join(fingerprints, ",")
	}
}

// GetRecipientKeyFingerprints gets the recipient key fingerprints from tags
func (r *OutOfBandRecord) GetRecipientKeyFingerprints() []string {
	if r.Tags == nil {
		return nil
	}
	if value, ok := r.Tags["recipientKeyFingerprints"]; ok && value != "" {
		return strings.Split(value, ",")
	}
	return nil
}

// AssertRole validates that the record has the expected role
func (r *OutOfBandRecord) AssertRole(expectedRole OutOfBandRole) error {
	if r.Role != expectedRole {
		return fmt.Errorf("invalid out-of-band record role %s, expected is %s", r.Role, expectedRole)
	}
	return nil
}

// AssertState validates that the record is in one of the expected states
func (r *OutOfBandRecord) AssertState(expectedStates ...string) error {
	if len(expectedStates) == 0 {
		return fmt.Errorf("no expected states provided")
	}

	for _, state := range expectedStates {
		if r.State == state {
			return nil
		}
	}

	return fmt.Errorf("invalid out-of-band record state %s, valid states are: %s",
		r.State, strings.Join(expectedStates, ", "))
}

// OutOfBandRepository handles storage of out-of-band records
type OutOfBandRepository struct {
	storageService storage.StorageService
	eventEmitter   events.Bus
}

// NewOutOfBandRepository creates a storage-backed repository
func NewOutOfBandRepository(storageService storage.StorageService, eventEmitter events.Bus) *OutOfBandRepository {
	return &OutOfBandRepository{storageService: storageService, eventEmitter: eventEmitter}
}

// GetById retrieves a record by ID
func (r *OutOfBandRepository) GetById(agentCtx *agentctx.AgentContext, id string) (*OutOfBandRecord, error) {
	if r.storageService == nil {
		return nil, fmt.Errorf("storage service not available")
	}

	baseCtx := ctxstd.Background()
	if agentCtx != nil && agentCtx.Context != nil {
		baseCtx = agentCtx.Context
	}

	recordAny, err := r.storageService.GetById(baseCtx, "OutOfBandRecord", id)
	if err != nil {
		return nil, err
	}

	record, ok := recordAny.(*OutOfBandRecord)
	if !ok {
		return nil, fmt.Errorf("invalid record type")
	}

	return record, nil
}

// FindByInvitationThreadId finds a record by invitation thread ID
func (r *OutOfBandRepository) FindByInvitationThreadId(agentCtx *agentctx.AgentContext, threadId string) *OutOfBandRecord {
	if r == nil || r.storageService == nil || threadId == "" {
		return nil
	}
	q := storage.NewQuery().WithTag("threadId", threadId)
	baseCtx := ctxstd.Background()
	if agentCtx != nil && agentCtx.Context != nil {
		baseCtx = agentCtx.Context
	}
	rec, err := r.storageService.FindSingleByQuery(baseCtx, "OutOfBandRecord", *q)
	if err == nil && rec != nil {
		if out, ok := rec.(*OutOfBandRecord); ok {
			return out
		}
		var out OutOfBandRecord
		if data, err := rec.ToJSON(); err == nil {
			_ = json.Unmarshal(data, &out)
			return &out
		}
		return nil
	}
	// Fallback: scan all if query failed or returned nil
	if list, errAll := r.storageService.GetAll(baseCtx, "OutOfBandRecord"); errAll == nil {
		for _, it := range list {
			if it == nil {
				continue
			}
			if out, ok := it.(*OutOfBandRecord); ok {
				if out != nil && out.Tags != nil && out.Tags["threadId"] == threadId {
					return out
				}
				continue
			}
			var tmp OutOfBandRecord
			if data, err := it.ToJSON(); err == nil {
				if json.Unmarshal(data, &tmp) == nil {
					if tmp.Tags != nil && tmp.Tags["threadId"] == threadId {
						return &tmp
					}
				}
			}
		}
	}
	return nil
}

// FindByCreatedInvitationId finds a record by created invitation id (pthid)
func (r *OutOfBandRepository) FindByCreatedInvitationId(agentCtx *agentctx.AgentContext, createdInvitationId string) *OutOfBandRecord {
	if r == nil || r.storageService == nil || createdInvitationId == "" {
		return nil
	}
	q := storage.NewQuery().WithTag("threadId", createdInvitationId)
	baseCtx := ctxstd.Background()
	if agentCtx != nil && agentCtx.Context != nil {
		baseCtx = agentCtx.Context
	}
	rec, err := r.storageService.FindSingleByQuery(baseCtx, "OutOfBandRecord", *q)
	if err != nil || rec == nil {
		return nil
	}
	if out, ok := rec.(*OutOfBandRecord); ok {
		return out
	}
	var out OutOfBandRecord
	if data, err := rec.ToJSON(); err == nil {
		_ = json.Unmarshal(data, &out)
		return &out
	}
	return nil
}

// FindByRequestThreadId finds a record by one of the attached request thread ids.
// Parity with Credo-TS which indexes invitationRequestsThreadIds and queries by message.threadId.
func (r *OutOfBandRepository) FindByRequestThreadId(agentCtx *agentctx.AgentContext, threadId string) *OutOfBandRecord {
	if r == nil || r.storageService == nil || threadId == "" {
		return nil
	}
	// Tags are stored as invreq:<thid> = "1"
	key := "invreq:" + threadId
	q := storage.NewQuery().WithTag(key, "1")
	baseCtx := ctxstd.Background()
	if agentCtx != nil && agentCtx.Context != nil {
		baseCtx = agentCtx.Context
	}
	rec, err := r.storageService.FindSingleByQuery(baseCtx, "OutOfBandRecord", *q)
	if err == nil && rec != nil {
		if out, ok := rec.(*OutOfBandRecord); ok {
			return out
		}
		var out OutOfBandRecord
		if data, err := rec.ToJSON(); err == nil {
			_ = json.Unmarshal(data, &out)
			return &out
		}
		return nil
	}
	// Fallback: scan all and match
	if list, errAll := r.storageService.GetAll(baseCtx, "OutOfBandRecord"); errAll == nil {
		for _, it := range list {
			if it == nil {
				continue
			}
			if out, ok := it.(*OutOfBandRecord); ok {
				if out != nil && out.Tags != nil && out.Tags[key] == "1" {
					return out
				}
				continue
			}
			var tmp OutOfBandRecord
			if data, err := it.ToJSON(); err == nil {
				if json.Unmarshal(data, &tmp) == nil {
					if tmp.Tags != nil && tmp.Tags[key] == "1" {
						return &tmp
					}
				}
			}
		}
	}
	return nil
}

// Update updates a record
func (r *OutOfBandRepository) Update(agentCtx *agentctx.AgentContext, record *OutOfBandRecord) error {
	if r == nil || r.storageService == nil || record == nil {
		return nil
	}
	if record.BaseRecord == nil {
		record.BaseRecord = storage.NewBaseRecord("OutOfBandRecord")
	} else {
		record.BaseRecord.Type = "OutOfBandRecord"
	}
	if record.Tags == nil {
		record.Tags = map[string]string{}
	}
	if record.ID == "" && record.BaseRecord.GetId() != "" {
		record.ID = record.BaseRecord.GetId()
	}
	// keep base tags in sync
	if record.BaseRecord != nil {
		record.BaseRecord.Tags = record.Tags
	}
	baseCtx := ctxstd.Background()
	if agentCtx != nil && agentCtx.Context != nil {
		baseCtx = agentCtx.Context
	}
	return r.storageService.Update(baseCtx, record)
}

func (r *OutOfBandRepository) Save(agentCtx *agentctx.AgentContext, record *OutOfBandRecord) error {
	if r == nil || r.storageService == nil || record == nil {
		return nil
	}
	if record.BaseRecord == nil {
		record.BaseRecord = storage.NewBaseRecord("OutOfBandRecord")
	} else {
		record.BaseRecord.Type = "OutOfBandRecord"
	}
	if record.Tags == nil {
		record.Tags = map[string]string{}
	}
	if record.ID == "" && record.BaseRecord.GetId() != "" {
		record.ID = record.BaseRecord.GetId()
	}
	if r.eventEmitter != nil {
		r.eventEmitter.Publish("OutOfBandRecord.saving", events.Event{Name: "OutOfBandRecord.saving", Data: record})
	}
	// keep base tags in sync
	if record.BaseRecord != nil {
		record.BaseRecord.Tags = record.Tags
	}
	baseCtx := ctxstd.Background()
	if agentCtx != nil && agentCtx.Context != nil {
		baseCtx = agentCtx.Context
	}
	if err := r.storageService.Save(baseCtx, record); err != nil {
		return err
	}
	if r.eventEmitter != nil {
		r.eventEmitter.Publish("OutOfBandRecord.saved", events.Event{Name: "OutOfBandRecord.saved", Data: record})
	}
	return nil
}

func (r *OutOfBandRepository) FindById(agentCtx *agentctx.AgentContext, id string) (*OutOfBandRecord, error) {
	if r == nil || r.storageService == nil || id == "" {
		return nil, nil
	}
	baseCtx := ctxstd.Background()
	if agentCtx != nil && agentCtx.Context != nil {
		baseCtx = agentCtx.Context
	}
	rec, err := r.storageService.GetById(baseCtx, "OutOfBandRecord", id)
	if err != nil {
		return nil, err
	}
	if out, ok := rec.(*OutOfBandRecord); ok {
		return out, nil
	}
	var out OutOfBandRecord
	data, _ := rec.ToJSON()
	_ = json.Unmarshal(data, &out)
	return &out, nil
}

func (r *OutOfBandRepository) GetAll(agentCtx *agentctx.AgentContext) ([]*OutOfBandRecord, error) {
	if r == nil || r.storageService == nil {
		return []*OutOfBandRecord{}, nil
	}
	baseCtx := ctxstd.Background()
	if agentCtx != nil && agentCtx.Context != nil {
		baseCtx = agentCtx.Context
	}
	list, err := r.storageService.FindByQuery(baseCtx, "OutOfBandRecord", *storage.NewQuery())
	if err != nil {
		return nil, err
	}
	out := make([]*OutOfBandRecord, 0, len(list))
	for _, rec := range list {
		if cr, ok := rec.(*OutOfBandRecord); ok {
			out = append(out, cr)
			continue
		}
		var tmp OutOfBandRecord
		if data, err := rec.ToJSON(); err == nil {
			if json.Unmarshal(data, &tmp) == nil {
				out = append(out, &tmp)
			}
		}
	}
	return out, nil
}

// FindByQuery finds records by a simple tag-based query (role/state/invitationId/threadId/recipientKeyFingerprints)
func (r *OutOfBandRepository) FindByQuery(agentCtx *agentctx.AgentContext, tags map[string]string) ([]*OutOfBandRecord, error) {
	if r == nil || r.storageService == nil {
		return []*OutOfBandRecord{}, nil
	}
	q := storage.NewQuery()
	for k, v := range tags {
		if v == "" {
			continue
		}
		q = q.WithTag(k, v)
	}
	baseCtx := ctxstd.Background()
	if agentCtx != nil && agentCtx.Context != nil {
		baseCtx = agentCtx.Context
	}
	list, err := r.storageService.FindByQuery(baseCtx, "OutOfBandRecord", *q)
	if err != nil {
		return nil, err
	}
	out := make([]*OutOfBandRecord, 0, len(list))
	for _, rec := range list {
		if cr, ok := rec.(*OutOfBandRecord); ok {
			out = append(out, cr)
			continue
		}
		var tmp OutOfBandRecord
		if data, err := rec.ToJSON(); err == nil {
			if json.Unmarshal(data, &tmp) == nil {
				out = append(out, &tmp)
			}
		}
	}
	return out, nil
}

// FindSingleByQuery finds a single record matching the tags
func (r *OutOfBandRepository) FindSingleByQuery(agentCtx *agentctx.AgentContext, tags map[string]string) (*OutOfBandRecord, error) {
	list, err := r.FindByQuery(agentCtx, tags)
	if err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return nil, nil
	}
	return list[0], nil
}

// FindByRecipientKey finds records by recipient key fingerprint
func (r *OutOfBandRepository) FindByRecipientKey(agentCtx *agentctx.AgentContext, fingerprint string) ([]*OutOfBandRecord, error) {
	if r == nil || r.storageService == nil || fingerprint == "" {
		return nil, nil
	}

	// Search for records with matching recipient key fingerprint
	q := storage.NewQuery().WithTag("recipientKeyFingerprints", fingerprint)
	baseCtx := ctxstd.Background()
	if agentCtx != nil && agentCtx.Context != nil {
		baseCtx = agentCtx.Context
	}

	records, err := r.storageService.FindByQuery(baseCtx, "OutOfBandRecord", *q)
	if err != nil {
		return nil, err
	}

	var result []*OutOfBandRecord
	for _, rec := range records {
		if oobRec, ok := rec.(*OutOfBandRecord); ok {
			// Check if the fingerprint is in the list
			fingerprints := oobRec.GetRecipientKeyFingerprints()
			for _, fp := range fingerprints {
				if fp == fingerprint {
					result = append(result, oobRec)
					break
				}
			}
		}
	}

	return result, nil
}

func (r *OutOfBandRepository) Delete(agentCtx *agentctx.AgentContext, id string) error {
	if r == nil || r.storageService == nil || id == "" {
		return nil
	}
	baseCtx := ctxstd.Background()
	if agentCtx != nil && agentCtx.Context != nil {
		baseCtx = agentCtx.Context
	}
	return r.storageService.DeleteById(baseCtx, "OutOfBandRecord", id)
}

// OutOfBandService handles out-of-band operations
type OutOfBandService struct{}

// NewOutOfBandService creates a new service
func NewOutOfBandService() *OutOfBandService {
	return &OutOfBandService{}
}

// GetResolvedServiceForOutOfBandRecord gets resolved service from OOB record
func (s *OutOfBandService) GetResolvedServiceForOutOfBandRecord(
	agentContext interface{},
	record *OutOfBandRecord,
) interface{} {
	if record == nil || record.OutOfBandInvitation == nil {
		return nil
	}
	if inv, ok := record.OutOfBandInvitation.(*oobmessages.OutOfBandInvitationMessage); ok && inv != nil {
		svcs := inv.GetServices()
		if len(svcs) > 0 {
			svc := svcs[0]
			endpoint := ""
			if se, ok := svc.ServiceEndpoint.(string); ok {
				endpoint = se
			}
			if endpoint != "" && len(svc.RecipientKeys) > 0 {
				// Attempt to create a stable did:peer from the inline service for parity with Credo-TS
				if did, err := OutOfBandServiceToPeerDID(svc); err == nil && did != "" {
					return did // Return did:peer DID string (numalgo4 preferred)
				}
				return map[string]interface{}{
					"id":              svc.Id,
					"serviceEndpoint": endpoint,
					"recipientKeys":   svc.RecipientKeys,
					"routingKeys":     svc.RoutingKeys,
				}
			}
		}
	}
	return nil
}

// canTransition returns true if a transition from current -> next is allowed
func canTransition(current string, next string) bool {
	if current == next {
		return true
	}
	switch current {
	case OutOfBandStateInitial:
		return next == OutOfBandStatePrepareResponse
	case OutOfBandStateAwaitResponse:
		return next == OutOfBandStateDone || next == OutOfBandStatePrepareResponse
	case OutOfBandStatePrepareResponse:
		return next == OutOfBandStateDone
	case OutOfBandStateDone:
		return false
	default:
		return false
	}
}

// UpdateState validates transition, persists, and emits OutOfBandEventStateChanged
func (s *OutOfBandService) UpdateState(
	agentCtx *agentctx.AgentContext,
	repo *OutOfBandRepository,
	eventBus events.Bus,
	record *OutOfBandRecord,
	newState string,
) error {
	if record == nil || repo == nil {
		return fmt.Errorf("invalid arguments for UpdateState")
	}
	if !canTransition(record.State, newState) {
		return fmt.Errorf("invalid OOB state transition %s -> %s", record.State, newState)
	}
	previous := record.State
	record.State = newState
	record.UpdatedAt = time.Now()
	if err := repo.Update(agentCtx, record); err != nil {
		return err
	}
	if eventBus != nil {
		eventBus.Publish(OutOfBandEventStateChanged, map[string]interface{}{
			"outOfBandRecord": record,
			"previousState":   previous,
			"state":           record.State,
		})
	}
	return nil
}
