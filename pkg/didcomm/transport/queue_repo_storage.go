package transport

import (
	stdctx "context"
	"encoding/json"
	"sort"
	"time"

	corestorage "github.com/ajna-inc/essi/pkg/core/storage"
	envelopeServices "github.com/ajna-inc/essi/pkg/didcomm/services"
)

// storage-backed queue repository for mediator pickup
type storageQueueRepo struct {
	storage corestorage.StorageService
}

// queuedMessageRecord implements storage.Record for queued messages
type queuedMessageRecord struct {
	*corestorage.BaseRecord
	ConnectionId string `json:"connectionId"`
	Payload      []byte `json:"payload"` // JSON of EncryptedMessage
	Status       string `json:"status"`
	DeliveredAt  int64  `json:"deliveredAt,omitempty"`
}

func newQueuedMessageRecord() corestorage.Record {
	return &queuedMessageRecord{BaseRecord: corestorage.NewBaseRecord("QueuedMessageRecord")}
}

func (r *queuedMessageRecord) ToJSON() ([]byte, error) { return json.Marshal(r) }
func (r *queuedMessageRecord) FromJSON(b []byte) error { return json.Unmarshal(b, r) }

func (r *queuedMessageRecord) GetTags() map[string]string {
	tags := r.BaseRecord.GetTags()
	tags["connectionId"] = r.ConnectionId
	tags["status"] = r.Status
	return tags
}

func (r *queuedMessageRecord) Clone() corestorage.Record {
	c := &queuedMessageRecord{BaseRecord: corestorage.NewBaseRecord("QueuedMessageRecord")}
	c.BaseRecord.ID = r.BaseRecord.ID
	c.BaseRecord.CreatedAt = r.BaseRecord.CreatedAt
	c.BaseRecord.UpdatedAt = r.BaseRecord.UpdatedAt
	c.ConnectionId = r.ConnectionId
	c.Payload = append([]byte(nil), r.Payload...)
	return c
}

func NewStorageQueueRepository(storage corestorage.StorageService) QueueRepository {
	// ensure record type
	corestorage.RegisterRecordType("QueuedMessageRecord", newQueuedMessageRecord)
	return &storageQueueRepo{storage: storage}
}

func (r *storageQueueRepo) Add(msg *QueuedMessage) {
	if msg == nil || r.storage == nil || msg.Payload == nil {
		return
	}
	// serialize payload
	b, _ := json.Marshal(msg.Payload)
	statusStr := string(msg.Status)
	if statusStr == "" {
		statusStr = string(QueueStatusQueued)
	}
	rec := &queuedMessageRecord{BaseRecord: corestorage.NewBaseRecord("QueuedMessageRecord"), ConnectionId: msg.ConnectionId, Payload: b, Status: statusStr}
	_ = r.storage.Save(stdctx.Background(), rec)
}

func (r *storageQueueRepo) GetAll() []*QueuedMessage {
	if r.storage == nil {
		return nil
	}
	list, _ := r.storage.GetAll(stdctx.Background(), "QueuedMessageRecord")
	out := []*QueuedMessage{}
	for _, rec := range list {
		if q, ok := rec.(*queuedMessageRecord); ok {
			var env envelopeServices.EncryptedMessage
			_ = json.Unmarshal(q.Payload, &env)
			out = append(out, &QueuedMessage{ID: q.GetId(), ConnectionId: q.ConnectionId, Payload: &env, CreatedAt: q.GetCreatedAt(), Status: QueueStatus(q.Status)})
		}
	}
	// sort by CreatedAt
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

func (r *storageQueueRepo) GetByConnection(connectionId string) []*QueuedMessage {
	if r.storage == nil {
		return nil
	}
	q := corestorage.NewQuery().WithEqual("_tags.connectionId", connectionId).WithSort("createdAt", "ASC")
	list, _ := r.storage.FindByQuery(stdctx.Background(), "QueuedMessageRecord", *q)
	out := []*QueuedMessage{}
	for _, rec := range list {
		if qmr, ok := rec.(*queuedMessageRecord); ok {
			var env envelopeServices.EncryptedMessage
			_ = json.Unmarshal(qmr.Payload, &env)
			out = append(out, &QueuedMessage{ID: qmr.GetId(), ConnectionId: qmr.ConnectionId, Payload: &env, CreatedAt: qmr.GetCreatedAt(), Status: QueueStatus(qmr.Status)})
		}
	}
	return out
}

func (r *storageQueueRepo) PopByConnection(connectionId string, n int) []*QueuedMessage {
	if r.storage == nil {
		return nil
	}
	q := corestorage.NewQuery().WithEqual("_tags.connectionId", connectionId).WithEqual("_tags.status", string(QueueStatusQueued)).WithSort("createdAt", "ASC")
	list, _ := r.storage.FindByQuery(stdctx.Background(), "QueuedMessageRecord", *q)
	out := []*QueuedMessage{}
	for _, rec := range list {
		if n > 0 && len(out) >= n {
			break
		}
		qmr, ok := rec.(*queuedMessageRecord)
		if !ok {
			continue
		}
		var env envelopeServices.EncryptedMessage
		_ = json.Unmarshal(qmr.Payload, &env)
		out = append(out, &QueuedMessage{ID: qmr.GetId(), ConnectionId: qmr.ConnectionId, Payload: &env, CreatedAt: qmr.GetCreatedAt(), Status: QueueStatus(qmr.Status)})
		// mark delivered
		qmr.Status = string(QueueStatusDelivered)
		qmr.DeliveredAt = time.Now().Unix()
		_ = r.storage.Update(stdctx.Background(), qmr)
	}
	return out
}

func (r *storageQueueRepo) Clear() {
	if r.storage == nil {
		return
	}
	list, _ := r.storage.GetAll(stdctx.Background(), "QueuedMessageRecord")
	for _, rec := range list {
		_ = r.storage.Delete(stdctx.Background(), rec)
	}
}

func (r *storageQueueRepo) DeleteByIDs(ids []string) error {
	if r.storage == nil || len(ids) == 0 {
		return nil
	}
	for _, id := range ids {
		_ = r.storage.DeleteById(stdctx.Background(), "QueuedMessageRecord", id)
	}
	return nil
}
