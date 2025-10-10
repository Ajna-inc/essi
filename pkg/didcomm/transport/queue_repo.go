package transport

import (
	"sync"
	"time"

	"github.com/ajna-inc/essi/pkg/core/common"
	envelopeServices "github.com/ajna-inc/essi/pkg/didcomm/services"
)

// DIDComm queue transport support (simple in-memory repository)

const DidCommTransportQueue = "didcomm:transport/queue"

// QueueStatus represents the lifecycle state of a queued message
type QueueStatus string

const (
	QueueStatusQueued    QueueStatus = "queued"
	QueueStatusDelivered QueueStatus = "delivered" // delivered via v2 delivery-request, awaiting ack
	QueueStatusAcked     QueueStatus = "acked"
)

type QueuedMessage struct {
	ID            string
	ConnectionId  string
	RecipientDids []string
	Payload       *envelopeServices.EncryptedMessage
	CreatedAt     time.Time
	DeliveredAt   time.Time
	Status        QueueStatus
}

type QueueRepository interface {
	Add(msg *QueuedMessage)
	GetAll() []*QueuedMessage
	GetByConnection(connectionId string) []*QueuedMessage
	PopByConnection(connectionId string, n int) []*QueuedMessage
	DeleteByIDs(ids []string) error
	Clear()
}

type inMemoryQueueRepo struct {
	mu   sync.RWMutex
	list []*QueuedMessage
}

func (r *inMemoryQueueRepo) Add(msg *QueuedMessage) {
	if msg == nil {
		return
	}
	if msg.ID == "" {
		msg.ID = common.GenerateUUID()
	}
	if msg.Status == "" {
		msg.Status = QueueStatusQueued
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.list = append(r.list, msg)
}

func (r *inMemoryQueueRepo) GetAll() []*QueuedMessage {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*QueuedMessage, len(r.list))
	copy(out, r.list)
	return out
}

func (r *inMemoryQueueRepo) GetByConnection(connectionId string) []*QueuedMessage {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*QueuedMessage
	for _, m := range r.list {
		if m != nil && m.ConnectionId == connectionId {
			out = append(out, m)
		}
	}
	return out
}

func (r *inMemoryQueueRepo) PopByConnection(connectionId string, n int) []*QueuedMessage {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []*QueuedMessage
	// select only queued messages (not delivered/acked)
	for _, m := range r.list {
		if m != nil && m.ConnectionId == connectionId && m.Status == QueueStatusQueued {
			out = append(out, m)
			if n > 0 && len(out) >= n {
				break
			}
		}
	}
	// mark selected as delivered
	now := time.Now()
	sel := map[string]struct{}{}
	for _, m := range out {
		sel[m.ID] = struct{}{}
	}
	for _, m := range r.list {
		if m == nil {
			continue
		}
		if _, ok := sel[m.ID]; ok {
			m.Status = QueueStatusDelivered
			m.DeliveredAt = now
		}
	}
	return out
}

func (r *inMemoryQueueRepo) DeleteByIDs(ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	idset := map[string]struct{}{}
	for _, id := range ids {
		idset[id] = struct{}{}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	kept := make([]*QueuedMessage, 0, len(r.list))
	for _, m := range r.list {
		if m == nil {
			continue
		}
		if _, ok := idset[m.ID]; ok {
			continue
		}
		kept = append(kept, m)
	}
	r.list = kept
	return nil
}

func (r *inMemoryQueueRepo) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.list = nil
}

var globalQueueRepo QueueRepository = &inMemoryQueueRepo{}

func SetGlobalQueueRepository(repo QueueRepository) {
	if repo == nil {
		return
	}
	globalQueueRepo = repo
}

func GetGlobalQueueRepository() QueueRepository { return globalQueueRepo }
