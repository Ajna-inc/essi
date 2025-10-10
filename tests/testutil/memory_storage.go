package testutil

import (
	"context"
	"encoding/json"
	"strings"
	"sync"

	corectx "github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/core/di"
	corestorage "github.com/ajna-inc/essi/pkg/core/storage"
)

// InMemoryStorageService is a minimal in-memory implementation of StorageService
type InMemoryStorageService struct {
	mu   sync.RWMutex
	data map[string]map[string][]byte // class -> id -> full JSON
}

func NewInMemoryStorageService() *InMemoryStorageService {
	return &InMemoryStorageService{data: make(map[string]map[string][]byte)}
}

func (s *InMemoryStorageService) Save(ctx context.Context, record corestorage.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.data[record.GetType()]; !ok {
		s.data[record.GetType()] = make(map[string][]byte)
	}
	b, err := record.ToJSON()
	if err != nil {
		return err
	}
	s.data[record.GetType()][record.GetId()] = b
	return nil
}

func (s *InMemoryStorageService) Update(ctx context.Context, record corestorage.Record) error {
	return s.Save(ctx, record)
}

func (s *InMemoryStorageService) Delete(ctx context.Context, record corestorage.Record) error {
	return s.DeleteById(ctx, record.GetType(), record.GetId())
}

func (s *InMemoryStorageService) DeleteById(ctx context.Context, recordClass, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if m, ok := s.data[recordClass]; ok {
		delete(m, id)
	}
	return nil
}

func (s *InMemoryStorageService) GetById(ctx context.Context, recordClass, id string) (corestorage.Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if m, ok := s.data[recordClass]; ok {
		if b, ok := m[id]; ok {
			rec, _ := corestorage.CreateRecord(recordClass)
			_ = rec.FromJSON(b)
			return rec, nil
		}
	}
	return nil, nil
}

func (s *InMemoryStorageService) GetAll(ctx context.Context, recordClass string) ([]corestorage.Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []corestorage.Record{}
	if m, ok := s.data[recordClass]; ok {
		for _, b := range m {
			rec, _ := corestorage.CreateRecord(recordClass)
			_ = rec.FromJSON(b)
			out = append(out, rec)
		}
	}
	return out, nil
}

func (s *InMemoryStorageService) FindByQuery(ctx context.Context, recordClass string, q corestorage.Query) ([]corestorage.Record, error) {
	// Minimal tag-based equality: keys like "_tags.foo" must match record.GetTags()["foo"] == value
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []corestorage.Record{}
	for _, b := range s.data[recordClass] {
		rec, _ := corestorage.CreateRecord(recordClass)
		_ = rec.FromJSON(b)
		if matches(rec, q) {
			out = append(out, rec)
		}
	}
	return out, nil
}

func (s *InMemoryStorageService) FindSingleByQuery(ctx context.Context, recordClass string, q corestorage.Query) (corestorage.Record, error) {
	list, _ := s.FindByQuery(ctx, recordClass, q)
	if len(list) == 0 {
		return nil, nil
	}
	return list[0], nil
}

func matches(rec corestorage.Record, q corestorage.Query) bool {
	// Only handle Equal on tags for now
	if q.Equal != nil {
		for k, v := range q.Equal {
			if strings.HasPrefix(k, "_tags.") {
				tag := strings.TrimPrefix(k, "_tags.")
				if tv, ok := rec.GetTags()[tag]; !ok || tv != toString(v) {
					return false
				}
			}
		}
	}
	return true
}

func toString(v interface{}) string {
	switch t := v.(type) {
	case string:
		return t
	default:
		b, _ := json.Marshal(v)
		return string(b)
	}
}

// MemoryStorageModule registers an in-memory storage service into DI
type MemoryStorageModule struct{ svc *InMemoryStorageService }

func NewMemoryStorageModule() *MemoryStorageModule {
	return &MemoryStorageModule{svc: NewInMemoryStorageService()}
}

func (m *MemoryStorageModule) Register(dm di.DependencyManager) error {
	dm.RegisterInstance(di.TokenStorageService, m.svc)
	return nil
}
func (m *MemoryStorageModule) OnInitializeContext(ctx *corectx.AgentContext) error { return nil }
func (m *MemoryStorageModule) OnShutdown(ctx *corectx.AgentContext) error          { return nil }
