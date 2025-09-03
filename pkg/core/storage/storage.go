package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// StorageService defines the interface for storage operations
type StorageService interface {
	Save(ctx context.Context, record Record) error
	Update(ctx context.Context, record Record) error
	Delete(ctx context.Context, record Record) error
	DeleteById(ctx context.Context, recordClass string, id string) error
	GetById(ctx context.Context, recordClass string, id string) (Record, error)
	GetAll(ctx context.Context, recordClass string) ([]Record, error)
	FindByQuery(ctx context.Context, recordClass string, query Query) ([]Record, error)
	FindSingleByQuery(ctx context.Context, recordClass string, query Query) (Record, error)
}

// Record represents a base record interface
type Record interface {
	GetId() string
	SetId(id string)
	GetType() string
	GetTags() map[string]string
	SetTags(tags map[string]string)
	GetTag(key string) (string, bool)
	SetTag(key, value string)
	GetCreatedAt() time.Time
	GetUpdatedAt() time.Time
	SetUpdatedAt(time time.Time)
	Clone() Record
	ToJSON() ([]byte, error)
	FromJSON(data []byte) error
}

// BaseRecord provides a base implementation of Record
type BaseRecord struct {
	ID        string            `json:"id"`
	Type      string            `json:"_type"`
	Tags      map[string]string `json:"_tags,omitempty"`
	CreatedAt time.Time         `json:"createdAt"`
	UpdatedAt time.Time         `json:"updatedAt"`
}

// NewBaseRecord creates a new BaseRecord
func NewBaseRecord(recordType string) *BaseRecord {
	now := time.Now()
	return &BaseRecord{
		ID:        uuid.New().String(),
		Type:      recordType,
		Tags:      make(map[string]string),
		CreatedAt: now,
		UpdatedAt: now,
	}
}

func (r *BaseRecord) GetId() string {
	return r.ID
}

func (r *BaseRecord) SetId(id string) {
	r.ID = id
}

func (r *BaseRecord) GetType() string {
	return r.Type
}

func (r *BaseRecord) GetTags() map[string]string {
	if r.Tags == nil {
		r.Tags = make(map[string]string)
	}
	return r.Tags
}

func (r *BaseRecord) SetTags(tags map[string]string) {
	r.Tags = tags
}

func (r *BaseRecord) GetTag(key string) (string, bool) {
	if r.Tags == nil {
		return "", false
	}
	value, exists := r.Tags[key]
	return value, exists
}

func (r *BaseRecord) SetTag(key, value string) {
	if r.Tags == nil {
		r.Tags = make(map[string]string)
	}
	r.Tags[key] = value
	r.UpdatedAt = time.Now()
}

func (r *BaseRecord) RemoveTag(key string) {
	if r.Tags != nil {
		delete(r.Tags, key)
		r.UpdatedAt = time.Now()
	}
}

func (r *BaseRecord) GetCreatedAt() time.Time {
	return r.CreatedAt
}

func (r *BaseRecord) GetUpdatedAt() time.Time {
	return r.UpdatedAt
}

func (r *BaseRecord) SetUpdatedAt(t time.Time) {
	r.UpdatedAt = t
}

func (r *BaseRecord) Clone() Record {
	clone := &BaseRecord{
		ID:        r.ID,
		Type:      r.Type,
		CreatedAt: r.CreatedAt,
		UpdatedAt: r.UpdatedAt,
	}

	if r.Tags != nil {
		clone.Tags = make(map[string]string)
		for k, v := range r.Tags {
			clone.Tags[k] = v
		}
	}

	return clone
}

func (r *BaseRecord) ToJSON() ([]byte, error) {
	return json.Marshal(r)
}

func (r *BaseRecord) FromJSON(data []byte) error {
	return json.Unmarshal(data, r)
}

// Query represents a storage query
type Query struct {
	// Simple equality queries
	Equal map[string]interface{} `json:"equal,omitempty"`

	// Text search queries
	Like map[string]string `json:"like,omitempty"`

	// Range queries
	GreaterThan   map[string]interface{} `json:"gt,omitempty"`
	GreaterThanEq map[string]interface{} `json:"gte,omitempty"`
	LessThan      map[string]interface{} `json:"lt,omitempty"`
	LessThanEq    map[string]interface{} `json:"lte,omitempty"`

	// Array queries
	In    map[string][]interface{} `json:"in,omitempty"`
	NotIn map[string][]interface{} `json:"nin,omitempty"`

	// Logical operators
	And []Query `json:"and,omitempty"`
	Or  []Query `json:"or,omitempty"`
	Not *Query  `json:"not,omitempty"`

	// Pagination
	Limit  int `json:"limit,omitempty"`
	Offset int `json:"offset,omitempty"`

	// Sorting
	Sort []SortOption `json:"sort,omitempty"`
}

// SortOption represents sorting configuration
type SortOption struct {
	Field string `json:"field"`
	Order string `json:"order"` // "ASC" or "DESC"
}

// NewQuery creates a new empty query
func NewQuery() *Query {
	return &Query{
		Equal:         make(map[string]interface{}),
		Like:          make(map[string]string),
		GreaterThan:   make(map[string]interface{}),
		GreaterThanEq: make(map[string]interface{}),
		LessThan:      make(map[string]interface{}),
		LessThanEq:    make(map[string]interface{}),
		In:            make(map[string][]interface{}),
		NotIn:         make(map[string][]interface{}),
	}
}

// WithEqual adds an equality condition to the query
func (q *Query) WithEqual(field string, value interface{}) *Query {
	if q.Equal == nil {
		q.Equal = make(map[string]interface{})
	}
	q.Equal[field] = value
	return q
}

// WithTag adds a tag equality condition to the query
func (q *Query) WithTag(key, value string) *Query {
	return q.WithEqual(fmt.Sprintf("_tags.%s", key), value)
}

// WithLike adds a LIKE condition to the query
func (q *Query) WithLike(field, pattern string) *Query {
	if q.Like == nil {
		q.Like = make(map[string]string)
	}
	q.Like[field] = pattern
	return q
}

// WithIn adds an IN condition to the query
func (q *Query) WithIn(field string, values ...interface{}) *Query {
	if q.In == nil {
		q.In = make(map[string][]interface{})
	}
	q.In[field] = values
	return q
}

// WithLimit sets the query limit
func (q *Query) WithLimit(limit int) *Query {
	q.Limit = limit
	return q
}

// WithOffset sets the query offset
func (q *Query) WithOffset(offset int) *Query {
	q.Offset = offset
	return q
}

// WithSort adds sorting to the query
func (q *Query) WithSort(field, order string) *Query {
	if q.Sort == nil {
		q.Sort = make([]SortOption, 0)
	}
	q.Sort = append(q.Sort, SortOption{Field: field, Order: order})
	return q
}

// Repository provides a higher-level interface for record operations
type Repository interface {
	Save(ctx context.Context, record Record) error
	Update(ctx context.Context, record Record) error
	Delete(ctx context.Context, record Record) error
	DeleteById(ctx context.Context, id string) error
	GetById(ctx context.Context, id string) (Record, error)
	GetAll(ctx context.Context) ([]Record, error)
	FindByQuery(ctx context.Context, query Query) ([]Record, error)
	FindSingleByQuery(ctx context.Context, query Query) (Record, error)
	GetRecordClass() string
}

// BaseRepository provides a base implementation of Repository
type BaseRepository struct {
	storage     StorageService
	recordClass string
}

// NewBaseRepository creates a new BaseRepository
func NewBaseRepository(storage StorageService, recordClass string) *BaseRepository {
	return &BaseRepository{
		storage:     storage,
		recordClass: recordClass,
	}
}

func (r *BaseRepository) Save(ctx context.Context, record Record) error {
	return r.storage.Save(ctx, record)
}

func (r *BaseRepository) Update(ctx context.Context, record Record) error {
	return r.storage.Update(ctx, record)
}

func (r *BaseRepository) Delete(ctx context.Context, record Record) error {
	return r.storage.Delete(ctx, record)
}

func (r *BaseRepository) DeleteById(ctx context.Context, id string) error {
	return r.storage.DeleteById(ctx, r.recordClass, id)
}

func (r *BaseRepository) GetById(ctx context.Context, id string) (Record, error) {
	return r.storage.GetById(ctx, r.recordClass, id)
}

func (r *BaseRepository) GetAll(ctx context.Context) ([]Record, error) {
	return r.storage.GetAll(ctx, r.recordClass)
}

func (r *BaseRepository) FindByQuery(ctx context.Context, query Query) ([]Record, error) {
	return r.storage.FindByQuery(ctx, r.recordClass, query)
}

func (r *BaseRepository) FindSingleByQuery(ctx context.Context, query Query) (Record, error) {
	return r.storage.FindSingleByQuery(ctx, r.recordClass, query)
}

func (r *BaseRepository) GetRecordClass() string {
	return r.recordClass
}
