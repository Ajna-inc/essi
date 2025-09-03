package storage

import (
	"context"
	"fmt"
	"time"

	"github.com/Ajna-inc/askar-go"
	"github.com/google/uuid"
	askarerrors "github.com/ajna-inc/essi/pkg/askar/errors"
	agentcontext "github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/core/storage"
)

// AskarStorageService implements StorageService using Askar
type AskarStorageService struct {
	storeManager StoreManager
	storeID      string
}

// StoreManager interface for store operations
type StoreManager interface {
	WithSession(ctx *agentcontext.AgentContext, storeID string, fn func(*askar.Session) error) error
	WithTransaction(ctx *agentcontext.AgentContext, storeID string, fn func(*askar.Session) error) error
}

// NewAskarStorageService creates a new AskarStorageService
func NewAskarStorageService(storeManager StoreManager, storeID string) *AskarStorageService {
	return &AskarStorageService{
		storeManager: storeManager,
		storeID:      storeID,
	}
}

// Save saves a new record
func (s *AskarStorageService) Save(ctx context.Context, record storage.Record) error {
	if record == nil {
		return fmt.Errorf("record cannot be nil")
	}
	
	// Generate ID if not set
	if record.GetId() == "" {
		record.SetId(uuid.New().String())
	}
	
	record.SetUpdatedAt(time.Now())
	
	agentCtx := getAgentContext(ctx)
	
	return s.storeManager.WithTransaction(agentCtx, s.storeID, func(session *askar.Session) error {
		existing, err := session.Fetch(record.GetType(), record.GetId(), false)
		if err != nil {
			return askarerrors.WrapAskarError(err)
		}
		if existing != nil {
			return fmt.Errorf("record with ID %s already exists", record.GetId())
		}
		
		value, err := record.ToJSON()
		if err != nil {
			return fmt.Errorf("failed to serialize record: %w", err)
		}
		
		// Insert the record
		// Convert tags from map[string]string to map[string]interface{}
		tags := make(map[string]interface{})
		for k, v := range record.GetTags() {
			tags[k] = v
		}
		
		err = session.Insert(
			record.GetType(),    // category
			record.GetId(),      // name
			value,               // value
			tags,                // tags
		)
		
		if err != nil {
			return askarerrors.WrapAskarError(err)
		}
		
		return nil
	})
}

// Update updates an existing record
func (s *AskarStorageService) Update(ctx context.Context, record storage.Record) error {
	if record == nil {
		return fmt.Errorf("record cannot be nil")
	}
	
	record.SetUpdatedAt(time.Now())
	
	agentCtx := getAgentContext(ctx)
	
	return s.storeManager.WithTransaction(agentCtx, s.storeID, func(session *askar.Session) error {
		// Check if record exists
		existing, err := session.Fetch(record.GetType(), record.GetId(), false)
		if err != nil {
			return askarerrors.WrapAskarError(err)
		}
		if existing == nil {
			return fmt.Errorf("record with ID %s not found", record.GetId())
		}
		
		value, err := record.ToJSON()
		if err != nil {
			return fmt.Errorf("failed to serialize record: %w", err)
		}
		
		// Convert tags from map[string]string to map[string]interface{}
		tags := make(map[string]interface{})
		for k, v := range record.GetTags() {
			tags[k] = v
		}
		
		err = session.Replace(
			record.GetType(),    // category
			record.GetId(),      // name
			value,               // value
			tags,                // tags
		)
		
		if err != nil {
			return askarerrors.WrapAskarError(err)
		}
		
		return nil
	})
}

// Delete deletes a record
func (s *AskarStorageService) Delete(ctx context.Context, record storage.Record) error {
	if record == nil {
		return fmt.Errorf("record cannot be nil")
	}
	
	return s.DeleteById(ctx, record.GetType(), record.GetId())
}

// DeleteById deletes a record by ID
func (s *AskarStorageService) DeleteById(ctx context.Context, recordClass string, id string) error {
	agentCtx := getAgentContext(ctx)
	
	return s.storeManager.WithTransaction(agentCtx, s.storeID, func(session *askar.Session) error {
		err := session.Remove(recordClass, id)
		if err != nil {
			return askarerrors.WrapAskarError(err)
		}
		
		return nil
	})
}

// GetById retrieves a record by ID
func (s *AskarStorageService) GetById(ctx context.Context, recordClass string, id string) (storage.Record, error) {
	var record storage.Record
	
	agentCtx := getAgentContext(ctx)
	
	err := s.storeManager.WithSession(agentCtx, s.storeID, func(session *askar.Session) error {
		entry, err := session.Fetch(recordClass, id, false)
		if err != nil {
			return askarerrors.WrapAskarError(err)
		}
		
		if entry == nil {
			return fmt.Errorf("record with ID %s not found", id)
		}
		// Note: entry is automatically cleaned up
		
		// Create a new record and deserialize
		record = createRecord(recordClass)
		if err := record.FromJSON(entry.Value); err != nil {
			return fmt.Errorf("failed to deserialize record: %w", err)
		}
		
		// Deserialize tags (already a map)
		if len(entry.Tags) > 0 {
			tags := make(map[string]string)
			for k, v := range entry.Tags {
				if strVal, ok := v.(string); ok {
					tags[k] = strVal
				}
			}
			record.SetTags(tags)
		}
		
		return nil
	})
	
	if err != nil {
		return nil, err
	}
	
	return record, nil
}

// GetAll retrieves all records of a given class
func (s *AskarStorageService) GetAll(ctx context.Context, recordClass string) ([]storage.Record, error) {
	var records []storage.Record
	
	agentCtx := getAgentContext(ctx)
	
	err := s.storeManager.WithSession(agentCtx, s.storeID, func(session *askar.Session) error {
		// Fetch all records of this type (no limit)
		entries, err := session.FetchAll(recordClass, nil, -1, false, "", false)
		if err != nil {
			return askarerrors.WrapAskarError(err)
		}
		
		for _, entry := range entries {
			
			// Create and deserialize record
			record := createRecord(recordClass)
			if err := record.FromJSON(entry.Value); err != nil {
				// Skip malformed records
				continue
			}
			
			// Deserialize tags (already a map)
			if len(entry.Tags) > 0 {
				tags := make(map[string]string)
				for k, v := range entry.Tags {
					if strVal, ok := v.(string); ok {
						tags[k] = strVal
					}
				}
				record.SetTags(tags)
			}
			
			records = append(records, record)
		}
		
		return nil
	})
	
	if err != nil {
		return nil, err
	}
	
	return records, nil
}

// FindByQuery finds records matching a query
func (s *AskarStorageService) FindByQuery(ctx context.Context, recordClass string, query storage.Query) ([]storage.Record, error) {
	var records []storage.Record
	
	agentCtx := getAgentContext(ctx)
	
	err := s.storeManager.WithSession(agentCtx, s.storeID, func(session *askar.Session) error {
		// Convert query to Askar tag filter
		tagFilter := buildTagFilterMap(query)
		
		// Fetch with filter (use -1 when Limit == 0 for no limit)
		limit := int64(query.Limit)
		if limit == 0 {
			limit = -1
		}
		entries, err := session.FetchAll(recordClass, tagFilter, limit, false, "", false)
		if err != nil {
			return askarerrors.WrapAskarError(err)
		}
		
		// Apply offset manually if needed
		startIndex := 0
		if query.Offset > 0 {
			startIndex = int(query.Offset)
			if startIndex >= len(entries) {
				return nil // No results
			}
		}
		
		for i := startIndex; i < len(entries); i++ {
			entry := entries[i]
			
			// Create and deserialize record
			record := createRecord(recordClass)
			if err := record.FromJSON(entry.Value); err != nil {
				// Skip malformed records
				continue
			}
			
			// Deserialize tags (already a map)
			if len(entry.Tags) > 0 {
				tags := make(map[string]string)
				for k, v := range entry.Tags {
					if strVal, ok := v.(string); ok {
						tags[k] = strVal
					}
				}
				record.SetTags(tags)
			}
			
			// Apply additional filtering that Askar doesn't support natively
			if matchesQuery(record, query) {
				records = append(records, record)
			}
		}
		
		return nil
	})
	
	if err != nil {
		return nil, err
	}
	
	// Apply sorting if specified
	if len(query.Sort) > 0 {
		// TODO: Implement sorting
	}
	
	return records, nil
}

// FindSingleByQuery finds a single record matching a query
func (s *AskarStorageService) FindSingleByQuery(ctx context.Context, recordClass string, query storage.Query) (storage.Record, error) {
	query.Limit = 1
	
	records, err := s.FindByQuery(ctx, recordClass, query)
	if err != nil {
		return nil, err
	}
	
	if len(records) == 0 {
		return nil, fmt.Errorf("no record found matching query")
	}
	
	return records[0], nil
}

// Helper functions

// getAgentContext extracts or creates an AgentContext from context.Context
func getAgentContext(ctx context.Context) *agentcontext.AgentContext {
	// AgentContext embeds context.Context, not implements it
	// Check if it's stored as a value instead
	
	// Check if AgentContext is stored as a value
	if val := ctx.Value("agentContext"); val != nil {
		if agentCtx, ok := val.(*agentcontext.AgentContext); ok {
			return agentCtx
		}
	}
	
	// Create a minimal context if none found
	return &agentcontext.AgentContext{
		Context: ctx,
	}
}

// createRecord creates a new record instance for the given class
func createRecord(recordClass string) storage.Record {
	// Use the factory registry to create the correct record type
	record, err := storage.CreateRecord(recordClass)
	if err != nil {
		// Fallback to BaseRecord if there's an error
		return storage.NewBaseRecord(recordClass)
	}
	return record
}

// buildTagFilterMap converts a storage.Query to Askar tag filter map
func buildTagFilterMap(query storage.Query) map[string]interface{} {
	filter := make(map[string]interface{})
	
	// Handle equality queries
	for key, value := range query.Equal {
		// Convert tag queries
		if len(key) > 6 && key[:6] == "_tags." {
			tagKey := key[6:]
			filter[tagKey] = value
		}
	}
	
	if len(filter) == 0 {
		return nil
	}
	
	return filter
}

// matchesQuery checks if a record matches the query criteria
func matchesQuery(record storage.Record, query storage.Query) bool {
	// Check equality conditions
	for field, expected := range query.Equal {
		actual := getFieldValue(record, field)
		if actual != expected {
			return false
		}
	}
	
	// Check LIKE conditions
	for field, pattern := range query.Like {
		actual := getFieldValue(record, field)
		if !matchesPattern(actual, pattern) {
			return false
		}
	}
	
	// Check IN conditions
	for field, values := range query.In {
		actual := getFieldValue(record, field)
		found := false
		for _, value := range values {
			if actual == value {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	
	// Check NOT IN conditions
	for field, values := range query.NotIn {
		actual := getFieldValue(record, field)
		for _, value := range values {
			if actual == value {
				return false
			}
		}
	}
	
	// TODO: Implement other query conditions (GreaterThan, LessThan, etc.)
	
	return true
}

// getFieldValue gets a field value from a record
func getFieldValue(record storage.Record, field string) interface{} {
	// Handle tag fields
	if len(field) > 6 && field[:6] == "_tags." {
		tagKey := field[6:]
		value, _ := record.GetTag(tagKey)
		return value
	}
	
	// Handle standard fields
	switch field {
	case "id":
		return record.GetId()
	case "_type":
		return record.GetType()
	case "createdAt":
		return record.GetCreatedAt()
	case "updatedAt":
		return record.GetUpdatedAt()
	default:
		// For custom fields, we'd need to deserialize the record
		// This is a simplified implementation
		return nil
	}
}

// matchesPattern checks if a value matches a LIKE pattern
func matchesPattern(value interface{}, pattern string) bool {
	// Simple implementation - just check if pattern is contained
	// In a real implementation, you'd support SQL LIKE patterns
	if _, ok := value.(string); ok {
		// TODO: Implement proper LIKE pattern matching
		return true
	}
	return false
}

// TransactionOptions represents options for a transaction
type TransactionOptions struct {
	Profile string
}

// WithTransaction executes a function within a transaction
func (s *AskarStorageService) WithTransaction(ctx context.Context, fn func(context.Context) error, opts ...TransactionOptions) error {
	agentCtx := getAgentContext(ctx)
	
	profile := ""
	if len(opts) > 0 {
		profile = opts[0].Profile
	}
	
	return s.storeManager.WithTransaction(agentCtx, s.storeID, func(session *askar.Session) error {
		// Create a new context with the session
		txCtx := context.WithValue(ctx, "askarSession", session)
		if profile != "" {
			txCtx = context.WithValue(txCtx, "askarProfile", profile)
		}
		
		return fn(txCtx)
	})
}

// WithSession executes a function within a session (read-only)
func (s *AskarStorageService) WithSession(ctx context.Context, fn func(context.Context) error, opts ...TransactionOptions) error {
	agentCtx := getAgentContext(ctx)
	
	profile := ""
	if len(opts) > 0 {
		profile = opts[0].Profile
	}
	
	return s.storeManager.WithSession(agentCtx, s.storeID, func(session *askar.Session) error {
		// Create a new context with the session
		sessionCtx := context.WithValue(ctx, "askarSession", session)
		if profile != "" {
			sessionCtx = context.WithValue(sessionCtx, "askarProfile", profile)
		}
		
		return fn(sessionCtx)
	})
}