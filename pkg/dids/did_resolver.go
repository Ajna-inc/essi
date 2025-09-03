package dids

import (
	"fmt"
	"sync"
	"time"

	"github.com/ajna-inc/essi/pkg/core/context"
)

// DidResolutionResult represents the result of DID resolution
type DidResolutionResult struct {
	DidDocument           *DidDocument           `json:"didDocument,omitempty"`
	DidDocumentMetadata   *DidDocumentMetadata   `json:"didDocumentMetadata"`
	DidResolutionMetadata *DidResolutionMetadata `json:"didResolutionMetadata"`
}

// DidDocumentMetadata represents metadata about the DID document
type DidDocumentMetadata struct {
	Created       *time.Time `json:"created,omitempty"`
	Updated       *time.Time `json:"updated,omitempty"`
	Deactivated   bool       `json:"deactivated,omitempty"`
	VersionId     string     `json:"versionId,omitempty"`
	NextUpdate    *time.Time `json:"nextUpdate,omitempty"`
	NextVersionId string     `json:"nextVersionId,omitempty"`
	EquivalentId  []string   `json:"equivalentId,omitempty"`
	CanonicalId   string     `json:"canonicalId,omitempty"`
}

// DidResolutionMetadata represents metadata about the resolution process
type DidResolutionMetadata struct {
	ContentType  string     `json:"contentType,omitempty"`
	Error        string     `json:"error,omitempty"`
	ErrorMessage string     `json:"errorMessage,omitempty"`
	Retrieved    *time.Time `json:"retrieved,omitempty"`
	SerialNumber string     `json:"serialNumber,omitempty"`
}

// DID resolution error types
const (
	DidResolutionErrorInvalidDid                 = "invalidDid"
	DidResolutionErrorNotFound                   = "notFound"
	DidResolutionErrorRepresentationNotSupported = "representationNotSupported"
	DidResolutionErrorMethodNotSupported         = "methodNotSupported"
	DidResolutionErrorInternalError              = "internalError"
	DidResolutionErrorDeactivated                = "deactivated"
)

// DidResolver interface defines the contract for DID resolution
type DidResolver interface {
	// Resolve resolves a DID to a DID document
	Resolve(ctx *context.AgentContext, did string, options *DidResolutionOptions) (*DidResolutionResult, error)

	// SupportedMethods returns the DID methods supported by this resolver
	SupportedMethods() []string
}

// DidResolutionOptions represents options for DID resolution
type DidResolutionOptions struct {
	Accept           string            `json:"accept,omitempty"`
	VersionId        string            `json:"versionId,omitempty"`
	VersionTime      *time.Time        `json:"versionTime,omitempty"`
	NoCache          bool              `json:"noCache,omitempty"`
	AdditionalParams map[string]string `json:"-"`
}

// DidResolverService manages DID resolution across multiple methods
type DidResolverService struct {
	resolvers map[string]DidResolver
	cache     DidResolutionCache
	mutex     sync.RWMutex
}

// DidResolutionCache interface for caching DID resolution results
type DidResolutionCache interface {
	Get(did string) (*DidResolutionResult, bool)
	Set(did string, result *DidResolutionResult, ttl time.Duration)
	Delete(did string)
	Clear()
}

// NewDidResolverService creates a new DID resolver service
func NewDidResolverService() *DidResolverService {
	return &DidResolverService{
		resolvers: make(map[string]DidResolver),
		cache:     NewSimpleDidResolutionCache(),
	}
}

// RegisterResolver registers a DID resolver for specific methods
func (s *DidResolverService) RegisterResolver(resolver DidResolver) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	for _, method := range resolver.SupportedMethods() {
		s.resolvers[method] = resolver
	}
}

// UnregisterResolver unregisters a DID resolver
func (s *DidResolverService) UnregisterResolver(method string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	delete(s.resolvers, method)
}

// Resolve resolves a DID using the appropriate resolver
func (s *DidResolverService) Resolve(agentContext *context.AgentContext, did string, options *DidResolutionOptions) (*DidResolutionResult, error) {
	if options == nil {
		options = &DidResolutionOptions{}
	}

	// Parse the DID to get the method
	parsedDid := TryParseDid(did)
	if parsedDid == nil {
		return &DidResolutionResult{
			DidResolutionMetadata: &DidResolutionMetadata{
				Error:        DidResolutionErrorInvalidDid,
				ErrorMessage: fmt.Sprintf("Invalid DID format: %s", did),
			},
		}, nil
	}

	// Check cache first (unless noCache is specified)
	if !options.NoCache {
		if cached, found := s.cache.Get(did); found {
			return cached, nil
		}
	}

	// Find resolver for the method
	s.mutex.RLock()
	resolver, exists := s.resolvers[parsedDid.Method]
	s.mutex.RUnlock()

	if !exists {
		return &DidResolutionResult{
			DidResolutionMetadata: &DidResolutionMetadata{
				Error:        DidResolutionErrorMethodNotSupported,
				ErrorMessage: fmt.Sprintf("No resolver registered for DID method: %s", parsedDid.Method),
			},
		}, nil
	}

	// Resolve using the appropriate resolver
	result, err := resolver.Resolve(agentContext, did, options)
	if err != nil {
		return &DidResolutionResult{
			DidResolutionMetadata: &DidResolutionMetadata{
				Error:        DidResolutionErrorInternalError,
				ErrorMessage: err.Error(),
			},
		}, nil
	}

	// Cache successful resolution (unless noCache is specified)
	if !options.NoCache && result.DidDocument != nil && result.DidResolutionMetadata.Error == "" {
		// Cache for 1 hour by default
		s.cache.Set(did, result, time.Hour)
	}

	// Set resolution metadata
	if result.DidResolutionMetadata == nil {
		result.DidResolutionMetadata = &DidResolutionMetadata{}
	}
	now := time.Now()
	result.DidResolutionMetadata.Retrieved = &now

	return result, nil
}

// ResolveDidDocument resolves a DID and returns just the DID document
func (s *DidResolverService) ResolveDidDocument(agentContext *context.AgentContext, did string) (*DidDocument, error) {
	result, err := s.Resolve(agentContext, did, nil)
	if err != nil {
		return nil, err
	}

	if result.DidResolutionMetadata.Error != "" {
		return nil, fmt.Errorf("DID resolution failed: %s - %s",
			result.DidResolutionMetadata.Error,
			result.DidResolutionMetadata.ErrorMessage)
	}

	if result.DidDocument == nil {
		return nil, fmt.Errorf("DID document not found")
	}

	return result.DidDocument, nil
}

// GetSupportedMethods returns all supported DID methods
func (s *DidResolverService) GetSupportedMethods() []string {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	methods := make([]string, 0, len(s.resolvers))
	for method := range s.resolvers {
		methods = append(methods, method)
	}

	return methods
}

// SetCache sets a custom cache implementation
func (s *DidResolverService) SetCache(cache DidResolutionCache) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.cache = cache
}

// ClearCache clears the resolution cache
func (s *DidResolverService) ClearCache() {
	if s.cache != nil {
		s.cache.Clear()
	}
}

// SimpleDidResolutionCache provides a simple in-memory cache
type SimpleDidResolutionCache struct {
	cache map[string]*cacheEntry
	mutex sync.RWMutex
}

type cacheEntry struct {
	result    *DidResolutionResult
	expiresAt time.Time
}

// NewSimpleDidResolutionCache creates a new simple cache
func NewSimpleDidResolutionCache() *SimpleDidResolutionCache {
	cache := &SimpleDidResolutionCache{
		cache: make(map[string]*cacheEntry),
	}

	// Start cleanup goroutine
	go cache.cleanupExpired()

	return cache
}

// Get retrieves a cached result
func (c *SimpleDidResolutionCache) Get(did string) (*DidResolutionResult, bool) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	entry, exists := c.cache[did]
	if !exists {
		return nil, false
	}

	// Check if expired
	if time.Now().After(entry.expiresAt) {
		// Clean up expired entry
		go func() {
			c.mutex.Lock()
			delete(c.cache, did)
			c.mutex.Unlock()
		}()
		return nil, false
	}

	return entry.result, true
}

// Set stores a result in the cache
func (c *SimpleDidResolutionCache) Set(did string, result *DidResolutionResult, ttl time.Duration) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.cache[did] = &cacheEntry{
		result:    result,
		expiresAt: time.Now().Add(ttl),
	}
}

// Delete removes a cached result
func (c *SimpleDidResolutionCache) Delete(did string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	delete(c.cache, did)
}

// Clear removes all cached results
func (c *SimpleDidResolutionCache) Clear() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.cache = make(map[string]*cacheEntry)
}

// cleanupExpired periodically removes expired entries
func (c *SimpleDidResolutionCache) cleanupExpired() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			now := time.Now()
			c.mutex.Lock()
			for did, entry := range c.cache {
				if now.After(entry.expiresAt) {
					delete(c.cache, did)
				}
			}
			c.mutex.Unlock()
		}
	}
}

// BaseDidResolver provides common functionality for DID resolvers
type BaseDidResolver struct {
	supportedMethods []string
}

// NewBaseDidResolver creates a new base resolver
func NewBaseDidResolver(methods []string) *BaseDidResolver {
	return &BaseDidResolver{
		supportedMethods: methods,
	}
}

// SupportedMethods returns the supported methods
func (r *BaseDidResolver) SupportedMethods() []string {
	return r.supportedMethods
}

// CreateDidResolutionResult creates a successful resolution result
func (r *BaseDidResolver) CreateDidResolutionResult(didDocument *DidDocument) *DidResolutionResult {
	return &DidResolutionResult{
		DidDocument:         didDocument,
		DidDocumentMetadata: &DidDocumentMetadata{},
		DidResolutionMetadata: &DidResolutionMetadata{
			ContentType: "application/did+ld+json",
		},
	}
}

// CreateDidResolutionError creates an error resolution result
func (r *BaseDidResolver) CreateDidResolutionError(errorType, errorMessage string) *DidResolutionResult {
	return &DidResolutionResult{
		DidResolutionMetadata: &DidResolutionMetadata{
			Error:        errorType,
			ErrorMessage: errorMessage,
		},
	}
}

// Validation helpers

// ValidateDidForResolution validates a DID before resolution
func ValidateDidForResolution(did string) error {
	if did == "" {
		return fmt.Errorf("DID cannot be empty")
	}

	if !IsValidDid(did) {
		return fmt.Errorf("invalid DID format: %s", did)
	}

	return nil
}

// IsDidDeactivated checks if a DID document indicates deactivation
func IsDidDeactivated(result *DidResolutionResult) bool {
	if result.DidDocumentMetadata != nil {
		return result.DidDocumentMetadata.Deactivated
	}
	return false
}

// GetDidFromResult extracts the DID from a resolution result
func GetDidFromResult(result *DidResolutionResult) string {
	if result.DidDocument != nil {
		return result.DidDocument.Id
	}
	return ""
}
