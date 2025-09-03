package dids

import (
	"fmt"

	"github.com/ajna-inc/essi/pkg/core/context"
)

// DidCreateOptions captures inputs for DID creation
type DidCreateOptions struct {
	Method  string                 `json:"method"`
	Secret  string                 `json:"secret,omitempty"`
	Options map[string]interface{} `json:"options,omitempty"`
}

// DidCreateResult is the result of DID creation
type DidCreateResult struct {
	Did         string       `json:"did"`
	DidDocument *DidDocument `json:"didDocument,omitempty"`
	Keys        []string     `json:"keys,omitempty"`
	JobId       string       `json:"jobId,omitempty"`
}

// DidRegistrar registers DIDs for specific methods
type DidRegistrar interface {
	// Method returns the DID method this registrar supports (e.g., "key", "peer")
	Method() string
	// Create registers/creates a DID using the provided options
	Create(ctx *context.AgentContext, opts *DidCreateOptions) (*DidCreateResult, error)
}

// DidRegistrarService coordinates multiple registrars by method
type DidRegistrarService struct {
	registrars map[string]DidRegistrar
}

// NewDidRegistrarService constructs a registrar service
func NewDidRegistrarService() *DidRegistrarService {
	return &DidRegistrarService{registrars: map[string]DidRegistrar{}}
}

// RegisterRegistrar registers a registrar by its method
func (s *DidRegistrarService) RegisterRegistrar(reg DidRegistrar) {
	if reg == nil { return }
	if s.registrars == nil { s.registrars = map[string]DidRegistrar{} }
	s.registrars[reg.Method()] = reg
}

// GetRegistrar fetches a registrar for a method
func (s *DidRegistrarService) GetRegistrar(method string) (DidRegistrar, bool) {
	if s.registrars == nil { return nil, false }
	reg, ok := s.registrars[method]
	return reg, ok
}

// Create delegates creation to the appropriate registrar
func (s *DidRegistrarService) Create(ctx *context.AgentContext, opts *DidCreateOptions) (*DidCreateResult, error) {
	if opts == nil || opts.Method == "" {
		return nil, fmt.Errorf("did registrar: method not specified")
	}
	reg, ok := s.GetRegistrar(opts.Method)
	if !ok || reg == nil {
		return nil, fmt.Errorf("did registrar: no registrar for method %s", opts.Method)
	}
	return reg.Create(ctx, opts)
}


