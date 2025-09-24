package dids

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/core/di"
	didsCore "github.com/ajna-inc/essi/pkg/dids"
	"github.com/ajna-inc/essi/pkg/kanon"
)

// KanonDidRegistrar handles DID registration on Kanon ledger
// Following Credo-TS KanonDIDRegistrar pattern
type KanonDidRegistrar struct {
	ledgerService *kanon.EthereumLedgerService
}

// KanonDidRegistrarCreate creates a new Kanon DID registrar
func KanonDidRegistrarCreate(ledgerService *kanon.EthereumLedgerService) *KanonDidRegistrar {
	return &KanonDidRegistrar{
		ledgerService: ledgerService,
	}
}

// NewKanonDidRegistrar creates a registrar that resolves the ledger service from context
func NewKanonDidRegistrar() *KanonDidRegistrar { return &KanonDidRegistrar{ledgerService: nil} }

// Method implements dids.DidRegistrar
func (r *KanonDidRegistrar) Method() string { return "kanon" }

// Create implements dids.DidRegistrar with the canonical signature
func (r *KanonDidRegistrar) Create(agentContext *context.AgentContext, opts *didsCore.DidCreateOptions) (*didsCore.DidCreateResult, error) {
	if opts == nil {
		return nil, fmt.Errorf("did registrar: options is nil")
	}
	// Minimal: read did from options map to avoid inventing identifiers here
	var did string
	if opts.Options != nil {
		if v, ok := opts.Options["did"].(string); ok {
			did = v
		}
	}
	if did == "" {
		return nil, fmt.Errorf("did registrar: 'did' not provided in options")
	}

	// Build a minimal DID Document
	didDocument := &didsCore.DidDocument{
		Id:         did,
		Controller: []string{did},
	}

	docJson, err := json.Marshal(didDocument)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal DID document: %w", err)
	}

	// Resolve ledger service if not injected
	svc := r.ledgerService
	if svc == nil {
		if agentContext != nil && agentContext.DependencyManager != nil {
			if dm, ok := agentContext.DependencyManager.(di.DependencyManager); ok {
				if any, err := dm.Resolve(di.TokenKanonEthereumLedgerService); err == nil {
					svc, _ = any.(*kanon.EthereumLedgerService)
				}
			}
		}
	}
	if svc == nil {
		return nil, fmt.Errorf("kanon ledger service not available from DI")
	}

	// Register on ledger
	if err := svc.GetLedger().RegisterDID(did, string(docJson), ""); err != nil {
		return &didsCore.DidCreateResult{}, err
	}

	return &didsCore.DidCreateResult{Did: did, DidDocument: didDocument}, nil
}

// Update updates an existing DID on the Kanon ledger
func (r *KanonDidRegistrar) Update(agentContext *context.AgentContext, did string, didDocument *didsCore.DidDocument) error {
	log.Printf("KanonDidRegistrar: Updating DID: %s", did)

	// Marshal to JSON for storage
	docJson, err := json.Marshal(didDocument)
	if err != nil {
		return fmt.Errorf("failed to marshal DID document: %w", err)
	}

	// Resolve ledger service if not injected
	svc := r.ledgerService
	if svc == nil {
		if agentContext != nil && agentContext.DependencyManager != nil {
			if dm, ok := agentContext.DependencyManager.(di.DependencyManager); ok {
				if any, err := dm.Resolve(di.TokenKanonEthereumLedgerService); err == nil {
					svc, _ = any.(*kanon.EthereumLedgerService)
				}
			}
		}
	}
	if svc == nil {
		return fmt.Errorf("kanon ledger service not available from DI")
	}

	// Update on ledger
	ledger := svc.GetLedger()
	return ledger.UpdateDID(did, string(docJson), "")
}

// CreateResource creates a resource (schema, credDef, etc.) on the Kanon ledger
// This follows the Credo-TS pattern where resources are linked to DIDs
func (r *KanonDidRegistrar) CreateResource(agentContext *context.AgentContext, resourceId string, options CreateResourceOptions) (*CreateResourceResult, error) {
	log.Printf("KanonDidRegistrar: Creating resource: %s", resourceId)

	// Marshal resource data
	dataJson, err := json.Marshal(options.Data)
	if err != nil {
		return &CreateResourceResult{
			DidState: &DidState{
				State:  "failed",
				Reason: fmt.Sprintf("failed to marshal resource data: %v", err),
			},
		}, nil
	}

	// Resolve ledger service if not injected
	svc := r.ledgerService
	if svc == nil {
		if agentContext != nil && agentContext.DependencyManager != nil {
			if dm, ok := agentContext.DependencyManager.(di.DependencyManager); ok {
				if any, err := dm.Resolve(di.TokenKanonEthereumLedgerService); err == nil {
					svc, _ = any.(*kanon.EthereumLedgerService)
				}
			}
		}
	}
	if svc == nil {
		return &CreateResourceResult{DidState: &DidState{State: "failed", Reason: "kanon ledger service not available from DI"}}, nil
	}

	// Store based on resource type
	ledger := svc.GetLedger()
	var storeErr error
	switch options.Data["resourceType"] {
	case "anonCredsSchema":
		storeErr = ledger.RegisterSchema(resourceId, string(dataJson), options.IssuerId)
	case "anonCredsCredentialDefinition":
		// Extract schema ID if present
		schemaId := ""
		if data, ok := options.Data["data"].(map[string]interface{}); ok {
			if sid, ok := data["schemaId"].(string); ok {
				schemaId = sid
			}
		}
		storeErr = ledger.RegisterCredentialDefinition(resourceId, schemaId, options.IssuerId, string(dataJson))
	default:
		storeErr = fmt.Errorf("unsupported resource type: %v", options.Data["resourceType"])
	}

	if storeErr != nil {
		return &CreateResourceResult{DidState: &DidState{State: "failed", Reason: storeErr.Error()}}, nil
	}

	return &CreateResourceResult{
		DidState:                &DidState{State: "finished", Did: resourceId},
		DidRegistrationMetadata: map[string]interface{}{"resourceId": resourceId, "network": options.Network},
		DidDocumentMetadata:     map[string]interface{}{},
	}, nil
}

// CreateDidOptions holds options for DID creation
type CreateDidOptions struct {
	Did                string
	VerificationMethod *didsCore.VerificationMethod
	Network            string
}

// CreateResourceOptions holds options for resource creation
type CreateResourceOptions struct {
	Data     map[string]interface{}
	Network  string
	IssuerId string
}

// CreateDidResult represents the result of DID creation
type CreateDidResult struct {
	DidState                *DidState
	DidRegistrationMetadata map[string]interface{}
	DidDocumentMetadata     map[string]interface{}
}

// CreateResourceResult represents the result of resource creation
type CreateResourceResult struct {
	DidState                *DidState
	DidRegistrationMetadata map[string]interface{}
	DidDocumentMetadata     map[string]interface{}
}

// DidState represents the state of a DID operation
type DidState struct {
	State       string // "finished", "failed", "action", "wait"
	Did         string
	DidDocument *didsCore.DidDocument
	Reason      string // For failed state
}
