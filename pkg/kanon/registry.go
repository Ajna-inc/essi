package kanon

import (
	"context"
	"encoding/json"
	"log"
	"regexp"
	"time"

	"github.com/ajna-inc/essi/pkg/anoncreds/registry"
	"github.com/ajna-inc/essi/pkg/anoncreds/repository"
	"github.com/ajna-inc/essi/pkg/kanon/ledger"
    "github.com/ajna-inc/essi/pkg/core/di"
    ac "github.com/Ajna-inc/anoncreds-go/pkg/anoncreds"
    issuercore "github.com/ajna-inc/essi/pkg/anoncreds/issuer"
)

// Registry implements the anoncreds Registry interface backed by a Kanon ledger (EVM).
// Phase 1 supports read operations required for holder flows.
type Registry struct {
	rx     *regexp.Regexp
	ledger ledger.KanonLedger
    dm     di.DependencyManager
}

// NewRegistry creates a new Kanon registry that owns its identifier patterns.
func NewRegistry(l ledger.KanonLedger) *Registry {
	rx := regexp.MustCompile(`^(did:kanon:|schema:kanon:|creddef:kanon:)`)
	return &Registry{rx: rx, ledger: l}
}

// InitializeWithDI allows TS-like initialization after construction.
// If no ledger was supplied at construction, resolve it from typed DI.
func (r *Registry) InitializeWithDI(dm di.DependencyManager) error {
    log.Printf("🔍 [KanonRegistry] InitializeWithDI called, current ledger: %v", r.ledger != nil)
    if r.ledger != nil { 
        log.Printf("✅ [KanonRegistry] Already has ledger, skipping DI resolution")
        return nil 
    }
    if any, err := dm.Resolve(di.TokenKanonLedger); err == nil {
        if l, ok := any.(ledger.KanonLedger); ok { 
            r.ledger = l
            log.Printf("✅ [KanonRegistry] Successfully resolved ledger from DI")
        } else {
            log.Printf("❌ [KanonRegistry] Failed to cast resolved value to KanonLedger")
        }
    } else {
        log.Printf("❌ [KanonRegistry] Failed to resolve TokenKanonLedger from DI: %v", err)
    }
    r.dm = dm
    log.Printf("🔍 [KanonRegistry] After InitializeWithDI, ledger available: %v", r.ledger != nil)
    return nil
}

func (r *Registry) MethodName() string                  { return "kanon" }
func (r *Registry) SupportedIdentifier() *regexp.Regexp { return r.rx }

func (r *Registry) GetSchema(schemaId string) (registry.Schema, string, error) {
	raw, err := r.ledger.GetSchema(schemaId)
	if err != nil {
		return registry.Schema{}, "", err
	}
	var payload ledger.SchemaPayload
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return registry.Schema{}, "", err
	}
	return registry.Schema{
		AttrNames: payload.Data.AttrNames,
		Name:      payload.Data.Name,
		Version:   payload.Data.Version,
		IssuerId:  payload.Data.IssuerId,
	}, schemaId, nil
}

func (r *Registry) GetCredentialDefinition(credDefId string) (registry.CredentialDefinition, string, error) {
	_, _, raw, err := r.ledger.GetCredentialDefinition(credDefId)
	if err != nil {
		return registry.CredentialDefinition{}, "", err
	}
	var payload ledger.CredentialDefinitionPayload
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return registry.CredentialDefinition{}, "", err
	}
	// Ensure value.primary is the flattened CL public key (not nested under .value)
	val := payload.Data.Value
	if val != nil {
		if primaryRaw, ok := val["primary"].(map[string]interface{}); ok {
			if inner, ok := primaryRaw["value"].(map[string]interface{}); ok {
				val["primary"] = inner
			}
		}
	} else {
		// Ensure non-nil value for TS compatibility (Object.keys on value)
		val = map[string]interface{}{}
	}
	return registry.CredentialDefinition{
		IssuerId: payload.Data.IssuerId,
		SchemaId: payload.Data.SchemaId,
		Tag:      payload.Data.Tag,
		Value:    val,
	}, credDefId, nil
}

// Revocation APIs are stubs in phase 1
func (r *Registry) GetRevocationRegistryDefinition(revRegDefId string) (registry.RevocationRegistryDefinition, string, error) {
	return registry.RevocationRegistryDefinition{}, "", nil
}

func (r *Registry) GetRevocationStatusList(revRegDefId string, timestamp int64) (registry.RevocationStatusList, error) {
	return registry.RevocationStatusList{}, nil
}

// Writes
func (r *Registry) RegisterSchema(opts registry.RegisterSchemaOptions) (registry.RegisterSchemaResult, error) {
	// Build on-chain payload compatible with SchemaPayload
	payload := ledger.SchemaPayload{}
	payload.Data.Name = opts.Schema.Name
	payload.Data.Version = opts.Schema.Version
	payload.Data.AttrNames = opts.Schema.AttrNames
	payload.Data.IssuerId = opts.Schema.IssuerId
	b, err := json.Marshal(payload)
	if err != nil {
		return registry.RegisterSchemaResult{State: "failed", Schema: opts.Schema, Reason: err.Error()}, nil
	}
	schemaId := opts.Schema.Id
	if schemaId == "" {
		// Minimal deterministic id pattern following TS style
		schemaId = "schema:kanon:testnet:" + opts.Schema.Name + ":" + opts.Schema.Version
	}
	if err := r.ledger.RegisterSchema(schemaId, string(b), opts.Schema.IssuerId); err != nil {
		return registry.RegisterSchemaResult{State: "failed", Schema: opts.Schema, Reason: err.Error()}, nil
	}
	return registry.RegisterSchemaResult{State: "finished", Schema: opts.Schema, SchemaId: schemaId}, nil
}

func (r *Registry) RegisterCredentialDefinition(opts registry.RegisterCredentialDefinitionOptions) (registry.RegisterCredentialDefinitionResult, error) {
	startTime := time.Now()
	log.Printf("        🔍 [CredDef] Starting registration for: %s", opts.CredentialDefinition.Id)
	
	// Determine the credential definition ID
	credDefId := opts.CredentialDefinition.Id
	if credDefId == "" {
		credDefId = "creddef:kanon:testnet:example:" + opts.CredentialDefinition.Tag
	}
	
	// Check if credential definition already exists in repository
	if r.dm != nil {
		// Get credential definition repository
		credDefRepoAny, _ := r.dm.Resolve(di.Token{Name: "CredentialDefinitionRepository"})
		if credDefRepo, ok := credDefRepoAny.(*repository.CredentialDefinitionRepository); ok {
			// Check if we already have this credential definition
			ctx := context.Background()
			existingRecord, err := credDefRepo.FindByCredentialDefinitionId(ctx, credDefId)
			if err == nil && existingRecord != nil {
				log.Printf("        🔍 [CredDef] CACHE HIT! Found existing credential definition in repository: %s", credDefId)
				log.Printf("        🔍 [CredDef] Skipping expensive key generation (saved ~4.6s)")
				return registry.RegisterCredentialDefinitionResult{
					State: "finished",
					CredentialDefinition: existingRecord.CredentialDefinition,
					CredentialDefinitionId: credDefId,
				}, nil
			}
			log.Printf("        🔍 [CredDef] Not found in repository, will create new credential definition")
		}
	}
	
	// Build on-chain payload compatible with CredentialDefinitionPayload
	payload := ledger.CredentialDefinitionPayload{}
	payload.Data.IssuerId = opts.CredentialDefinition.IssuerId
	payload.Data.SchemaId = opts.CredentialDefinition.SchemaId
	payload.Data.Tag = opts.CredentialDefinition.Tag

    // Generate a real CL credential definition using anoncreds and store secrets in issuer
    var credDefPublic map[string]interface{}
    if r.dm != nil {
        // Resolve core issuer instance (holds CL secrets)
        resolveStart := time.Now()
        if any, err := r.dm.Resolve(di.TokenAnonCredsCoreIssuer); err == nil {
            log.Printf("        🔍 [CredDef] Resolved issuer: %v", time.Since(resolveStart))
            if issuer, ok := any.(*issuercore.AnoncredsIssuer); ok {
                // Fetch schema JSON from ledger
                fetchStart := time.Now()
                rawSchema, err := r.ledger.GetSchema(opts.CredentialDefinition.SchemaId)
                log.Printf("        🔍 [CredDef] Fetched schema from ledger: %v", time.Since(fetchStart))
                if err == nil && rawSchema != "" {
                    // Extract inner data object for schema JSON
                    var sp ledger.SchemaPayload
                    if jsonErr := json.Unmarshal([]byte(rawSchema), &sp); jsonErr == nil {
                        inner := map[string]interface{}{
                            "name": sp.Data.Name,
                            "version": sp.Data.Version,
                            "attrNames": sp.Data.AttrNames,
                            "issuerId": sp.Data.IssuerId,
                        }
                        innerBytes, _ := json.Marshal(inner)
                        // Build anoncreds schema from JSON
                        schemaFromJSONStart := time.Now()
                        schemaObj, schemaErr := ac.SchemaFromJSON(string(innerBytes))
                        log.Printf("        🔍 [CredDef] Built schema object: %v", time.Since(schemaFromJSONStart))
                        if schemaErr == nil {
                            defer schemaObj.Clear()
                            // Create and store cred def secrets; get public JSON
                            createCredDefStart := time.Now()
                            log.Printf("        🔍 [CredDef] Calling CreateAndStoreCredentialDefinition...")
                            pubJSON, _, cdErr := issuer.CreateAndStoreCredentialDefinition(
                                opts.CredentialDefinition.SchemaId,
                                schemaObj,
                                opts.CredentialDefinition.IssuerId,
                                opts.CredentialDefinition.Tag,
                                opts.CredentialDefinition.Id,
                            )
                            log.Printf("        🔍 [CredDef] CreateAndStoreCredentialDefinition took: %v ⚠️", time.Since(createCredDefStart))
                            if cdErr == nil {
                                _ = json.Unmarshal([]byte(pubJSON), &credDefPublic)
                            }
                        }
                    }
                }
            }
        }
    }
    if credDefPublic == nil {
        return registry.RegisterCredentialDefinitionResult{State: "failed", CredentialDefinition: opts.CredentialDefinition, Reason: "failed to generate CL credential definition"}, nil
    }
    payload.Data.Value = credDefPublic
	b, err := json.Marshal(payload)
	if err != nil {
		return registry.RegisterCredentialDefinitionResult{State: "failed", CredentialDefinition: opts.CredentialDefinition, Reason: err.Error()}, nil
	}
	// credDefId already defined at the beginning of the function
	ledgerStart := time.Now()
	if err := r.ledger.RegisterCredentialDefinition(credDefId, opts.CredentialDefinition.SchemaId, opts.CredentialDefinition.IssuerId, string(b)); err != nil {
		return registry.RegisterCredentialDefinitionResult{State: "failed", CredentialDefinition: opts.CredentialDefinition, Reason: err.Error()}, nil
	}
	log.Printf("        🔍 [CredDef] Ledger registration: %v", time.Since(ledgerStart))
	
	// Store credential definition in repository for future reuse
	if r.dm != nil {
		storeStart := time.Now()
		// Store credential definition record
		credDefRepoAny, _ := r.dm.Resolve(di.Token{Name: "CredentialDefinitionRepository"})
		if credDefRepo, ok := credDefRepoAny.(*repository.CredentialDefinitionRepository); ok {
			ctx := context.Background()
			credDefRecord := repository.NewCredentialDefinitionRecord(
				credDefId,
				opts.CredentialDefinition,
				"kanon", // method name
			)
			if err := credDefRepo.Save(ctx, credDefRecord); err != nil {
				log.Printf("        ⚠️  [CredDef] Failed to save credential definition to repository: %v", err)
			} else {
				log.Printf("        🔍 [CredDef] Saved credential definition to repository for reuse")
			}
		}
		
		// Note: The private keys and key correctness proof are already stored in the issuer's memory
		// We could also persist them to repositories if needed for cross-session persistence
		log.Printf("        🔍 [CredDef] Repository storage: %v", time.Since(storeStart))
	}
	
	log.Printf("        🔍 [CredDef] Total registration time: %v", time.Since(startTime))
	return registry.RegisterCredentialDefinitionResult{State: "finished", CredentialDefinition: opts.CredentialDefinition, CredentialDefinitionId: credDefId}, nil
}

func (r *Registry) RegisterRevocationRegistryDefinition(opts registry.RegisterRevocationRegistryDefinitionOptions) (registry.RegisterRevocationRegistryDefinitionResult, error) {
	return registry.RegisterRevocationRegistryDefinitionResult{State: "failed", RevocationRegistryDefinition: opts.RevocationRegistryDefinition, Reason: "not implemented"}, nil
}
func (r *Registry) RegisterRevocationStatusList(opts registry.RegisterRevocationStatusListOptions) (registry.RegisterRevocationStatusListResult, error) {
	return registry.RegisterRevocationStatusListResult{State: "failed", RevocationStatusList: opts.RevocationStatusList, Reason: "not implemented"}, nil
}
