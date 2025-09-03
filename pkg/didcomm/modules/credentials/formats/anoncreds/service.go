package anoncreds

import (
	"encoding/json"

	regsvc "github.com/ajna-inc/essi/pkg/anoncreds/registry"
	acsvc "github.com/ajna-inc/essi/pkg/anoncreds/services"
	agentctx "github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/core/di"
	"github.com/ajna-inc/essi/pkg/core/utils"
	credmsgs "github.com/ajna-inc/essi/pkg/didcomm/modules/credentials/messages"
	credrecs "github.com/ajna-inc/essi/pkg/didcomm/modules/credentials/records"
)

// AnonCredsCredentialFormatService adapts the existing anoncreds flow to the generic format service interface.
type AnonCredsCredentialFormatService struct{}

func NewAnonCredsCredentialFormatService() *AnonCredsCredentialFormatService {
	return &AnonCredsCredentialFormatService{}
}

func (s *AnonCredsCredentialFormatService) FormatID() string { return FormatOffer }

func (s *AnonCredsCredentialFormatService) BuildRequestFromOffer(dm di.DependencyManager, threadId string, connectionId string, offer *credmsgs.OfferCredentialV2, rec *credrecs.CredentialRecord) (*credmsgs.RequestCredentialV2, bool, error) {
	// Look for matching anoncreds offer
	var payload map[string]interface{}
	for i, f := range offer.Formats {
		if f.Format == FormatOffer && i < len(offer.OffersAttach) {
			att := offer.OffersAttach[i]
			if att.Data != nil && att.Data.Json != nil {
				if jsonData, ok := att.Data.Json.(map[string]interface{}); ok {
					payload = jsonData
					break
				}
			}
			if att.Data != nil && att.Data.Base64 != "" {
				if b, err := utils.DecodeBase64(att.Data.Base64); err == nil {
					_ = json.Unmarshal(b, &payload)
				}
			}
		}
	}
	if payload == nil {
		return nil, false, nil
	}

	// Preferred path: use typed holder + registry services to build a valid anoncreds request
	var reqPayload, reqMeta map[string]interface{}
	if dm != nil {
		// Resolve agent context
		var ctx *agentctx.AgentContext
		if any, err := dm.Resolve(di.TokenAgentContext); err == nil {
			ctx, _ = any.(*agentctx.AgentContext)
		}
		// Resolve typed holder service
		var holderSvc acsvc.AnonCredsHolderService
		if any, err := dm.Resolve(acsvc.TokenAnonCredsHolderService); err == nil {
			if h, ok := any.(acsvc.AnonCredsHolderService); ok {
				holderSvc = h
			}
		}
		// Resolve registry service
		var registry *regsvc.Service
		if any, err := dm.Resolve(di.TokenRegistryService); err == nil {
			registry, _ = any.(*regsvc.Service)
		}
		// Build request if possible
		if ctx != nil && holderSvc != nil && registry != nil {
			var credDefMap map[string]interface{}
			if credDefId, ok := payload["cred_def_id"].(string); ok && credDefId != "" {
				if cd, _, err := registry.GetCredentialDefinition(credDefId); err == nil {
					credDefMap = map[string]interface{}{"id": credDefId}
					if cd.SchemaId != "" {
						credDefMap["schemaId"] = cd.SchemaId
					}
					if cd.Value != nil {
						credDefMap["value"] = cd.Value
					}
				}
			}
			if res, err := holderSvc.CreateCredentialRequest(ctx, &acsvc.CreateCredentialRequestOptions{
				CredentialOffer:      payload,
				CredentialDefinition: credDefMap,
			}); err == nil && res != nil {
				reqPayload = res.CredentialRequest
				reqMeta = res.CredentialRequestMetadata
			}
		}
	}

	// Fallback: legacy adapter
	if reqPayload == nil {
		var holder interface {
			EnsureLinkSecret() (string, error)
			CreateCredentialRequest(map[string]interface{}) (map[string]interface{}, map[string]interface{}, error)
		}
		if dm != nil {
			if v, err := dm.Resolve(di.TokenAnonCredsHolderService); err == nil {
				if h, ok := v.(interface {
					EnsureLinkSecret() (string, error)
					CreateCredentialRequest(map[string]interface{}) (map[string]interface{}, map[string]interface{}, error)
				}); ok {
					holder = h
				}
			}
		}
		if holder != nil {
			_, _ = holder.EnsureLinkSecret()
			reqPayload, reqMeta, _ = holder.CreateCredentialRequest(payload)
		}
	}

	if reqPayload == nil {
		reqPayload = map[string]interface{}{}
	}
	req := BuildRequestWithAnonCreds(threadId, reqPayload)
	if rec != nil {
		rec.RequestMetadata = reqMeta
	}
	return req, true, nil
}
