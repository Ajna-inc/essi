package v2

import (
	"encoding/json"

	"github.com/ajna-inc/essi/pkg/core/di"
	"github.com/ajna-inc/essi/pkg/core/utils"
	formats "github.com/ajna-inc/essi/pkg/didcomm/modules/credentials/formats"
	anonfmt "github.com/ajna-inc/essi/pkg/didcomm/modules/credentials/formats/anoncreds"
	credmsgs "github.com/ajna-inc/essi/pkg/didcomm/modules/credentials/messages"
	protocols "github.com/ajna-inc/essi/pkg/didcomm/modules/credentials/protocols"
	credrecs "github.com/ajna-inc/essi/pkg/didcomm/modules/credentials/records"
)

// V2CredentialProtocol orchestrates v2 flows by delegating to registered format services
type V2CredentialProtocol struct {
	// explicitly provided format services
	formatServices []formats.CredentialFormatService
}

func NewV2CredentialProtocol(formatServices ...[]formats.CredentialFormatService) *V2CredentialProtocol {
	var fs []formats.CredentialFormatService
	if len(formatServices) > 0 {
		fs = formatServices[0]
	}
	return &V2CredentialProtocol{formatServices: fs}
}

func (p *V2CredentialProtocol) ID() string { return "issue-credential/2.0" }

func (p *V2CredentialProtocol) TryBuildRequestFromOffer(dm di.DependencyManager, threadId string, connectionId string, offer *credmsgs.OfferCredentialV2, rec *credrecs.CredentialRecord) (*credmsgs.RequestCredentialV2, bool, error) {
	for _, s := range p.formatServices {
		if s == nil {
			continue
		}
		if req, handled, err := s.BuildRequestFromOffer(dm, threadId, connectionId, offer, rec); err == nil && handled {
			return req, true, nil
		}
	}
	return nil, false, nil
}

func (p *V2CredentialProtocol) TryBuildIssueFromRequest(dm di.DependencyManager, threadId string, connectionId string, req *credmsgs.RequestCredentialV2, rec *credrecs.CredentialRecord) (*credmsgs.IssueCredentialV2Credential, bool, error) {
	// For anoncreds, resolve issuer via DI and build issued
	if dm == nil || rec == nil || rec.OfferPayload == nil || req == nil {
		return nil, false, nil
	}
	// Locate anoncreds request payload (handle json or base64)
	var requestPayload map[string]interface{}
	for i, f := range req.Formats {
		if f.Format == anonfmt.FormatRequest && i < len(req.RequestsAttach) {
			att := req.RequestsAttach[i]
			if att.Data != nil && att.Data.Json != nil {
				requestPayload = att.Data.Json.(map[string]interface{})
				break
			}
			if att.Data != nil && att.Data.Base64 != "" {
				if b, err := utils.DecodeBase64(att.Data.Base64); err == nil {
					_ = json.Unmarshal(b, &requestPayload)
					if requestPayload != nil {
						break
					}
				}
			}
		}
	}
	// Fallback: scan all attachments regardless of formats order
	if requestPayload == nil {
		for _, att := range req.RequestsAttach {
			if att.Data != nil && att.Data.Json != nil {
				if m, ok := att.Data.Json.(map[string]interface{}); ok {
					requestPayload = m
					break
				}
			}
			if att.Data != nil && att.Data.Base64 != "" {
				if b, err := utils.DecodeBase64(att.Data.Base64); err == nil {
					_ = json.Unmarshal(b, &requestPayload)
					if requestPayload != nil {
						break
					}
				}
			}
		}
	}
	if requestPayload == nil {
		return nil, false, nil
	}
	// Reconstruct attribute values when present on record
	values := map[string]map[string]string{}
	if rec.PreviewAttributes != nil {
		for k, v := range rec.PreviewAttributes {
			values[k] = map[string]string{"raw": v, "encoded": v}
		}
	}
	// Resolve issuer: require core issuer (stores CL secrets)
	var issuer interface {
		CreateCredential(map[string]interface{}, map[string]interface{}, map[string]map[string]string) (map[string]interface{}, string, error)
	}
	if v, err := dm.Resolve(di.TokenAnonCredsCoreIssuer); err == nil {
		if i, ok := v.(interface {
			CreateCredential(map[string]interface{}, map[string]interface{}, map[string]map[string]string) (map[string]interface{}, string, error)
		}); ok {
			issuer = i
		}
	}
	if issuer == nil {
		return nil, false, nil
	}
	issued, _, err := issuer.CreateCredential(rec.OfferPayload, requestPayload, values)
	if err != nil {
		return nil, false, err
	}
	msg := anonfmt.BuildIssuedWithAnonCreds(threadId, issued)
	return msg, true, nil
}

var _ protocols.CredentialProtocol = (*V2CredentialProtocol)(nil)
