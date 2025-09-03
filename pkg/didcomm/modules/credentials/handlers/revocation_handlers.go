package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/ajna-inc/essi/pkg/core/di"
	"github.com/ajna-inc/essi/pkg/didcomm/messages"
	"github.com/ajna-inc/essi/pkg/didcomm/models"
	credsvc "github.com/ajna-inc/essi/pkg/didcomm/modules/credentials/services"
	"github.com/ajna-inc/essi/pkg/didcomm/transport"
)

// V2RevocationNotification represents a v2 revocation notification message
type V2RevocationNotification struct {
	*messages.BaseMessage
	Comment          string `json:"comment,omitempty"`
	RevocationFormat string `json:"revocation_format"`
	CredentialId     string `json:"credential_id"`
}

// V2RevocationNotificationType is the message type constant
const V2RevocationNotificationType = "https://didcomm.org/revocation_notification/2.0/revoke"

// V2RevocationNotificationHandlerFunc processes revocation notifications and tags the related credential record
func V2RevocationNotificationHandlerFunc(ctx *transport.InboundMessageContext) (*models.OutboundMessageContext, error) {
	var msg V2RevocationNotification
	if err := json.Unmarshal(ctx.Raw, &msg); err != nil {
		return nil, fmt.Errorf("failed to parse v2 revocation notification: %w", err)
	}
	// Only anoncreds supported for now
	if msg.RevocationFormat != "anoncreds" {
		log.Printf("⚠️ Unsupported revocation format: %s", msg.RevocationFormat)
		return nil, nil
	}
	// Expected credentialId format: "<revRegId>::<credRevId>"
	parts := strings.Split(msg.CredentialId, "::")
	if len(parts) == 2 {
		revRegId := parts[0]
		credRevId := parts[1]
		// Find credential record(s) matching tags
		// We tag records with anonCredsRevocationRegistryId and anonCredsCredentialRevocationId
		if ctx != nil && ctx.TypedDI != nil {
			if dep, err := ctx.TypedDI.Resolve(di.TokenCredentialsService); err == nil {
				if svc, ok := dep.(*credsvc.CredentialService); ok && svc != nil {
					// naive scan for now
					if all, err := svc.GetAllRecords(); err == nil {
						for _, r := range all {
							if r != nil && r.Tags != nil && r.Tags["anonCredsRevocationRegistryId"] == revRegId && r.Tags["anonCredsCredentialRevocationId"] == credRevId {
								r.SetTag("revoked", "true")
								_ = svc.UpdateRecord(r)
								log.Printf("🔔 Marked credential record %s as revoked", r.ID)
							}
						}
					}
				}
			}
		}
	}
	// No response required
	return nil, nil
}