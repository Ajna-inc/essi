package services

import (
	"log"
	
	"github.com/ajna-inc/essi/pkg/core/context"
	credmsgs "github.com/ajna-inc/essi/pkg/didcomm/modules/credentials/messages"
	credrecs "github.com/ajna-inc/essi/pkg/didcomm/modules/credentials/records"
	credutils "github.com/ajna-inc/essi/pkg/didcomm/modules/credentials/utils"
	anonfmt "github.com/ajna-inc/essi/pkg/didcomm/modules/credentials/formats/anoncreds"
)

// AutoAcceptCredential defines when to auto-accept credentials
type AutoAcceptCredential string

const (
	AutoAcceptNever       AutoAcceptCredential = "never"
	AutoAcceptAlways      AutoAcceptCredential = "always"
	AutoAcceptContentApproved AutoAcceptCredential = "contentApproved"
)

// CredentialAutoAcceptService handles auto-accept logic for credentials
type CredentialAutoAcceptService struct {
	context *context.AgentContext
	service *CredentialService
}

// NewCredentialAutoAcceptService creates a new auto-accept service
func NewCredentialAutoAcceptService(ctx *context.AgentContext, service *CredentialService) *CredentialAutoAcceptService {
	return &CredentialAutoAcceptService{
		context: ctx,
		service: service,
	}
}

// ShouldAutoRespondToProposal checks if we should auto-respond to a proposal with an offer
func (s *CredentialAutoAcceptService) ShouldAutoRespondToProposal(
	proposalMessage *credmsgs.ProposeCredentialV2,
	offerMessage *credmsgs.OfferCredentialV2,
) bool {
	// Find anoncreds format attachments
	var proposalPayload, offerPayload map[string]interface{}
	
	// Extract proposal payload
	for i, f := range proposalMessage.Formats {
		if f.Format == anonfmt.FormatProposal && i < len(proposalMessage.ProposalsAttach) {
			if att := proposalMessage.ProposalsAttach[i]; att.Data != nil && att.Data.Json != nil {
				proposalPayload = att.Data.Json.(map[string]interface{})
				break
			}
		}
	}
	
	// Extract offer payload
	for i, f := range offerMessage.Formats {
		if f.Format == anonfmt.FormatOffer && i < len(offerMessage.OffersAttach) {
			if att := offerMessage.OffersAttach[i]; att.Data != nil && att.Data.Json != nil {
				offerPayload = att.Data.Json.(map[string]interface{})
				break
			}
		}
	}
	
	if proposalPayload == nil || offerPayload == nil {
		return false
	}
	
	// Check if credential definition IDs match
	proposalCredDefId, _ := proposalPayload["cred_def_id"].(string)
	offerCredDefId, _ := offerPayload["cred_def_id"].(string)
	
	if proposalCredDefId == "" || offerCredDefId == "" {
		return false
	}
	
	match := proposalCredDefId == offerCredDefId
	if match {
		log.Printf("✅ Auto-accept: Proposal and offer credential definitions match: %s", proposalCredDefId)
	} else {
		log.Printf("❌ Auto-accept: Credential definition mismatch - proposal: %s, offer: %s", 
			proposalCredDefId, offerCredDefId)
	}
	
	return match
}

// ShouldAutoRespondToOffer checks if we should auto-respond to an offer with a request
func (s *CredentialAutoAcceptService) ShouldAutoRespondToOffer(
	proposalMessage *credmsgs.ProposeCredentialV2,
	offerMessage *credmsgs.OfferCredentialV2,
) bool {
	// If there was no proposal, check connection/record auto-accept settings
	if proposalMessage == nil {
		// Could check connection record auto-accept settings here
		// For now, return false to require manual acceptance
		return false
	}
	
	// Same logic as proposal - check if cred def IDs match
	return s.ShouldAutoRespondToProposal(proposalMessage, offerMessage)
}

// ShouldAutoRespondToRequest checks if we should auto-respond to a request with a credential
func (s *CredentialAutoAcceptService) ShouldAutoRespondToRequest(
	offerMessage *credmsgs.OfferCredentialV2,
	requestMessage *credmsgs.RequestCredentialV2,
) bool {
	// Find anoncreds format attachments
	var offerPayload, requestPayload map[string]interface{}
	
	// Extract offer payload
	for i, f := range offerMessage.Formats {
		if f.Format == anonfmt.FormatOffer && i < len(offerMessage.OffersAttach) {
			if att := offerMessage.OffersAttach[i]; att.Data != nil && att.Data.Json != nil {
				offerPayload = att.Data.Json.(map[string]interface{})
				break
			}
		}
	}
	
	// Extract request payload
	for i, f := range requestMessage.Formats {
		if f.Format == anonfmt.FormatRequest && i < len(requestMessage.RequestsAttach) {
			if att := requestMessage.RequestsAttach[i]; att.Data != nil && att.Data.Json != nil {
				requestPayload = att.Data.Json.(map[string]interface{})
				break
			}
		}
	}
	
	if offerPayload == nil || requestPayload == nil {
		return false
	}
	
	// Check if credential definition IDs match
	offerCredDefId, _ := offerPayload["cred_def_id"].(string)
	requestCredDefId, _ := requestPayload["cred_def_id"].(string)
	
	if offerCredDefId == "" || requestCredDefId == "" {
		return false
	}
	
	match := offerCredDefId == requestCredDefId
	if match {
		log.Printf("✅ Auto-accept: Offer and request credential definitions match: %s", offerCredDefId)
	} else {
		log.Printf("❌ Auto-accept: Credential definition mismatch - offer: %s, request: %s",
			offerCredDefId, requestCredDefId)
	}
	
	return match
}

// ShouldAutoRespondToCredential checks if we should auto-respond to a credential with an ack
func (s *CredentialAutoAcceptService) ShouldAutoRespondToCredential(
	credentialRecord *credrecs.CredentialRecord,
	requestMessage *credmsgs.RequestCredentialV2,
	credentialMessage *credmsgs.IssueCredentialV2Credential,
) bool {
	// Find anoncreds format attachments
	var requestPayload, credentialPayload map[string]interface{}
	
	// Extract request payload
	for i, f := range requestMessage.Formats {
		if f.Format == anonfmt.FormatRequest && i < len(requestMessage.RequestsAttach) {
			if att := requestMessage.RequestsAttach[i]; att.Data != nil && att.Data.Json != nil {
				requestPayload = att.Data.Json.(map[string]interface{})
				break
			}
		}
	}
	
	// Extract credential payload
	for i, f := range credentialMessage.Formats {
		if f.Format == anonfmt.FormatCredential && i < len(credentialMessage.CredentialsAttach) {
			if att := credentialMessage.CredentialsAttach[i]; att.Data != nil && att.Data.Json != nil {
				credentialPayload = att.Data.Json.(map[string]interface{})
				break
			}
		}
	}
	
	if requestPayload == nil || credentialPayload == nil {
		return false
	}
	
	// Check if credential definition IDs match
	requestCredDefId, _ := requestPayload["cred_def_id"].(string)
	credentialCredDefId, _ := credentialPayload["cred_def_id"].(string)
	
	if requestCredDefId == "" || credentialCredDefId == "" {
		return false
	}
	
	if requestCredDefId != credentialCredDefId {
		log.Printf("❌ Auto-accept: Credential definition mismatch - request: %s, credential: %s",
			requestCredDefId, credentialCredDefId)
		return false
	}
	
	// If we don't have any attributes stored we can't compare
	if credentialRecord.PreviewAttributes == nil {
		log.Printf("⚠️ Auto-accept: No preview attributes to compare")
		return false
	}
	
	// Check if credential values match what we expected
	credValues, ok := credentialPayload["values"].(map[string]interface{})
	if !ok {
		log.Printf("⚠️ Auto-accept: No credential values found")
		return false
	}
	
	expectedValues := credutils.ConvertAttributesToCredentialValues(credentialRecord.PreviewAttributes)
	match := credutils.CheckCredentialValuesMatch(expectedValues, credValues)
	
	if match {
		log.Printf("✅ Auto-accept: Credential values match expected values")
	} else {
		log.Printf("❌ Auto-accept: Credential values don't match expected values")
	}
	
	return match
}

// GetAutoAcceptConfig gets the auto-accept configuration for a credential exchange
func (s *CredentialAutoAcceptService) GetAutoAcceptConfig(
	credentialRecord *credrecs.CredentialRecord,
) AutoAcceptCredential {
	// Check record-level auto-accept setting
	if credentialRecord.AutoAcceptCredential != "" {
		return AutoAcceptCredential(credentialRecord.AutoAcceptCredential)
	}
	
	// Check agent-level configuration
	if s.context.Config != nil && s.context.Config.AutoAcceptCredentials != "" {
		return AutoAcceptCredential(s.context.Config.AutoAcceptCredentials)
	}
	
	// Default to never auto-accept
	return AutoAcceptNever
}

// ShouldAutoAccept determines if a credential exchange step should be auto-accepted
func (s *CredentialAutoAcceptService) ShouldAutoAccept(
	credentialRecord *credrecs.CredentialRecord,
	contentApproved bool,
) bool {
	config := s.GetAutoAcceptConfig(credentialRecord)
	
	switch config {
	case AutoAcceptAlways:
		return true
	case AutoAcceptContentApproved:
		return contentApproved
	case AutoAcceptNever:
		return false
	default:
		return false
	}
}