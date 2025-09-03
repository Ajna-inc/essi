package services

import (
	"encoding/json"
	"log"
	"fmt"
	"github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/core/di"
	coreevents "github.com/ajna-inc/essi/pkg/core/events"
	"github.com/ajna-inc/essi/pkg/core/common"
	regsvc "github.com/ajna-inc/essi/pkg/anoncreds/registry"
	"github.com/ajna-inc/essi/pkg/didcomm/messages"
	crederrors "github.com/ajna-inc/essi/pkg/didcomm/modules/credentials/errors"
	anonfmt "github.com/ajna-inc/essi/pkg/didcomm/modules/credentials/formats/anoncreds"
	credmsgs "github.com/ajna-inc/essi/pkg/didcomm/modules/credentials/messages"
	credrecs "github.com/ajna-inc/essi/pkg/didcomm/modules/credentials/records"
	credutils "github.com/ajna-inc/essi/pkg/didcomm/modules/credentials/utils"
	protocols "github.com/ajna-inc/essi/pkg/didcomm/modules/credentials/protocols"
)

type CredentialService struct {
	context *context.AgentContext
	typedDI di.DependencyManager
	repo    credrecs.Repository
	holder  interface {
		EnsureLinkSecret() (string, error)
		CreateCredentialRequest(map[string]interface{}) (map[string]interface{}, map[string]interface{}, error)
		ProcessIssuedCredential(map[string]interface{}, map[string]interface{}) error
	}
	issuer interface {
		CreateCredentialOffer(credentialDefinitionId string) (map[string]interface{}, error)
		CreateCredential(offer map[string]interface{}, request map[string]interface{}, values map[string]map[string]string) (map[string]interface{}, string, error)
	}
}

func NewCredentialService(ctx *context.AgentContext, typed di.DependencyManager, repo credrecs.Repository) *CredentialService {
	cs := &CredentialService{context: ctx, typedDI: typed, repo: repo}
	if typed != nil {
		if any, err := typed.Resolve(di.TokenAnonCredsCoreIssuer); err == nil {
			if i, ok := any.(interface{ CreateCredentialOffer(string) (map[string]interface{}, error); CreateCredential(map[string]interface{}, map[string]interface{}, map[string]map[string]string) (map[string]interface{}, string, error) }); ok {
				cs.issuer = i
			}
		}
		if any, err := typed.Resolve(di.TokenAnonCredsHolderService); err == nil {
			if h, ok := any.(interface{ EnsureLinkSecret() (string, error); CreateCredentialRequest(map[string]interface{}) (map[string]interface{}, map[string]interface{}, error); ProcessIssuedCredential(map[string]interface{}, map[string]interface{}) error }); ok {
				cs.holder = h
			}
		}
	}
	return cs
}

// SetAnoncredsHolder injects the anoncreds holder implementation
func (cs *CredentialService) SetAnoncredsHolder(h interface {
	EnsureLinkSecret() (string, error)
	CreateCredentialRequest(map[string]interface{}) (map[string]interface{}, map[string]interface{}, error)
	ProcessIssuedCredential(map[string]interface{}, map[string]interface{}) error
}) {
	cs.holder = h
}

// SetAnoncredsIssuer injects the anoncreds issuer implementation
func (cs *CredentialService) SetAnoncredsIssuer(i interface {
	CreateCredentialOffer(string) (map[string]interface{}, error)
	CreateCredential(map[string]interface{}, map[string]interface{}, map[string]map[string]string) (map[string]interface{}, string, error)
}) {
	cs.issuer = i
}

func (cs *CredentialService) emit(event string, data interface{}) {
	if cs.typedDI != nil {
		if any, err := cs.typedDI.Resolve(di.TokenEventBusService); err == nil {
			if bus, ok := any.(coreevents.Bus); ok {
				bus.Publish(event, data)
			}
		}
	}
}

// GetContext returns the agent context
func (cs *CredentialService) GetContext() *context.AgentContext { return cs.context }
// FindRecordByThreadId retrieves a credential record by thread id
func (cs *CredentialService) FindRecordByThreadId(threadId string) (*credrecs.CredentialRecord, error) {
    if cs.repo == nil {
        return nil, fmt.Errorf("credential repository not available")
    }
    return cs.repo.FindByThreadId(cs.context, threadId)
}


// GetHolder returns the anoncreds holder adapter if set
func (cs *CredentialService) GetHolder() interface {
	EnsureLinkSecret() (string, error)
	CreateCredentialRequest(map[string]interface{}) (map[string]interface{}, map[string]interface{}, error)
	ProcessIssuedCredential(map[string]interface{}, map[string]interface{}) error
} {
	return cs.holder
}

// GetAllRecords retrieves all credential records
func (cs *CredentialService) GetAllRecords() ([]*credrecs.CredentialRecord, error) {
	if cs.repo == nil {
		return nil, fmt.Errorf("credential repository not available")
	}
	return cs.repo.GetAll(cs.context)
}

// UpdateRecord updates a credential record
func (cs *CredentialService) UpdateRecord(record *credrecs.CredentialRecord) error {
	if cs.repo == nil {
		return fmt.Errorf("credential repository not available")
	}
	return cs.repo.Update(cs.context, record)
}

// Placeholder operations for request/issue; add storage and validation later
func (cs *CredentialService) AcceptOffer(connectionId string) error {
	// For now, just emit
	cs.emit("credentials.acceptOffer", map[string]string{"connectionId": connectionId})
	return nil
}

func (cs *CredentialService) ProcessIssuedCredential(connectionId string) error {
	cs.emit("credentials.received", map[string]string{"connectionId": connectionId})
	return nil
}

// Holder flow: on offer, create record and auto-build request
func (cs *CredentialService) ProcessOffer(thid string, connectionId string, offer *credmsgs.OfferCredentialV2) (*credmsgs.RequestCredentialV2, *credrecs.CredentialRecord, error) {
	rec := credrecs.NewCredentialRecord(common.GenerateUUID())
	rec.ConnectionId = connectionId
	rec.ThreadId = thid
	rec.Role = "holder"
	rec.State = credrecs.StateOfferReceived
	if offer != nil && len(offer.Formats) > 0 { rec.Formats = make([]string, 0, len(offer.Formats)); for _, f := range offer.Formats { rec.Formats = append(rec.Formats, f.Format) } }
	if err := cs.repo.Save(cs.context, rec); err != nil { return nil, nil, err }
	cs.emit("credentials.offerReceived", map[string]string{"recordId": rec.ID, "connectionId": connectionId})

	var req *credmsgs.RequestCredentialV2
	var built bool

	// Try registered protocols via typed DI
	if cs.typedDI != nil {
		if any, err := cs.typedDI.Resolve(di.TokenCredentialProtocols); err == nil {
			switch v := any.(type) {
			case []protocols.CredentialProtocol:
				for _, p := range v { if p == nil { continue }
					if req2, handled, err := p.TryBuildRequestFromOffer(cs.typedDI, thid, connectionId, offer, rec); err == nil && handled { req = req2; built = true; break }
				}
			case []interface{}:
				for _, it := range v { if p, ok := it.(protocols.CredentialProtocol); ok && p != nil {
					if req2, handled, err := p.TryBuildRequestFromOffer(cs.typedDI, thid, connectionId, offer, rec); err == nil && handled { req = req2; built = true; break }
				} }
			}
		}
	}
	if built { return req, rec, nil }

	return nil, rec, crederrors.NewProblemReportError("no credential protocol handled offer", crederrors.InvalidCredentialOffer)
}

// Holder flow: on credential received, update and build ack
func (cs *CredentialService) ProcessIssue(thid string, connectionId string, cred *credmsgs.IssueCredentialV2Credential) (*credmsgs.Ack, error) {
	rec, err := cs.repo.FindByThreadId(cs.context, thid)
	if err != nil {
		// create record if missing to keep flow going
		rec = credrecs.NewCredentialRecord(common.GenerateUUID())
		rec.ConnectionId = connectionId
		rec.ThreadId = thid
		rec.Role = "holder"
		rec.State = credrecs.StateCredentialReceived
		_ = cs.repo.Save(cs.context, rec)
	} else {
		rec.State = credrecs.StateCredentialReceived
		_ = cs.repo.Update(cs.context, rec)
	}
	
	// If anoncreds payload exists and holder is available, process credential
	if cs.holder != nil {
		var credPayload map[string]interface{}
		for i, f := range cred.Formats {
			if f.Format == anonfmt.FormatCredential && i < len(cred.CredentialsAttach) {
				att := cred.CredentialsAttach[i]
				if att.Data != nil && att.Data.Json != nil {
					credPayload = att.Data.Json.(map[string]interface{})
				}
				break
			}
		}
		
		if credPayload != nil {
			// CRITICAL VALIDATION: Verify credential values match what we expected
			if rec.PreviewAttributes != nil {
				// Extract credential values from the payload
				credValues, ok := credPayload["values"].(map[string]interface{})
				if ok {
					expectedValues := credutils.ConvertAttributesToCredentialValues(rec.PreviewAttributes)
					
					// Assert values match (this is critical for security)
					if err := credutils.AssertCredentialValuesMatch(credValues, expectedValues); err != nil {
						log.Printf("❌ Credential value validation failed: %v", err)
						return nil, crederrors.NewProblemReportError(
							err.Error(),
							crederrors.ValueMismatch,
						).WithDetail("threadId", thid)
					}
					log.Printf("✅ Credential values validated successfully")
				}
			}
			
			var reqMeta map[string]interface{}
			if rec.RequestMetadata != nil {
				reqMeta = rec.RequestMetadata
			}
			
			if err := cs.holder.ProcessIssuedCredential(credPayload, reqMeta); err != nil {
				log.Printf("Failed to process issued credential: %v", err)
				return nil, err
			}

			// Store revocation metadata/tags if present (parity with TS)
			if revRegId, ok := credPayload["rev_reg_id"].(string); ok && revRegId != "" {
				rec.RevocationRegistryId = revRegId
				rec.SetTag("anonCredsRevocationRegistryId", revRegId)
			}
			if credRevId, ok := credPayload["cred_rev_id"].(string); ok && credRevId != "" {
				rec.CredentialRevocationId = credRevId
				rec.SetTag("anonCredsCredentialRevocationId", credRevId)
			}
			_ = cs.repo.Update(cs.context, rec)
		}
	}
	
	rec.State = credrecs.StateDone
	_ = cs.repo.Update(cs.context, rec)
	
	cs.emit("credentials.issuedReceived", map[string]string{"recordId": rec.ID, "connectionId": connectionId})
	cs.emit("credentials.stateChanged", map[string]string{"recordId": rec.ID, "state": string(credrecs.StateDone), "connectionId": connectionId})
	
	ack := credmsgs.NewAck()
	ack.SetThreadId(thid)
	return ack, nil
}

// Issuer flow: create an offer for a given cred def and preview attributes
func (cs *CredentialService) CreateOffer(thid string, connectionId string, credentialDefinitionId string, previewAttributes map[string]string) (*credmsgs.OfferCredentialV2, *credrecs.CredentialRecord, error) {
	rec := credrecs.NewCredentialRecord(common.GenerateUUID())
	rec.ConnectionId = connectionId
	rec.ThreadId = thid
	rec.Role = "issuer"
	rec.State = credrecs.StateOfferSent
	if err := cs.repo.Save(cs.context, rec); err != nil {
		return nil, nil, err
	}

	// Build anoncreds offer via issuer if present
	offer := credmsgs.NewOfferCredentialV2()
	offer.SetThreadId(thid)
	
	if previewAttributes != nil && len(previewAttributes) > 0 {
		preview := &credmsgs.CredentialPreview{
			Type:       "https://didcomm.org/issue-credential/2.0/credential-preview",
			Attributes: []credmsgs.CredentialPreviewAttribute{},
		}
		for name, value := range previewAttributes {
			preview.Attributes = append(preview.Attributes, credmsgs.CredentialPreviewAttribute{
				Name:  name,
				Value: value,
			})
		}
		offer.CredentialPreview = preview
		log.Printf("✅ Added credential preview with %d attributes", len(preview.Attributes))
		for _, attr := range preview.Attributes {
			log.Printf("  - %s: %s", attr.Name, attr.Value)
		}
	} else {
		log.Printf("⚠️ No preview attributes provided")
	}
	
	// Persist preview attributes on record for later issuing
	rec.PreviewAttributes = previewAttributes
	_ = cs.repo.Update(cs.context, rec)
	// Always attach a format/attachment so the TS agent can validate the message
	payload := map[string]interface{}{"cred_def_id": credentialDefinitionId}
	if cs.issuer != nil {
		if p, err := cs.issuer.CreateCredentialOffer(credentialDefinitionId); err == nil && p != nil {
			payload = p
		}
	}
	// Store offer payload in record for later use when issuing credential
	rec.OfferPayload = payload
	log.Printf("🔷 About to update record with OfferPayload (len=%d)", len(payload))
	if err := cs.repo.Update(cs.context, rec); err != nil {
		log.Printf("Error updating record with offer payload: %v", err)
	} else {
		log.Printf("✅ Stored offer payload in record ID=%s, ThreadId=%s", rec.ID, rec.ThreadId)
		if verifyRec, err := cs.repo.FindByThreadId(cs.context, rec.ThreadId); err == nil {
			log.Printf("✅ Verified record found by ThreadId=%s, has OfferPayload=%v", rec.ThreadId, verifyRec.OfferPayload != nil)
			if verifyRec.OfferPayload != nil {
				if payload, err := json.Marshal(verifyRec.OfferPayload); err == nil && len(payload) > 100 {
					log.Printf("   OfferPayload content (first 100 chars): %s...", string(payload[:100]))
				}
			}
		} else {
			log.Printf("❌ Could not verify record by ThreadId=%s: %v", rec.ThreadId, err)
		}
	}
	// Enrich with schema/cred def data if available via typed anoncreds registry
	var resolvedSchemaId string
	var resolvedSchema map[string]interface{}
	if cs.typedDI != nil {
		if any, err := cs.typedDI.Resolve(di.TokenAnonCredsRegistryService); err == nil {
			if router, ok := any.(*regsvc.Service); ok && router != nil {
				if cd, sid, err := router.GetCredentialDefinition(credentialDefinitionId); err == nil {
					resolvedSchemaId = cd.SchemaId
					if sid != "" { payload["schema_id"] = cd.SchemaId }
					if schema, _, err := router.GetSchema(cd.SchemaId); err == nil {
						b, _ := json.Marshal(schema)
						_ = json.Unmarshal(b, &resolvedSchema)
					}
				}
			}
		}
	}
	
	// CRITICAL VALIDATION: Validate preview attributes match schema
	if resolvedSchema != nil && previewAttributes != nil {
		if err := credutils.AssertAttributesMatchMap(resolvedSchema, previewAttributes); err != nil {
			log.Printf("❌ Schema attribute validation failed: %v", err)
			return nil, nil, crederrors.NewProblemReportError(
				err.Error(),
				crederrors.InvalidAttribute,
			).WithDetail("credentialDefinitionId", credentialDefinitionId)
		}
		log.Printf("✅ Preview attributes validated against schema")
	}
	// Ensure required anoncreds offer identifiers are present
	if _, ok := payload["cred_def_id"]; !ok {
		payload["cred_def_id"] = credentialDefinitionId
	} else if s, ok := payload["cred_def_id"].(string); !ok || s == "" {
		payload["cred_def_id"] = credentialDefinitionId
	}
	if _, ok := payload["schema_id"]; !ok && resolvedSchemaId != "" {
		payload["schema_id"] = resolvedSchemaId
	}
	if _, ok := payload["nonce"]; !ok {
		payload["nonce"] = "1234567890"
	}
	// Note: Credo-TS expects flat strings, not wrapped values
	// The xr_cap transformation from array to object is already handled in CreateOfferFromParts
	if b, err := json.Marshal(payload); err == nil {
		log.Printf("anoncreds offer payload: %s", string(b))
	}
	anonfmt.AddOfferFormat(offer, "offer-0", payload)
	
	if offerJSON, err := offer.ToJSON(); err == nil {
		log.Printf("📤 Complete offer message being sent: %s", string(offerJSON))
	}
	
	cs.emit("credentials.offerSent", map[string]string{"recordId": rec.ID, "connectionId": connectionId})
	return offer, rec, nil
}

// Issuer flow: process request and issue credential
func (cs *CredentialService) ProcessRequest(thid string, connectionId string, req *credmsgs.RequestCredentialV2) (*credmsgs.IssueCredentialV2Credential, error) {
	log.Printf("ProcessRequest called for thread %s, connection %s", thid, connectionId)
	if allRecs, err := cs.repo.GetAll(cs.context); err == nil { log.Printf("📋 All credential records in repository:"); for _, r := range allRecs { log.Printf("  - ID=%s, ThreadId=%s, State=%s, HasOfferPayload=%v", r.ID, r.ThreadId, r.State, r.OfferPayload != nil) } }
	rec, err := cs.repo.FindByThreadId(cs.context, thid); if err != nil { log.Printf("Failed to find record for thread %s: %v", thid, err); return nil, err }
	rec.State = credrecs.StateRequestReceived; _ = cs.repo.Update(cs.context, rec)

	// Try registered protocols via typed DI
	if cs.typedDI != nil {
		if any, err := cs.typedDI.Resolve(di.TokenCredentialProtocols); err == nil {
			switch v := any.(type) {
			case []protocols.CredentialProtocol:
				for _, p := range v { if p == nil { continue }
					if msg, handled, err := p.TryBuildIssueFromRequest(cs.typedDI, thid, connectionId, req, rec); err == nil && handled { return msg, nil }
				}
			case []interface{}:
				for _, it := range v { if p, ok := it.(protocols.CredentialProtocol); ok && p != nil {
					if msg, handled, err := p.TryBuildIssueFromRequest(cs.typedDI, thid, connectionId, req, rec); err == nil && handled { return msg, nil }
				} }
			}
		}
	}

	return nil, crederrors.NewProblemReportError("no credential protocol handled request", crederrors.InvalidCredentialRequest)
}

// MarkRequestSent sets record to request-sent
func (cs *CredentialService) MarkRequestSent(thid string) error {
	rec, err := cs.repo.FindByThreadId(cs.context, thid)
	if err != nil {
		return err
	}
	rec.State = credrecs.StateRequestSent
	if err := cs.repo.Update(cs.context, rec); err != nil {
		return err
	}
	cs.emit("credentials.stateChanged", map[string]string{"recordId": rec.ID, "state": string(credrecs.StateRequestSent), "connectionId": rec.ConnectionId})
	return nil
}

// MarkCredentialIssued sets record to credential-issued (after sending credential)
func (cs *CredentialService) MarkCredentialIssued(thid string) error {
	rec, err := cs.repo.FindByThreadId(cs.context, thid)
	if err != nil {
		return err
	}
	rec.State = credrecs.StateCredentialIssued
	if err := cs.repo.Update(cs.context, rec); err != nil {
		return err
	}
	cs.emit("credentials.stateChanged", map[string]string{"recordId": rec.ID, "state": string(credrecs.StateCredentialIssued), "connectionId": rec.ConnectionId})
	return nil
}

// MarkDone sets record to done (after ack)
func (cs *CredentialService) MarkDone(thid string) error {
	rec, err := cs.repo.FindByThreadId(cs.context, thid)
	if err != nil {
		return err
	}
	rec.State = credrecs.StateDone
	if err := cs.repo.Update(cs.context, rec); err != nil {
		return err
	}
	cs.emit("credentials.stateChanged", map[string]string{
		"recordId": rec.ID, 
		"state": string(credrecs.StateDone),
		"connectionId": rec.ConnectionId,
	})
	return nil
}

// CreateProposal creates a credential proposal (holder-initiated flow)
func (cs *CredentialService) CreateProposal(
	thid string,
	connectionId string,
	credentialPreview *credmsgs.CredentialPreview,
	comment string,
	goal string,
	goalCode string,
	autoAccept credrecs.AutoAcceptCredential,
) (*credmsgs.ProposeCredentialV2, *credrecs.CredentialRecord, error) {
	rec := credrecs.NewCredentialRecord(common.GenerateUUID())
	rec.ConnectionId = connectionId
	rec.ThreadId = thid
	rec.Role = "holder"
	rec.State = credrecs.StateProposalSent
	rec.AutoAcceptCredential = autoAccept
	
	// Store preview attributes if provided
	if credentialPreview != nil && len(credentialPreview.Attributes) > 0 {
		rec.PreviewAttributes = make(map[string]string)
		for _, attr := range credentialPreview.Attributes {
			rec.PreviewAttributes[attr.Name] = attr.Value
		}
	}
	
	if err := cs.repo.Save(cs.context, rec); err != nil {
		return nil, nil, err
	}
	
	// Build proposal message
	proposal := credmsgs.NewProposeCredentialV2()
	proposal.SetThreadId(thid)
	proposal.Comment = comment
	proposal.Goal = goal
	proposal.GoalCode = goalCode
	proposal.CredentialPreview = credentialPreview
	
	// Add AnonCreds format proposal
	// For now, just indicate we support AnonCreds
	proposal.Formats = []credmsgs.FormatEntry{
		{AttachID: "proposal-0", Format: anonfmt.FormatProposal},
	}
	proposal.ProposalsAttach = []messages.AttachmentDecorator{
		{
			Id: "proposal-0",
			Data: &messages.AttachmentData{
				Json: map[string]interface{}{
					"@type": "anoncreds/credential-filter@v1.0",
				},
			},
		},
	}
	
	cs.emit("credentials.proposalSent", map[string]string{"recordId": rec.ID, "connectionId": connectionId})
	return proposal, rec, nil
}

// ProcessProposal processes a received credential proposal (issuer side)
func (cs *CredentialService) ProcessProposal(
	thid string,
	connectionId string,
	proposal *credmsgs.ProposeCredentialV2,
) (*credrecs.CredentialRecord, error) {
	rec := credrecs.NewCredentialRecord(common.GenerateUUID())
	rec.ConnectionId = connectionId
	rec.ThreadId = thid
	rec.Role = "issuer"
	rec.State = credrecs.StateProposalReceived
	
	// Store preview attributes if provided
	if proposal.CredentialPreview != nil && len(proposal.CredentialPreview.Attributes) > 0 {
		rec.PreviewAttributes = make(map[string]string)
		for _, attr := range proposal.CredentialPreview.Attributes {
			rec.PreviewAttributes[attr.Name] = attr.Value
		}
	}
	
	// Store formats from proposal
	if len(proposal.Formats) > 0 {
		rec.Formats = make([]string, 0, len(proposal.Formats))
		for _, f := range proposal.Formats {
			rec.Formats = append(rec.Formats, f.Format)
		}
	}
	
	if err := cs.repo.Save(cs.context, rec); err != nil {
		return nil, err
	}
	
	cs.emit("credentials.proposalReceived", map[string]string{"recordId": rec.ID, "connectionId": connectionId})
	return rec, nil
}

// DeclineOffer declines a credential offer
func (cs *CredentialService) DeclineOffer(thid string, reason string) (*credmsgs.CredentialProblemReportV2, error) {
	rec, err := cs.repo.FindByThreadId(cs.context, thid)
	if err != nil {
		return nil, err
	}
	
	rec.State = credrecs.StateDeclined
	if err := cs.repo.Update(cs.context, rec); err != nil {
		return nil, err
	}
	
	problemReport := credmsgs.NewCredentialProblemReportV2(
		credmsgs.ProblemCodeOfferNotAccepted,
		reason,
	)
	problemReport.SetThreadId(thid)
	
	cs.emit("credentials.declined", map[string]string{"recordId": rec.ID, "reason": reason})
	return problemReport, nil
}

// DeclineRequest declines a credential request  
func (cs *CredentialService) DeclineRequest(thid string, reason string) (*credmsgs.CredentialProblemReportV2, error) {
	rec, err := cs.repo.FindByThreadId(cs.context, thid)
	if err != nil {
		return nil, err
	}
	
	rec.State = credrecs.StateDeclined
	if err := cs.repo.Update(cs.context, rec); err != nil {
		return nil, err
	}
	
	// Create problem report
	problemReport := credmsgs.NewCredentialProblemReportV2(
		credmsgs.ProblemCodeRequestNotAccepted,
		reason,
	)
	problemReport.SetThreadId(thid)
	
	cs.emit("credentials.declined", map[string]string{"recordId": rec.ID, "reason": reason})
	return problemReport, nil
}

// AbandonCredentialExchange abandons the credential exchange
func (cs *CredentialService) AbandonCredentialExchange(thid string, reason string) (*credmsgs.CredentialProblemReportV2, error) {
	rec, err := cs.repo.FindByThreadId(cs.context, thid)
	if err != nil {
		return nil, err
	}
	
	rec.State = credrecs.StateAbandoned
	if err := cs.repo.Update(cs.context, rec); err != nil {
		return nil, err
	}
	
	// Create problem report
	problemReport := credmsgs.NewCredentialProblemReportV2(
		credmsgs.ProblemCodeAbandoned,
		reason,
	)
	problemReport.SetThreadId(thid)
	
	cs.emit("credentials.abandoned", map[string]string{"recordId": rec.ID, "reason": reason})
	return problemReport, nil
}

// ProcessProblemReport processes a received problem report
func (cs *CredentialService) ProcessProblemReport(
	thid string,
	problemReport *credmsgs.CredentialProblemReportV2,
) error {
	rec, err := cs.repo.FindByThreadId(cs.context, thid)
	if err != nil {
		// If no record found, we can't process the problem report
		log.Printf("No credential record found for thread %s", thid)
		return nil
	}
	
	// Update state based on problem code
	switch problemReport.Code {
	case credmsgs.ProblemCodeAbandoned:
		rec.State = credrecs.StateAbandoned
	case credmsgs.ProblemCodeRejected,
		credmsgs.ProblemCodeOfferNotAccepted,
		credmsgs.ProblemCodeRequestNotAccepted:
		rec.State = credrecs.StateDeclined
	default:
		// For other errors, keep the current state but log the problem
		log.Printf("Problem report received for thread %s: %s - %s", 
			thid, problemReport.Code, problemReport.Comment)
	}
	
	// Store problem report details in tags for querying
	rec.SetTag("problemCode", problemReport.Code)
	if problemReport.Comment != "" {
		rec.SetTag("problemComment", problemReport.Comment)
	}
	
	if err := cs.repo.Update(cs.context, rec); err != nil {
		return err
	}
	
	cs.emit("credentials.problemReportReceived", map[string]interface{}{
		"recordId": rec.ID,
		"code":     problemReport.Code,
		"comment":  problemReport.Comment,
		"state":    string(rec.State),
	})
	
	return nil
}

// ShouldAutoAccept determines if a credential should be auto-accepted
func (cs *CredentialService) ShouldAutoAccept(rec *credrecs.CredentialRecord) bool {
	// Check record-specific setting first
	switch rec.AutoAcceptCredential {
	case credrecs.AutoAcceptAlways:
		return true
	case credrecs.AutoAcceptNever:
		return false
	case credrecs.AutoAcceptContentApproved:
		// Check if content is approved (implement your logic here)
		return cs.isContentApproved(rec)
	default:
		// Fall back to global config via typed DI
		if cs.typedDI != nil {
			if any, err := cs.typedDI.Resolve(di.TokenAutoAcceptCredentials); err == nil {
				// Check for string value first (new format)
				if v, ok := any.(string); ok {
					switch v {
					case "always":
						return true
					case "contentApproved":
						return cs.isContentApproved(rec)
					case "never":
						return false
					}
				}
				// Legacy: check for boolean value
				if v, ok := any.(bool); ok {
					return v
				}
			}
		}
		// Check agent context config
		if cs.context != nil && cs.context.Config != nil {
			switch cs.context.Config.AutoAcceptCredentials {
			case "always":
				return true
			case "contentApproved":
				return cs.isContentApproved(rec)
			case "never":
				return false
			}
		}
		// Default to false
		return false
	}
}

// isContentApproved checks if credential content is approved for auto-accept
func (cs *CredentialService) isContentApproved(rec *credrecs.CredentialRecord) bool {
	// Implement your content approval logic here
	// For example, check if attributes match expected values
	// or if credential definition is from trusted issuer
	
	// For now, return false (manual approval required)
	return false
}

