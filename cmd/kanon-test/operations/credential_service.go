package operations

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/ajna-inc/essi/pkg/anoncreds"
	anonServices "github.com/ajna-inc/essi/pkg/anoncreds/services"
	"github.com/ajna-inc/essi/pkg/core/agent"
	"github.com/ajna-inc/essi/pkg/core/di"
	"github.com/ajna-inc/essi/pkg/core/events"
	"github.com/ajna-inc/essi/pkg/didcomm/messages"
	"github.com/ajna-inc/essi/pkg/didcomm/models"
	connServices "github.com/ajna-inc/essi/pkg/didcomm/modules/connections/services"
	credMessages "github.com/ajna-inc/essi/pkg/didcomm/modules/credentials/messages"
	credrecords "github.com/ajna-inc/essi/pkg/didcomm/modules/credentials/records"
	credServices "github.com/ajna-inc/essi/pkg/didcomm/modules/credentials/services"
	"github.com/ajna-inc/essi/pkg/didcomm/transport"
	"github.com/google/uuid"
)

// CredentialService handles credential operations using AnonCreds
type CredentialService struct {
	agent             *agent.Agent
	anonApi           *anoncreds.AnonCredsApi
	metrics           *Metrics
	credentialService *credServices.CredentialService
	connectionService *connServices.ConnectionService
	messageSender     *transport.MessageSender
}

// NewCredentialService creates a new credential service handler
func NewCredentialService(agent *agent.Agent, anonApi *anoncreds.AnonCredsApi, metrics *Metrics) *CredentialService {
	ops := &CredentialService{agent: agent, anonApi: anonApi, metrics: metrics}
	if agent != nil {
		dm := agent.GetDependencyManager()
		if dm != nil {
			if service, err := dm.Resolve(di.TokenCredentialsService); err == nil {
				if credSvc, ok := service.(*credServices.CredentialService); ok {
					ops.credentialService = credSvc
					log.Printf("✅ Credential service initialized")
				}
			}
			if service, err := dm.Resolve(di.TokenConnectionService); err == nil {
				if connSvc, ok := service.(*connServices.ConnectionService); ok {
					ops.connectionService = connSvc
					log.Printf("✅ Connection service initialized")
				}
			}
			if service, err := dm.Resolve(di.TokenMessageSender); err == nil {
				if sender, ok := service.(*transport.MessageSender); ok {
					ops.messageSender = sender
					log.Printf("✅ Message sender initialized")
				}
			}
		}
	}
	if ops.credentialService == nil {
		log.Printf("⚠️ Warning: Credential service not available - credential operations will fail")
	}
	return ops
}

// OfferCredentialToConnection offers a credential to a connection using proper DIDComm protocol
// This method MUST use the CredentialService to ensure proper state management
func (r *CredentialService) OfferCredentialToConnection(connectionID, credDefID string, attributes map[string]string) error {
	startTime := time.Now()
	defer func() {
		if r.metrics != nil {
			r.metrics.Record("offer_credential_real", time.Since(startTime))
		}
	}()

	// Ensure we have the required services
	if r.credentialService == nil {
		return fmt.Errorf("credential service not available - cannot send credential offer")
	}
	if r.connectionService == nil {
		return fmt.Errorf("connection service not available - cannot send credential offer")
	}
	if r.messageSender == nil {
		return fmt.Errorf("message sender not available - cannot send credential offer")
	}

	log.Printf("📤 Creating credential offer via CredentialService for connection: %s", connectionID)
	log.Printf("   Credential Definition: %s", credDefID)
	log.Printf("   Attributes: %v", attributes)

	// Generate a thread ID for the credential exchange
	threadID := uuid.New().String()

	// Use the CredentialService to create the offer
	// This ensures a CredentialRecord is created and stored with the proper thread ID
	offerMessage, credentialRecord, err := r.credentialService.CreateOffer(
		threadID,
		connectionID,
		credDefID,
		attributes,
	)
	if err != nil {
		return fmt.Errorf("failed to create credential offer via service: %w", err)
	}

	log.Printf("✅ Created credential offer with thread ID: %s", threadID)
	log.Printf("   Credential Record ID: %s", credentialRecord.ID)
	log.Printf("   Record State: %s", credentialRecord.State)

	// Get the connection to send the message
	connection, err := r.connectionService.FindById(connectionID)
	if err != nil {
		return fmt.Errorf("failed to find connection %s: %w", connectionID, err)
	}

	// Send the offer message using the message sender
	outboundCtx := models.NewOutboundMessageContext(offerMessage, models.OutboundMessageContextParams{
		AgentContext:     r.agent.GetContext(),
		Connection:       connection,
		AssociatedRecord: credentialRecord,
	})
	err = r.messageSender.SendMessage(outboundCtx)
	if err != nil {
		// Update the credential record to reflect the error
		credentialRecord.SetTag("error", err.Error())
		_ = r.credentialService.UpdateRecord(credentialRecord)
		return fmt.Errorf("failed to send credential offer: %w", err)
	}

	log.Printf("✅ Credential offer sent successfully to connection %s", connectionID)
	log.Printf("   Thread ID: %s (stored for handling the response)", threadID)
	return nil
}

// DEPRECATED: These helper methods are kept for backward compatibility but should not be used
// All credential operations should go through the CredentialService

// Deprecated: Use CredentialService.CreateOffer instead
func (r *CredentialService) createCredentialPreview(attributes map[string]string) map[string]interface{} {
	log.Printf("⚠️ DEPRECATED: createCredentialPreview should not be called directly")
	var attrs []map[string]interface{}
	for name, value := range attributes {
		attrs = append(attrs, map[string]interface{}{
			"name":      name,
			"value":     value,
			"mime-type": "text/plain",
		})
	}

	return map[string]interface{}{
		"@type":      "https://didcomm.org/issue-credential/2.0/credential-preview",
		"attributes": attrs,
	}
}

// Deprecated: Use CredentialService.CreateOffer instead
func (r *CredentialService) createOfferAttachment(credOffer *anonServices.AnonCredsCredentialOffer) map[string]interface{} {
	log.Printf("⚠️ DEPRECATED: createOfferAttachment should not be called directly")
	// Convert credential offer to JSON
	offerJSON, _ := json.Marshal(credOffer)

	return map[string]interface{}{
		"@id":       "libindy-cred-offer-0",
		"mime-type": "application/json",
		"data": map[string]interface{}{
			"base64": base64.StdEncoding.EncodeToString(offerJSON),
		},
	}
}

// Deprecated: Use CredentialService.CreateOffer instead
func (r *CredentialService) createOfferCredentialMessage(preview, attachment map[string]interface{}) messages.AgentMessage {
	log.Printf("⚠️ DEPRECATED: createOfferCredentialMessage should not be called directly - use CredentialService")
	// Create proper v2 offer credential message
	offerMsg := credMessages.NewOfferCredentialV2()
	offerMsg.SetId(uuid.New().String())

	// Convert preview to proper type
	var attrs []credMessages.CredentialPreviewAttribute
	if previewAttrs, ok := preview["attributes"].([]map[string]interface{}); ok {
		for _, attr := range previewAttrs {
			attrs = append(attrs, credMessages.CredentialPreviewAttribute{
				Name:     attr["name"].(string),
				Value:    attr["value"].(string),
				MimeType: attr["mime-type"].(string),
			})
		}
	}

	offerMsg.CredentialPreview = &credMessages.CredentialPreview{
		Type:       "https://didcomm.org/issue-credential/2.0/credential-preview",
		Attributes: attrs,
	}

	// Add format entry for anoncreds
	offerMsg.Formats = []credMessages.FormatEntry{
		{
			AttachID: attachment["@id"].(string),
			Format:   "anoncreds/credential-offer@v1.0",
		},
	}

	attachmentDecorator := messages.AttachmentDecorator{
		Id:       attachment["@id"].(string),
		MimeType: attachment["mime-type"].(string),
		Data: &messages.AttachmentData{
			Base64: attachment["data"].(map[string]interface{})["base64"].(string),
		},
	}

	offerMsg.OffersAttach = []messages.AttachmentDecorator{attachmentDecorator}

	return offerMsg
}

// IssueCredential issues a credential in response to a credential request
func (r *CredentialService) IssueCredential(credentialRequest map[string]interface{}, credOffer *anonServices.AnonCredsCredentialOffer, attributeValues map[string]string) (*anonServices.CreateCredentialReturn, error) {
	startTime := time.Now()
	defer func() {
		if r.metrics != nil {
			r.metrics.Record("issue_credential", time.Since(startTime))
		}
	}()

	log.Println("📜 Issuing credential...")

	// Convert attribute values to the format expected by CreateCredential
	credValues := make(map[string]map[string]string)
	for name, value := range attributeValues {
		credValues[name] = map[string]string{
			"raw":     value,
			"encoded": r.encodeValue(value),
		}
	}

	// Convert credential offer to map
	offerMap := make(map[string]interface{})
	offerJSON, _ := json.Marshal(credOffer)
	json.Unmarshal(offerJSON, &offerMap)

	credReturn, err := r.anonApi.CreateCredential(&anonServices.CreateCredentialOptions{
		CredentialOffer:   offerMap,
		CredentialRequest: credentialRequest,
		CredentialValues:  credValues,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create credential: %w", err)
	}

	log.Println("✅ Credential issued successfully")
	return credReturn, nil
}

// encodeValue encodes a credential value for AnonCreds
func (r *CredentialService) encodeValue(value string) string {
	// AnonCreds encoding: convert to integer representation
	// For now, simple hash-based encoding
	hash := int64(0)
	for _, ch := range value {
		hash = hash*31 + int64(ch)
	}
	return fmt.Sprintf("%d", hash)
}

// SendCredentialMessage is DEPRECATED and should not be used
// The credential issuance should happen through the CredentialService.ProcessRequest handler
// which is automatically triggered when a credential request is received
func (r *CredentialService) SendCredentialMessage(connectionID string, credential map[string]interface{}) error {
	return fmt.Errorf("DEPRECATED: Direct credential sending is not allowed. Credentials must be issued through CredentialService.ProcessRequest in response to a credential request")
}

// WaitForCredentialExchangeComplete waits for the credential exchange to complete
func (r *CredentialService) WaitForCredentialExchangeComplete(connectionID string, timeout time.Duration) error {
	log.Printf("⏳ Waiting for credential exchange to complete for connection: %s", connectionID)

	// Get event bus
	dm := r.agent.GetDependencyManager()
	bus := r.getEventBus(dm)
	if bus == nil {
		return fmt.Errorf("event bus not available")
	}

	done := make(chan error, 1)

	// Subscribe to credential state changes
	unsubscribe := bus.Subscribe("credentials.stateChanged", func(ev events.Event) {
		data, ok := ev.Data.(map[string]string)
		if !ok {
			// Try map[string]interface{} as well
			if dataInterface, ok := ev.Data.(map[string]interface{}); ok {
				// Convert to string map
				data = make(map[string]string)
				for k, v := range dataInterface {
					if str, ok := v.(string); ok {
						data[k] = str
					}
				}
			} else {
				return
			}
		}

		connID := data["connectionId"]
		state := data["state"]
		recordID := data["recordId"]

		// Log all state changes for this connection for debugging
		if connID == connectionID {
			log.Printf("   Credential state changed: %s (record: %s)", state, recordID)

			// Check if the credential exchange is done
			if state == string(credrecords.StateDone) {
				log.Printf("✅ Credential exchange completed for connection %s (state: done)", connectionID)
				done <- nil
			}
		}
	})
	defer unsubscribe()

	// Also log credential lifecycle events for debugging
	unsubscribe2 := bus.Subscribe("credentials.received", func(ev events.Event) {
		data, ok := ev.Data.(map[string]string)
		if !ok {
			// Try map[string]interface{} as well
			if dataInterface, ok := ev.Data.(map[string]interface{}); ok {
				// Convert to string map
				data = make(map[string]string)
				for k, v := range dataInterface {
					if str, ok := v.(string); ok {
						data[k] = str
					}
				}
			} else {
				return
			}
		}

		connID := data["connectionId"]

		if connID == connectionID {
			log.Printf("   📥 Credential received for connection %s (waiting for done state)", connectionID)
			// Don't complete yet - wait for the done state after ACK is sent
		}
	})
	defer unsubscribe2()

	// Also subscribe to offer received events for debugging
	unsubscribe3 := bus.Subscribe("credentials.offerReceived", func(ev events.Event) {
		data, ok := ev.Data.(map[string]string)
		if !ok {
			if dataInterface, ok := ev.Data.(map[string]interface{}); ok {
				data = make(map[string]string)
				for k, v := range dataInterface {
					if str, ok := v.(string); ok {
						data[k] = str
					}
				}
			} else {
				return
			}
		}

		connID := data["connectionId"]
		if connID == connectionID {
			log.Printf("   📋 Credential offer received for connection %s", connectionID)
		}
	})
	defer unsubscribe3()

	// Wait for completion or timeout
	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		return fmt.Errorf("timeout waiting for credential exchange after %v", timeout)
	}
}

// getEventBus retrieves the event bus from dependency manager
func (r *CredentialService) getEventBus(dm di.DependencyManager) events.Bus {
	if any, err := dm.Resolve(di.TokenEventBusService); err == nil {
		if bus, ok := any.(events.Bus); ok {
			return bus
		}
	}
	return nil
}
