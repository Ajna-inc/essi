package operations

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/ajna-inc/essi/pkg/core/agent"
	"github.com/google/uuid"
)

// ProofRequestOperations handles proof request operations as a verifier
type ProofRequestOperations struct {
	agent   *agent.Agent
	metrics *Metrics
}

// NewProofRequestOperations creates a new proof request operations handler
func NewProofRequestOperations(agent *agent.Agent, metrics *Metrics) *ProofRequestOperations {
	return &ProofRequestOperations{
		agent:   agent,
		metrics: metrics,
	}
}

// SendProofRequest sends a proof request to a connection (as verifier)
func (p *ProofRequestOperations) SendProofRequest(connectionID string) error {
	start := time.Now()
	defer func() {
		p.metrics.Record("SendProofRequest", time.Since(start))
	}()

	log.Printf("📋 Sending proof request to connection: %s", connectionID)

	// Create a proof request message
	proofRequest := p.createProofRequestMessage()
	
	// Package the proof request as a DIDComm message
	message := map[string]interface{}{
		"@type": "https://didcomm.org/present-proof/1.0/request-presentation",
		"@id":   uuid.New().String(),
		"comment": "Please provide proof of your credentials",
		"request_presentations~attach": []map[string]interface{}{
			{
				"@id":     "libindy-request-presentation-0",
				"mime-type": "application/json",
				"data": map[string]interface{}{
					"base64": p.encodeBase64(proofRequest),
				},
			},
		},
	}

	// Send the message
	err := p.sendMessage(connectionID, message)
	if err != nil {
		return fmt.Errorf("failed to send proof request: %w", err)
	}

	log.Printf("✅ Proof request sent to connection %s", connectionID)
	log.Println("⏳ Waiting for proof presentation from the other agent...")
	
	return nil
}

// SendProofRequestV2 sends a proof request using DIDComm v2 protocol
func (p *ProofRequestOperations) SendProofRequestV2(connectionID string) error {
	start := time.Now()
	defer func() {
		p.metrics.Record("SendProofRequestV2", time.Since(start))
	}()

	log.Printf("📋 Sending proof request (v2) to connection: %s", connectionID)

	// Create an Aries RFC 0454 Present Proof V2 request
	proofRequest := p.createProofRequestV2()
	
	// Package as DIDComm v2 message
	message := map[string]interface{}{
		"@type": "https://didcomm.org/present-proof/2.0/request-presentation", 
		"@id":   uuid.New().String(),
		"comment": "Please provide proof of your employee credentials",
		"will_confirm": true,
		"formats": []map[string]interface{}{
			{
				"attach_id": "dif",
				"format": "dif/presentation-exchange/definitions@v1.0",
			},
		},
		"request_presentations~attach": []map[string]interface{}{
			{
				"@id": "dif",
				"mime-type": "application/json", 
				"data": map[string]interface{}{
					"json": proofRequest,
				},
			},
		},
	}

	// Send the message
	err := p.sendMessage(connectionID, message)
	if err != nil {
		return fmt.Errorf("failed to send proof request v2: %w", err)
	}

	log.Printf("✅ Proof request (v2) sent to connection %s", connectionID)
	log.Println("⏳ Waiting for proof presentation from the other agent...")
	
	return nil
}

// createProofRequestMessage creates an Indy proof request
func (p *ProofRequestOperations) createProofRequestMessage() map[string]interface{} {
	return map[string]interface{}{
		"name":    "Employee Verification",
		"version": "1.0",
		"nonce":   fmt.Sprintf("%d", time.Now().UnixNano()),
		"requested_attributes": map[string]interface{}{
			"attr1_referent": map[string]interface{}{
				"name": "name",
				"restrictions": []map[string]interface{}{
					{
						"schema_name": "EmployeeID",
					},
				},
			},
			"attr2_referent": map[string]interface{}{
				"name": "age",
				"restrictions": []map[string]interface{}{
					{
						"schema_name": "EmployeeID", 
					},
				},
			},
		},
		"requested_predicates": map[string]interface{}{
			"predicate1_referent": map[string]interface{}{
				"name":    "age",
				"p_type":  ">=",
				"p_value": 18,
				"restrictions": []map[string]interface{}{
					{
						"schema_name": "EmployeeID",
					},
				},
			},
		},
	}
}

// createProofRequestV2 creates a DIF Presentation Exchange request
func (p *ProofRequestOperations) createProofRequestV2() map[string]interface{} {
	return map[string]interface{}{
		"id": uuid.New().String(),
		"input_descriptors": []map[string]interface{}{
			{
				"id": "employee_name",
				"name": "Employee Name",
				"purpose": "We need to verify your employee name",
				"constraints": map[string]interface{}{
					"fields": []map[string]interface{}{
						{
							"path": []string{"$.credentialSubject.name", "$.vc.credentialSubject.name"},
						},
					},
				},
			},
			{
				"id": "employee_age",
				"name": "Employee Age",
				"purpose": "We need to verify you are over 18",
				"constraints": map[string]interface{}{
					"fields": []map[string]interface{}{
						{
							"path": []string{"$.credentialSubject.age", "$.vc.credentialSubject.age"},
							"filter": map[string]interface{}{
								"type": "number",
								"minimum": 18,
							},
						},
					},
				},
			},
		},
	}
}

// sendMessage sends a DIDComm message to a connection
func (p *ProofRequestOperations) sendMessage(connectionID string, message map[string]interface{}) error {
	// Use the agent's SendMessage method directly
	err := p.agent.SendMessage(message, connectionID)
	if err != nil {
		return fmt.Errorf("failed to send message: %w", err)
	}

	return nil
}

// encodeBase64 encodes data to base64
func (p *ProofRequestOperations) encodeBase64(data interface{}) string {
	jsonBytes, _ := json.Marshal(data)
	return base64.StdEncoding.EncodeToString(jsonBytes)
}

// RequestAndVerifyProof sends a proof request and waits for presentation with timing
func (p *ProofRequestOperations) RequestAndVerifyProof(connectionID string, timeout time.Duration) error {
	totalStart := time.Now()
	defer func() {
		totalElapsed := time.Since(totalStart)
		p.metrics.Record("TotalProofExchange", totalElapsed)
		log.Printf("⏱️  Total proof exchange time: %v", totalElapsed)
	}()
	
	// Send the proof request
	if err := p.SendProofRequestV2(connectionID); err != nil {
		return fmt.Errorf("failed to send proof request: %w", err)
	}
	
	// Wait for and verify the presentation
	if err := p.WaitForProofPresentation(connectionID, timeout); err != nil {
		return fmt.Errorf("failed waiting for proof presentation: %w", err)
	}
	
	return nil
}

// WaitForProofPresentation waits for a proof presentation from the other agent
func (p *ProofRequestOperations) WaitForProofPresentation(connectionID string, timeout time.Duration) error {
	start := time.Now()
	defer func() {
		elapsed := time.Since(start)
		p.metrics.Record("WaitForProofPresentation", elapsed)
		log.Printf("⏱️  Proof presentation wait time: %v", elapsed)
	}()
	
	log.Printf("⏳ Waiting for proof presentation from connection %s (timeout: %v)", connectionID, timeout)
	
	// In a real implementation, this would:
	// 1. Listen for incoming proof presentation messages
	// 2. Process the presentation when received
	// 3. Verify the cryptographic proof
	// 4. Return the verification result
	
	// For now, we'll simulate waiting
	time.Sleep(2 * time.Second)
	
	log.Println("⚠️  Proof presentation handling not yet fully implemented")
	log.Println("   The other agent would need to:")
	log.Println("   1. Receive our proof request")
	log.Println("   2. Find matching credentials")
	log.Println("   3. Create a proof presentation")
	log.Println("   4. Send it back to us")
	log.Println("   5. We would then verify it")
	
	return nil
}