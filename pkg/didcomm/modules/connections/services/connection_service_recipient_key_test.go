package services

import (
	"testing"

	"github.com/ajna-inc/essi/pkg/didcomm/modules/oob/messages"
	"github.com/stretchr/testify/assert"
)

func TestRecipientKeyExtraction(t *testing.T) {
	// Create a mock OOB invitation with inline service and recipient keys
	invitation := messages.NewOutOfBandInvitationMessage("Test Invitation")
	invitation.SetId("test-invitation-id")

	// Add inline service with recipient keys
	recipientKey := "z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
	invitation.Services = []messages.OutOfBandService{
		{
			Id:              "service-1",
			ServiceEndpoint: "https://example.com/endpoint",
			RecipientKeys:   []string{recipientKey},
			RoutingKeys:     []string{},
		},
	}

	// Add handshake protocol
	invitation.Handshake = []messages.HandshakeProtocol{
		{ProtocolId: "https://didcomm.org/connections/1.0"},
	}

	// Test the key extraction logic
	assert.Equal(t, 1, len(invitation.Services), "Should have one service")
	assert.Equal(t, 1, len(invitation.Services[0].RecipientKeys), "Should have one recipient key")
	assert.Equal(t, recipientKey, invitation.Services[0].RecipientKeys[0], "Recipient key should match")

	// Test normalization
	normalized := normalizeRecipientKey(recipientKey)
	assert.NotEmpty(t, normalized, "Normalized key should not be empty")
	assert.Equal(t, recipientKey, normalized, "Key should be unchanged if already normalized")
	t.Logf("Normalized recipient key: %s", normalized)
}

func TestNormalizeRecipientKey(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "DID key format",
			input:    "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
			expected: "z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
		},
		{
			name:     "Base58 key",
			input:    "z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
			expected: "z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
		},
		{
			name:     "Empty string",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeRecipientKey(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}
