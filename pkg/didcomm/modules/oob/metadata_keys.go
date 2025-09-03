package oob

// Metadata key constants
const (
	MetadataKeyRecipientRouting = "recipientRouting"
	MetadataKeyLegacyInvitation = "legacyInvitation"
)

// RecipientRoutingMetadata stores routing information for the invitation
type RecipientRoutingMetadata struct {
	RecipientKeyFingerprint string   `json:"recipientKeyFingerprint"`
	RecipientKeyId          string   `json:"recipientKeyId"`
	RoutingKeyFingerprints  []string `json:"routingKeyFingerprints"`
	Endpoints               []string `json:"endpoints"`
	MediatorId              string   `json:"mediatorId,omitempty"`
}

// LegacyInvitationMetadata stores information about legacy invitation types
type LegacyInvitationMetadata struct {
	LegacyInvitationType string `json:"legacyInvitationType"`
}

// Legacy invitation types
const (
	LegacyInvitationTypeConnection     = "connections/1.x"
	LegacyInvitationTypeConnectionless = "connectionless"
)
