package formats

import (
    "github.com/ajna-inc/essi/pkg/core/di"
    credmsgs "github.com/ajna-inc/essi/pkg/didcomm/modules/credentials/messages"
    credrecs "github.com/ajna-inc/essi/pkg/didcomm/modules/credentials/records"
)

// HolderAdapter is the minimal interface needed by format services
// to create anoncreds-compatible requests or process issued credentials.
// Deprecated: adapters removed in favor of typed DI access
type HolderAdapter interface{}

// IssuerAdapter is the minimal interface needed to issue credentials
// from an offer + request + values payload.
// Deprecated: adapters removed in favor of typed DI access
type IssuerAdapter interface{}

// CredentialFormatService mirrors Credo-TS format services in a simplified form.
// Implementations can inspect the offer and build an appropriate v2 request.
type CredentialFormatService interface {
    // FormatID returns the format identifier string as used in cred v2 messages
    // (e.g., "anoncreds/credential-offer@v1.0").
    FormatID() string

    // BuildRequestFromOffer attempts to build a RequestCredentialV2 from the offer.
    // Returns (request, built=true) if handled; otherwise built=false to allow other services.
    BuildRequestFromOffer(dm di.DependencyManager, threadId string, connectionId string, offer *credmsgs.OfferCredentialV2, rec *credrecs.CredentialRecord) (*credmsgs.RequestCredentialV2, bool, error)
}


