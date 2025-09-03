package protocols

import (
    "github.com/ajna-inc/essi/pkg/core/di"
    credmsgs "github.com/ajna-inc/essi/pkg/didcomm/modules/credentials/messages"
    credrecs "github.com/ajna-inc/essi/pkg/didcomm/modules/credentials/records"
)

// CredentialProtocol defines a high-level protocol driver (e.g., Issue Credential v2)
// that can orchestrate across one or more credential formats.
//
// Minimal scaffold to enable DI registration; the service delegates based on message content.
type CredentialProtocol interface {
    ID() string

    // TryBuildRequestFromOffer attempts to construct a request from an offer.
    // Return (request, handled=true) when the protocol recognized and handled the offer.
    TryBuildRequestFromOffer(dm di.DependencyManager, threadId string, connectionId string, offer *credmsgs.OfferCredentialV2, rec *credrecs.CredentialRecord) (*credmsgs.RequestCredentialV2, bool, error)

    // TryBuildIssueFromRequest attempts to build an issue-credential from a request.
    // Return (issue, handled=true) when the protocol recognized and handled the request.
    TryBuildIssueFromRequest(dm di.DependencyManager, threadId string, connectionId string, req *credmsgs.RequestCredentialV2, rec *credrecs.CredentialRecord) (*credmsgs.IssueCredentialV2Credential, bool, error)
}


