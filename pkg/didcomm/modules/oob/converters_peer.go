package oob

import (
    "fmt"

    "github.com/ajna-inc/essi/pkg/didcomm/modules/oob/messages"
    "github.com/ajna-inc/essi/pkg/dids"
    peermethod "github.com/ajna-inc/essi/pkg/dids/methods/peer"
)

// OutOfBandServiceToPeerDID converts an inline OOB service into a did:peer using numalgo 4 when possible,
// falling back to numalgo 2. This mirrors Credo-TS high-level behavior of producing a stable peer DID from
// inline OOB services to support routing and resolution.
func OutOfBandServiceToPeerDID(service messages.OutOfBandService) (string, error) {
    endpoint, ok := service.ServiceEndpoint.(string)
    if !ok || endpoint == "" {
        return "", fmt.Errorf("serviceEndpoint must be a non-empty string")
    }
    if len(service.RecipientKeys) == 0 {
        return "", fmt.Errorf("recipientKeys required to derive peer DID from inline service")
    }

    // Build a DID Document with DIDCommMessaging service (used for numalgo 4)
    didDoc := dids.NewDidDocument("")
    didDoc.AddService(&dids.Service{
        Id:              service.Id,
        Type:            dids.ServiceTypeDIDCommMessaging,
        ServiceEndpoint: endpoint,
        Accept:          append([]string(nil), service.Accept...),
        RecipientKeys:   append([]string(nil), service.RecipientKeys...),
        RoutingKeys:     append([]string(nil), service.RoutingKeys...),
    })

    if short, long, err := peermethod.CreateDidPeerNumAlgo4FromDidDocument(didDoc); err == nil {
        // Prefer long form for immediate resolvability by receivers
        if long != "" { return long, nil }
        if short != "" { return short, nil }
    }

    // Fallback to numalgo 2 using a service element
    svc := &dids.Service{
        Id:              service.Id,
        Type:            dids.ServiceTypeDIDCommMessaging,
        ServiceEndpoint: endpoint,
        Accept:          append([]string(nil), service.Accept...),
        RecipientKeys:   append([]string(nil), service.RecipientKeys...),
        RoutingKeys:     append([]string(nil), service.RoutingKeys...),
    }
    elem, err := peermethod.CreatePeerDidElement(peermethod.PurposeService, dids.ServiceTypeDIDCommMessaging, svc)
    if err != nil {
        return "", fmt.Errorf("failed to construct peer did service element: %w", err)
    }
    did2, err := peermethod.CreateDidPeerNumAlgo2([]peermethod.PeerDidElement{*elem})
    if err != nil {
        return "", fmt.Errorf("failed to create did:peer numalgo2: %w", err)
    }
    return did2, nil
}
