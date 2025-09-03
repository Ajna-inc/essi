package routingmessages

import (
	base "github.com/ajna-inc/essi/pkg/didcomm/messages"
)

// RFC 0211 Coordinate Mediation messages
// https://didcomm.org/coordinate-mediation/1.0/

const (
	MediationRequestType      = "https://didcomm.org/coordinate-mediation/1.0/mediate-request"
	MediationGrantType        = "https://didcomm.org/coordinate-mediation/1.0/mediate-grant"
	MediationDenyType         = "https://didcomm.org/coordinate-mediation/1.0/mediate-deny"
	KeylistUpdateType         = "https://didcomm.org/coordinate-mediation/1.0/keylist-update"
	KeylistUpdateResponseType = "https://didcomm.org/coordinate-mediation/1.0/keylist-update-response"
)

type MediationRequest struct {
	*base.BaseMessage
}

func NewMediationRequest() *MediationRequest {
	return &MediationRequest{BaseMessage: base.NewBaseMessage(MediationRequestType)}
}

type MediationGrant struct {
	*base.BaseMessage
	RoutingKeys []string `json:"routing_keys"`
	Endpoint    string   `json:"endpoint"`
}

func NewMediationGrant(threadId string, endpoint string, routingKeys []string) *MediationGrant {
	m := &MediationGrant{BaseMessage: base.NewBaseMessage(MediationGrantType)}
	m.RoutingKeys = routingKeys
	m.Endpoint = endpoint
	m.SetThreadId(threadId)
	return m
}

type MediationDeny struct {
	*base.BaseMessage
}

func NewMediationDeny(threadId string) *MediationDeny {
	m := &MediationDeny{BaseMessage: base.NewBaseMessage(MediationDenyType)}
	m.SetThreadId(threadId)
	return m
}

type KeylistUpdateAction string

const (
	KeylistUpdateAdd    KeylistUpdateAction = "add"
	KeylistUpdateRemove KeylistUpdateAction = "remove"
)

type KeylistUpdateItem struct {
	RecipientKey string              `json:"recipient_key"`
	Action       KeylistUpdateAction `json:"action"`
}

type KeylistUpdate struct {
	*base.BaseMessage
	Updates []KeylistUpdateItem `json:"updates"`
}

func NewKeylistUpdate(items []KeylistUpdateItem) *KeylistUpdate {
	return &KeylistUpdate{BaseMessage: base.NewBaseMessage(KeylistUpdateType), Updates: items}
}

type KeylistUpdateResult string

const (
	KeylistUpdateResultSuccess  KeylistUpdateResult = "success"
	KeylistUpdateResultNoChange KeylistUpdateResult = "no_change"
	KeylistUpdateResultError    KeylistUpdateResult = "error"
)

type KeylistUpdateResponseItem struct {
	RecipientKey string              `json:"recipient_key"`
	Action       KeylistUpdateAction `json:"action"`
	Result       KeylistUpdateResult `json:"result"`
}

type KeylistUpdateResponse struct {
	*base.BaseMessage
	Updated []KeylistUpdateResponseItem `json:"updated"`
}

func NewKeylistUpdateResponse(threadId string, updated []KeylistUpdateResponseItem) *KeylistUpdateResponse {
	m := &KeylistUpdateResponse{BaseMessage: base.NewBaseMessage(KeylistUpdateResponseType), Updated: updated}
	m.SetThreadId(threadId)
	return m
}
