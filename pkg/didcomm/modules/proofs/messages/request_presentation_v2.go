package messages

import (
	"github.com/ajna-inc/essi/pkg/didcomm/messages"
)

const RequestPresentationV2Type = "https://didcomm.org/present-proof/2.0/request-presentation"

type RequestPresentationV2 struct {
	*messages.BaseMessage
	Comment              string                      `json:"comment,omitempty"`
	WillConfirm          bool                        `json:"will_confirm,omitempty"`
	PresentationRequest  *PresentationRequestAttach  `json:"presentation_request,omitempty"`
	Formats              []AttachmentFormat           `json:"formats"`
	RequestPresentations []messages.AttachmentDecorator `json:"request_presentations~attach"`
}

type PresentationRequestAttach struct {
	Type                string                            `json:"@type,omitempty"`
	Name                string                            `json:"name"`
	Version             string                            `json:"version"`
	Nonce               string                            `json:"nonce"`
	RequestedAttributes map[string]*RequestedAttribute    `json:"requested_attributes"`
	RequestedPredicates map[string]*RequestedPredicate    `json:"requested_predicates"`
	NonRevoked          *NonRevokedInterval               `json:"non_revoked,omitempty"`
}

type RequestedAttribute struct {
	Name         string                   `json:"name,omitempty"`
	Names        []string                 `json:"names,omitempty"`
	Restrictions []map[string]interface{} `json:"restrictions,omitempty"`
	NonRevoked   *NonRevokedInterval      `json:"non_revoked,omitempty"`
}

type RequestedPredicate struct {
	Name         string                   `json:"name"`
	PType        string                   `json:"p_type"`
	PValue       int                      `json:"p_value"`
	Restrictions []map[string]interface{} `json:"restrictions,omitempty"`
	NonRevoked   *NonRevokedInterval      `json:"non_revoked,omitempty"`
}

type NonRevokedInterval struct {
	From int64 `json:"from,omitempty"`
	To   int64 `json:"to,omitempty"`
}

type AttachmentFormat struct {
	AttachId string `json:"attach_id"`
	Format   string `json:"format"`
}

func NewRequestPresentationV2(id, threadId string) *RequestPresentationV2 {
	msg := &RequestPresentationV2{
		BaseMessage:          messages.NewBaseMessage(RequestPresentationV2Type),
		Formats:              []AttachmentFormat{},
		RequestPresentations: []messages.AttachmentDecorator{},
	}
	msg.Id = id
	if threadId != "" {
		msg.SetThreadId(threadId)
	}
	return msg
}

func (m *RequestPresentationV2) GetType() string {
	return RequestPresentationV2Type
}

func (m *RequestPresentationV2) GetId() string {
	return m.Id
}

func (m *RequestPresentationV2) GetThreadId() string {
	if m.Thread != nil && m.Thread.Thid != "" {
		return m.Thread.Thid
	}
	return m.Id
}