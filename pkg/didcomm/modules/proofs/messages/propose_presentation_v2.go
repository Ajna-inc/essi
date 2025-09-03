package messages

import (
	"github.com/ajna-inc/essi/pkg/didcomm/messages"
)

const ProposePresentationV2Type = "https://didcomm.org/present-proof/2.0/propose-presentation"

type ProposePresentationV2 struct {
	*messages.BaseMessage
	Comment           string                    `json:"comment,omitempty"`
	Formats           []AttachmentFormat           `json:"formats"`
	ProposalAttachments []messages.AttachmentDecorator `json:"proposal~attach"`
}

func NewProposePresentationV2(id, threadId string) *ProposePresentationV2 {
	msg := &ProposePresentationV2{
		BaseMessage:         messages.NewBaseMessage(ProposePresentationV2Type),
		Formats:             []AttachmentFormat{},
		ProposalAttachments: []messages.AttachmentDecorator{},
	}
	msg.Id = id
	if threadId != "" {
		msg.SetThreadId(threadId)
	}
	return msg
}

func (m *ProposePresentationV2) GetType() string {
	return ProposePresentationV2Type
}

func (m *ProposePresentationV2) GetId() string {
	return m.Id
}

func (m *ProposePresentationV2) GetThreadId() string {
	if m.Thread != nil && m.Thread.Thid != "" {
		return m.Thread.Thid
	}
	return m.Id
}