package messages

import (
	"github.com/ajna-inc/essi/pkg/didcomm/messages"
)

const PresentationV2Type = "https://didcomm.org/present-proof/2.0/presentation"

type PresentationV2 struct {
	*messages.BaseMessage
	Comment       string                    `json:"comment,omitempty"`
	Formats       []AttachmentFormat           `json:"formats"`
	Presentations []messages.AttachmentDecorator `json:"presentations~attach"`
}

func NewPresentationV2(id, threadId string) *PresentationV2 {
	msg := &PresentationV2{
		BaseMessage:   messages.NewBaseMessage(PresentationV2Type),
		Formats:       []AttachmentFormat{},
		Presentations: []messages.AttachmentDecorator{},
	}
	msg.Id = id
	if threadId != "" {
		msg.SetThreadId(threadId)
	}
	return msg
}

func (m *PresentationV2) GetType() string {
	return PresentationV2Type
}

func (m *PresentationV2) GetId() string {
	return m.Id
}

func (m *PresentationV2) GetThreadId() string {
	if m.Thread != nil && m.Thread.Thid != "" {
		return m.Thread.Thid
	}
	return m.Id
}