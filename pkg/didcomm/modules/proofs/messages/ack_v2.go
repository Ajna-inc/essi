package messages

import (
	"github.com/ajna-inc/essi/pkg/didcomm/messages"
)

const AckPresentationV2Type = "https://didcomm.org/present-proof/2.0/ack"

type AckPresentationV2 struct {
	*messages.BaseMessage
	Status string `json:"status,omitempty"`
}

func NewAckPresentationV2(id, threadId string) *AckPresentationV2 {
	msg := &AckPresentationV2{
		BaseMessage: messages.NewBaseMessage(AckPresentationV2Type),
		Status:      "OK",
	}
	msg.Id = id
	if threadId != "" {
		msg.SetThreadId(threadId)
	}
	return msg
}

func (m *AckPresentationV2) GetType() string {
	return AckPresentationV2Type
}

func (m *AckPresentationV2) GetId() string {
	return m.Id
}

func (m *AckPresentationV2) GetThreadId() string {
	if m.Thread != nil && m.Thread.Thid != "" {
		return m.Thread.Thid
	}
	return m.Id
}