package messages

import (
	"github.com/ajna-inc/essi/pkg/didcomm/messages"
	"github.com/ajna-inc/essi/pkg/didcomm/modules/proofs/models"
)

const ProblemReportV2Type = "https://didcomm.org/present-proof/2.0/problem-report"

// ProblemDescription represents the description of a problem
type ProblemDescription struct {
	Code        models.PresentationProblemReportReason `json:"code"`
	Description string                                  `json:"en,omitempty"`
}

// ProblemReportV2 represents a problem report message for V2 protocol
type ProblemReportV2 struct {
	*messages.BaseMessage
	Description ProblemDescription `json:"description"`
}

// NewProblemReportV2 creates a new problem report message
func NewProblemReportV2(id, threadId string, reason models.PresentationProblemReportReason, description string) *ProblemReportV2 {
	msg := &ProblemReportV2{
		BaseMessage: messages.NewBaseMessage(ProblemReportV2Type),
		Description: ProblemDescription{
			Code:        reason,
			Description: description,
		},
	}
	msg.Id = id
	if threadId != "" {
		msg.SetThreadId(threadId)
	}
	return msg
}

func (m *ProblemReportV2) GetType() string {
	return ProblemReportV2Type
}

func (m *ProblemReportV2) GetId() string {
	return m.Id
}

func (m *ProblemReportV2) GetThreadId() string {
	if m.Thread != nil && m.Thread.Thid != "" {
		return m.Thread.Thid
	}
	return m.Id
}