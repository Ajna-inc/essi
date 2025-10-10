package testutil

import (
	"github.com/ajna-inc/essi/pkg/didcomm/models"
)

// SenderSpy captures outbound message contexts for assertions
type SenderSpy struct {
	Ch chan *models.OutboundMessageContext
}

func NewSenderSpy() *SenderSpy { return &SenderSpy{Ch: make(chan *models.OutboundMessageContext, 10)} }

func (s *SenderSpy) SendMessage(out *models.OutboundMessageContext) error {
	s.Ch <- out
	return nil
}
