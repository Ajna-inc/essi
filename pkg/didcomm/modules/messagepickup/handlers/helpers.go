package handlers

import (
	"github.com/ajna-inc/essi/pkg/didcomm/messages"
)

// V1Batch represents a v1 message pickup batch
type V1Batch struct {
	*messages.BaseMessage
	Messages []struct {
		Id      string                 `json:"id"`
		Message map[string]interface{} `json:"message"`
	} `json:"messages~attach"`
}