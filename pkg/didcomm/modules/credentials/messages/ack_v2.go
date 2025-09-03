package messages

import (
	"encoding/json"

	"github.com/ajna-inc/essi/pkg/didcomm/messages"
)

const AckCredentialV2Type = "https://didcomm.org/issue-credential/2.0/ack"

type AckCredentialV2 struct {
	*messages.BaseMessage
	Status string `json:"status,omitempty"`
}

func NewAckCredentialV2() *AckCredentialV2 {
	return &AckCredentialV2{
		BaseMessage: messages.NewBaseMessage(AckCredentialV2Type),
		Status:      "OK",
	}
}

func (m *AckCredentialV2) ToJSON() ([]byte, error) {
	return json.Marshal(m)
}

func (m *AckCredentialV2) FromJSON(b []byte) error {
	return json.Unmarshal(b, &m)
}