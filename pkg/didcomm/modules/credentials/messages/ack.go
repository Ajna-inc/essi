package messages

import (
	"encoding/json"

	didmsg "github.com/ajna-inc/essi/pkg/didcomm/messages"
)

const AckType = "https://didcomm.org/notification/1.0/ack"

type Ack struct {
	*didmsg.BaseMessage
	Status string `json:"status,omitempty"`
}

func NewAck() *Ack                     { return &Ack{BaseMessage: didmsg.NewBaseMessage(AckType), Status: "OK"} }
func (m *Ack) ToJSON() ([]byte, error) { return m.BaseMessage.ToJSON() }
func (m *Ack) FromJSON(b []byte) error { return json.Unmarshal(b, &m) }
