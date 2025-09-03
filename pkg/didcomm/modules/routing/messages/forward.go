package routingmessages

import (
	base "github.com/ajna-inc/essi/pkg/didcomm/messages"
	envelopeservices "github.com/ajna-inc/essi/pkg/didcomm/services"
)

// Forward message as defined in RFC 0094 Cross Domain Messaging
// https://didcomm.org/routing/1.0/forward
// Type: https://didcomm.org/routing/1.0/forward

const ForwardMessageType = "https://didcomm.org/routing/1.0/forward"

type Forward struct {
	*base.BaseMessage
	// To is the verkey (base58) or DID of the final recipient
	To string `json:"to"`
	// Msg is the packed DIDComm message to be forwarded (JWE)
	Msg *envelopeservices.EncryptedMessage `json:"msg"`
}

func NewForward(to string, msg *envelopeservices.EncryptedMessage) *Forward {
	m := &Forward{
		BaseMessage: base.NewBaseMessage(ForwardMessageType),
		To:          to,
		Msg:         msg,
	}
	return m
}
