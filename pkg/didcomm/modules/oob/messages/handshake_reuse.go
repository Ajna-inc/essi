package messages

import (
    "github.com/ajna-inc/essi/pkg/didcomm/messages"
)

// Message type URIs for OOB handshake reuse
const (
    HandshakeReuseMessageType          = "https://didcomm.org/out-of-band/1.1/handshake-reuse"
    HandshakeReuseType                 = HandshakeReuseMessageType // Alias for backward compatibility
    HandshakeReuseAcceptedMessageType  = "https://didcomm.org/out-of-band/1.1/handshake-reuse-accepted"
    HandshakeReuseAcceptedType         = HandshakeReuseAcceptedMessageType // Alias for backward compatibility
)

// HandshakeReuseMessage represents an OOB handshake-reuse message
type HandshakeReuseMessage struct {
    *messages.BaseMessage
}

// NewHandshakeReuseMessage creates a new handshake-reuse message with a parent thread id
func NewHandshakeReuseMessage(parentThreadId string) *HandshakeReuseMessage {
    msg := &HandshakeReuseMessage{
        BaseMessage: messages.NewBaseMessage(HandshakeReuseType),
    }
    if parentThreadId != "" {
        msg.SetParentThreadId(parentThreadId)
    }
    return msg
}

// HandshakeReuseAcceptedMessage represents an OOB handshake-reuse-accepted message
type HandshakeReuseAcceptedMessage struct {
    *messages.BaseMessage
}

// NewHandshakeReuseAcceptedMessage creates a new handshake-reuse-accepted message that replies within the reuse thread
func NewHandshakeReuseAcceptedMessage(threadId string, parentThreadId string) *HandshakeReuseAcceptedMessage {
    msg := &HandshakeReuseAcceptedMessage{
        BaseMessage: messages.NewBaseMessage(HandshakeReuseAcceptedType),
    }
    if threadId != "" {
        msg.SetThreadId(threadId)
    }
    if parentThreadId != "" {
        msg.SetParentThreadId(parentThreadId)
    }
    return msg
}


