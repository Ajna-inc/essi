package transport

// InboundTransport defines how to start/stop inbound DIDComm handling
// Implementations should call into MessageReceiver for processing.
type InboundTransport interface {
    Start(receiver *MessageReceiver) error
    Stop() error
}


