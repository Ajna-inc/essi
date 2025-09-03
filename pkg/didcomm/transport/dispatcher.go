package transport

import (
	"fmt"
	"sync"

	"github.com/ajna-inc/essi/pkg/core/logger"
	"github.com/ajna-inc/essi/pkg/didcomm/models"
)

// HandlerFunc defines a function that returns an OutboundMessageContext
// This is the ONLY handler type we support - all handlers must return OutboundMessageContext
type HandlerFunc func(*InboundMessageContext) (*models.OutboundMessageContext, error)

// Dispatcher routes inbound messages to registered handlers and handles OutboundMessageContext
type Dispatcher struct {
	handlers      map[string]HandlerFunc
	messageSender MessageSenderInterface
	mutex         sync.RWMutex
}

// MessageSenderInterface defines the interface for sending messages
type MessageSenderInterface interface {
	SendMessage(outboundContext *models.OutboundMessageContext) error
}

// NewDispatcher creates a new dispatcher
func NewDispatcher() *Dispatcher {
	return &Dispatcher{
		handlers: make(map[string]HandlerFunc),
	}
}

// SetMessageSender sets the message sender for handling OutboundMessageContext
func (d *Dispatcher) SetMessageSender(sender MessageSenderInterface) {
	d.messageSender = sender
}

// getLogger resolves the injected logger
func getLogger(ctx *InboundMessageContext) logger.Logger {
	return logger.GetDefaultLogger()
}

// Register registers a handler for a message type
func (d *Dispatcher) Register(msgType string, handler HandlerFunc) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	if d.handlers == nil {
		d.handlers = make(map[string]HandlerFunc)
	}
	d.handlers[msgType] = handler
	logger.GetDefaultLogger().Infof("✅ Registered handler for message type: %s", msgType)
}

// Dispatch invokes the handler for the message and processes the result
func (d *Dispatcher) Dispatch(ctx *InboundMessageContext) error {
	if ctx == nil || ctx.Message == nil {
		return fmt.Errorf("nil inbound message context")
	}

	lg := getLogger(ctx)
	msgType := ctx.Message.GetType()

	// Emit AgentMessageReceived — skipped to avoid context-based DI

	d.mutex.RLock()
	handler, ok := d.handlers[msgType]
	d.mutex.RUnlock()

	if !ok {
		lg.Warnf("No handler registered for message type: %s", msgType)
		return fmt.Errorf("no handler registered for message type %s", msgType)
	}

	lg.Infof("Dispatching message type: %s", msgType)

	// Call the handler - it returns OutboundMessageContext or nil
	outboundCtx, err := handler(ctx)
	if err != nil {
		lg.Errorf("Handler error for %s: %v", msgType, err)
		return err
	}

	// If handler returns an outbound context, send the message
	if outboundCtx != nil {
		if d.messageSender == nil {
			lg.Warn("No message sender configured, cannot send response")
			return fmt.Errorf("no message sender configured")
		}

		// Emit AgentMessageProcessed — skipped to avoid context-based DI

		// Send the response message asynchronously
		go func(outCtx *models.OutboundMessageContext) {
			lg.Info("Sending response message")
			if err := d.messageSender.SendMessage(outCtx); err != nil {
				lg.Errorf("Failed to send outbound message: %v", err)
			} else {
				lg.Info("Outbound message sent successfully")
			}
		}(outboundCtx)
	} else {
		lg.Info("Handler returned no outbound message")
	}

	return nil
}

// Global dispatcher reference for components that need to dispatch outside the HTTP receiver
var globalDispatcher *Dispatcher

// SetDispatcher sets the global dispatcher
func SetDispatcher(d *Dispatcher) {
	globalDispatcher = d
}

// GetDispatcher retrieves the global dispatcher
func GetDispatcher() *Dispatcher {
	return globalDispatcher
}

// MessageHandlerRegistry allows modules to register handlers without knowing Dispatcher details
type MessageHandlerRegistry struct {
	dispatcher *Dispatcher
}

// NewMessageHandlerRegistry creates a new registry
func NewMessageHandlerRegistry(dispatcher *Dispatcher) *MessageHandlerRegistry {
	return &MessageHandlerRegistry{dispatcher: dispatcher}
}

// RegisterMessageHandler registers a handler for a message type
func (r *MessageHandlerRegistry) RegisterMessageHandler(msgType string, handler HandlerFunc) {
	if r == nil || r.dispatcher == nil {
		return
	}
	r.dispatcher.Register(msgType, handler)
}
