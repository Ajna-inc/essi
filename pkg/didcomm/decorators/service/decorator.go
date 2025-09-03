package service

import (
	"github.com/ajna-inc/essi/pkg/didcomm/messages"
	"github.com/ajna-inc/essi/pkg/didcomm/models"
)

// ServiceDecorator represents a ~service decorator on a message
type ServiceDecorator struct {
	RecipientKeys   []string `json:"recipientKeys"`
	RoutingKeys     []string `json:"routingKeys,omitempty"`
	ServiceEndpoint string   `json:"serviceEndpoint"`
}

// ToResolvedDidCommService converts to a resolved service
func (s *ServiceDecorator) ToResolvedDidCommService() *models.ResolvedDidCommService {
	if s == nil {
		return nil
	}
	return &models.ResolvedDidCommService{
		ID:              "",
		ServiceEndpoint: s.ServiceEndpoint,
		RecipientKeys:   s.RecipientKeys,
		RoutingKeys:     s.RoutingKeys,
	}
}

// FromResolvedDidCommService creates a decorator from a resolved service
func FromResolvedDidCommService(service *models.ResolvedDidCommService) *ServiceDecorator {
	if service == nil {
		return nil
	}
	return &ServiceDecorator{
		RecipientKeys:   service.RecipientKeys,
		RoutingKeys:     service.RoutingKeys,
		ServiceEndpoint: service.ServiceEndpoint,
	}
}

// GetServiceDecorator gets the service decorator from a message
func GetServiceDecorator(msg messages.AgentMessage) *ServiceDecorator {
	// In a real implementation, this would extract the ~service decorator
	// from the message's decorators map
	return nil
}

// SetServiceDecorator sets the service decorator on a message
func SetServiceDecorator(msg messages.AgentMessage, decorator *ServiceDecorator) {
	// In a real implementation, this would set the ~service decorator
	// on the message's decorators map
}