package transport

// Return route constants
const (
	ReturnRouteNone   = "none"
	ReturnRouteAll    = "all"
	ReturnRouteThread = "thread"
)

// TransportDecorator represents the ~transport decorator
type TransportDecorator struct {
	ReturnRoute             string `json:"return_route,omitempty"`
	ReturnRouteThread       string `json:"return_route_thread,omitempty"`
	QueuedTransportResponse string `json:"queued_transport_response,omitempty"`
}

// HasReturnRouting checks if the decorator has return routing enabled
func (t *TransportDecorator) HasReturnRouting() bool {
	return t != nil && (t.ReturnRoute == ReturnRouteAll || t.ReturnRoute == ReturnRouteThread)
}