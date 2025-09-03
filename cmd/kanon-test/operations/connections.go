package operations

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/ajna-inc/essi/pkg/core/agent"
	"github.com/ajna-inc/essi/pkg/core/di"
	"github.com/ajna-inc/essi/pkg/core/events"
	"github.com/ajna-inc/essi/pkg/didcomm/modules/connections/services"
)

// ConnectionOperations handles connection-related operations
type ConnectionOperations struct {
	agent   *agent.Agent
	metrics *Metrics
}

// NewConnectionOperations creates a new connection operations handler
func NewConnectionOperations(agent *agent.Agent, metrics *Metrics) *ConnectionOperations {
	return &ConnectionOperations{agent: agent, metrics: metrics}
}

// ProcessOOBInvitation processes an out-of-band invitation
func (c *ConnectionOperations) ProcessOOBInvitation(invitation string) (*services.ConnectionRecord, error) {
	startTime := time.Now()
	defer func() {
		if c.metrics != nil {
			c.metrics.Record("process_oob_invitation", time.Since(startTime))
		}
	}()
	log.Printf("📨 Processing OOB invitation: %s", invitation[:100]+"...")
	conn, err := c.agent.ProcessOOBInvitation(invitation)
	if err != nil {
		return nil, fmt.Errorf("failed to process OOB invitation: %w", err)
	}
	log.Printf("✅ Connected: %s", conn.ID)
	log.Printf("   State: %s", conn.State)
	log.Printf("   Their DID: %s", conn.TheirDid)
	return conn, nil
}

// WaitForConnection waits for a connection to reach the complete state
func (c *ConnectionOperations) WaitForConnection(connectionID string, timeout time.Duration) error {
	startTime := time.Now()
	defer func() {
		if c.metrics != nil {
			c.metrics.Record("wait_for_connection", time.Since(startTime))
		}
	}()
	dm := c.agent.GetDependencyManager()
	bus := c.getEventBus(dm)
	if bus == nil {
		return fmt.Errorf("event bus not available")
	}
	done := make(chan error, 1)
	unsubscribe := bus.Subscribe(events.EventConnectionStateChanged, func(ev events.Event) {
		data, ok := ev.Data.(map[string]interface{})
		if !ok {
			return
		}
		connID, _ := data["connectionId"].(string)
		state, _ := data["state"].(string)
		if connID == connectionID && state == "complete" {
			done <- nil
		}
	})
	defer unsubscribe()
	log.Printf("⏳ Waiting for connection %s to complete...", connectionID)
	select {
	case err := <-done:
		if err == nil {
			log.Printf("✅ Connection %s completed", connectionID)
		}
		return err
	case <-time.After(timeout):
		return fmt.Errorf("timeout waiting for connection %s", connectionID)
	}
}

// ConnectionCallback represents a callback function for connection events
type ConnectionCallback func(connectionID string) error

// WaitForConnectionAndExecute waits for a connection and executes a callback when complete
func (c *ConnectionOperations) WaitForConnectionAndExecute(connectionID string, timeout time.Duration, callback ConnectionCallback) error {
	startTime := time.Now()
	defer func() {
		if c.metrics != nil {
			c.metrics.Record("wait_and_execute", time.Since(startTime))
		}
	}()
	dm := c.agent.GetDependencyManager()
	bus := c.getEventBus(dm)
	if bus == nil {
		return fmt.Errorf("event bus not available")
	}
	done := make(chan error, 1)
	didExecute := &sync.Once{}
	unsubscribe := bus.Subscribe(events.EventConnectionStateChanged, func(ev events.Event) {
		data, ok := ev.Data.(map[string]interface{})
		if !ok {
			return
		}
		connID, _ := data["connectionId"].(string)
		state, _ := data["state"].(string)
		if connID == connectionID && state == "complete" {
			didExecute.Do(func() { go func() { err := callback(connectionID); done <- err }() })
		}
	})
	defer unsubscribe()
	log.Printf("⏳ Waiting for connection %s to complete before executing callback...", connectionID)
	select {
	case err := <-done:
		if err == nil {
			log.Printf("✅ Callback executed successfully for connection %s", connectionID)
		}
		return err
	case <-time.After(timeout):
		return fmt.Errorf("timeout waiting for connection %s", connectionID)
	}
}

// WaitForConnectionComplete waits for a connection to reach complete state
func (c *ConnectionOperations) WaitForConnectionComplete(connectionID string, timeout time.Duration) error {
	startTime := time.Now()
	for time.Since(startTime) < timeout {
		conn, err := c.agent.GetConnection(connectionID)
		if err != nil {
			return fmt.Errorf("failed to get connection: %w", err)
		}
		if conn.State == "complete" || conn.State == "responded" {
			log.Printf("✅ Connection %s is ready (state: %s)", connectionID, conn.State)
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for connection %s to complete", connectionID)
}

// GetConnections retrieves all connections
func (c *ConnectionOperations) GetConnections() ([]*services.ConnectionRecord, error) {
	startTime := time.Now()
	defer func() {
		if c.metrics != nil {
			c.metrics.Record("get_connections", time.Since(startTime))
		}
	}()
	return c.agent.GetConnections()
}

// GetConnection retrieves a specific connection by ID
func (c *ConnectionOperations) GetConnection(connectionID string) (*services.ConnectionRecord, error) {
	startTime := time.Now()
	defer func() {
		if c.metrics != nil {
			c.metrics.Record("get_connection", time.Since(startTime))
		}
	}()
	conns, err := c.agent.GetConnections()
	if err != nil {
		return nil, err
	}
	for _, conn := range conns {
		if conn.ID == connectionID {
			return conn, nil
		}
	}
	return nil, fmt.Errorf("connection %s not found", connectionID)
}

// getEventBus retrieves the event bus from the dependency manager
func (c *ConnectionOperations) getEventBus(dm di.DependencyManager) events.Bus {
	if any, err := dm.Resolve(di.TokenEventBusService); err == nil {
		if bus, ok := any.(events.Bus); ok {
			return bus
		}
	}
	return nil
}
