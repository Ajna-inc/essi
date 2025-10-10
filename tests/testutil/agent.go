//go:build integration
// +build integration

package testutil

import (
	"fmt"
	"testing"

	askarmodule "github.com/ajna-inc/essi/pkg/askar"
	"github.com/ajna-inc/essi/pkg/core/agent"
	corectx "github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/core/di"
	didcommmodule "github.com/ajna-inc/essi/pkg/didcomm"
	transport "github.com/ajna-inc/essi/pkg/didcomm/transport"
	didsmodule "github.com/ajna-inc/essi/pkg/dids/module"
)

// TestAgentOptions configures a lightweight test agent
type TestAgentOptions struct {
	Label                 string
	InboundHost           string
	InboundPort           int
	Endpoints             []string
	UseSubjectTransport   bool
	InMemoryStoreID       string
	MediatorInvitationUrl string
}

// NewTestAgent builds and initializes an Agent with in-memory Askar and DidComm modules.
// When UseSubjectTransport is true, registers SubjectOutboundTransport with the MessageSender.
func NewTestAgent(t *testing.T, opts TestAgentOptions) *agent.Agent {
	t.Helper()

	if opts.Label == "" {
		opts.Label = "test-agent"
	}
	if opts.InMemoryStoreID == "" {
		opts.InMemoryStoreID = opts.Label
	}

	cfg := &corectx.AgentConfig{Label: opts.Label, InboundHost: opts.InboundHost, InboundPort: opts.InboundPort, MediatorInvitationUrl: opts.MediatorInvitationUrl}
	if len(opts.Endpoints) > 0 {
		cfg.Endpoints = opts.Endpoints
	} else if opts.InboundPort > 0 {
		cfg.Endpoints = []string{fmt.Sprintf("http://%s:%d", valueOr(opts.InboundHost, "127.0.0.1"), opts.InboundPort)}
	}

	modules := []di.Module{
		askarmodule.NewAskarModuleBuilder().WithInMemoryDatabase().WithStoreID(opts.InMemoryStoreID).WithStoreKey("test-key-123").Build(),
		didsmodule.NewDidsModule(&didsmodule.DidsModuleConfig{EnableDidPeer: true, EnableDidKey: true}),
		didcommmodule.NewDidCommModule(nil),
	}

	a, err := agent.NewAgent(&agent.AgentOptions{Config: cfg, Modules: modules})
	if err != nil {
		t.Fatalf("new agent: %v", err)
	}
	if err := a.Initialize(); err != nil {
		t.Fatalf("init agent: %v", err)
	}
	t.Cleanup(func() { _ = a.Shutdown() })

	if opts.UseSubjectTransport {
		if any, err := a.GetDependencyManager().Resolve(di.TokenMessageSender); err == nil {
			if ms, ok := any.(*transport.MessageSender); ok && ms != nil {
				ms.RegisterOutboundTransport(transport.NewSubjectOutboundTransport())
			}
		}
	}
	return a
}

func valueOr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
