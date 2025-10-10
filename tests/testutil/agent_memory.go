package testutil

import (
	"testing"

	"github.com/ajna-inc/essi/pkg/core/agent"
	corectx "github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/core/di"
	didcommmodule "github.com/ajna-inc/essi/pkg/didcomm"
	transport "github.com/ajna-inc/essi/pkg/didcomm/transport"
	didsmodule "github.com/ajna-inc/essi/pkg/dids/module"
)

// NewMemoryAgent builds an Agent using in-memory storage (no native deps) and DidComm/DIDs modules.
func NewMemoryAgent(t *testing.T, label string, endpoints []string, useSubject bool) *agent.Agent {
	t.Helper()
	cfg := &corectx.AgentConfig{Label: label, Endpoints: endpoints}
	modules := []di.Module{
		NewMemoryStorageModule(),
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
	if useSubject {
		if any, err := a.GetDependencyManager().Resolve(di.TokenMessageSender); err == nil {
			if ms, ok := any.(*transport.MessageSender); ok && ms != nil {
				ms.RegisterOutboundTransport(transport.NewSubjectOutboundTransport())
			}
		}
	}
	return a
}
