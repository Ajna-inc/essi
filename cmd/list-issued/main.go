package main

import (
	"log"

	"github.com/ajna-inc/essi/pkg/askar"
	"github.com/ajna-inc/essi/pkg/core/agent"
	"github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/core/di"
	corestorage "github.com/ajna-inc/essi/pkg/core/storage"
	credrecs "github.com/ajna-inc/essi/pkg/didcomm/modules/credentials/records"
)

func main() {
	// Reuse the same Askar database used by kanon-test so we can inspect existing data
	askarModule := askar.NewAskarModuleBuilder().
		WithSQLiteDatabase("./kanon-test-askar.db").
		WithStoreID("kanon-test").
		WithStoreKey("kanon-test-secure-key-123456").
		Build()

	cfg := &context.AgentConfig{Label: "list-issued"}

	// Create minimal agent with storage so repositories resolve correctly
	a, err := agent.NewAgent(&agent.AgentOptions{
		Config:  cfg,
		Modules: []di.Module{askarModule},
	})
	if err != nil {
		log.Fatalf("new agent: %v", err)
	}
	if err := a.Initialize(); err != nil {
		log.Fatalf("init: %v", err)
	}
	defer a.Shutdown()

	// Resolve storage and construct credentials repository
	dm := a.GetDependencyManager()
	var storageSvc corestorage.StorageService
	if any, err := dm.Resolve(di.TokenStorageService); err == nil {
		storageSvc, _ = any.(corestorage.StorageService)
	}
	if storageSvc == nil {
		log.Fatalf("storage service not available")
	}

	repo := credrecs.NewAskarRepository(storageSvc)

	// List all credential exchange records
	all, err := repo.GetAll(a.GetContext())
	if err != nil {
		log.Fatalf("get all credentials: %v", err)
	}
	log.Printf("🔎 Credential exchanges in DB: %d", len(all))
	for _, r := range all {
		log.Printf("  - id=%s role=%s state=%s connId=%s thid=%s",
			r.ID, r.Role, r.State, r.ConnectionId, r.ThreadId)
	}

	// Issuer-side (credentials we issued)
	issued, err := repo.GetByRole("issuer")
	if err == nil {
		log.Printf("\n🔎 Issuer-side exchanges: %d", len(issued))
		for _, r := range issued {
			log.Printf("  - id=%s state=%s connId=%s thid=%s",
				r.ID, r.State, r.ConnectionId, r.ThreadId)
		}
	}

	// Completed (done) exchanges
	done, err := repo.GetByState(a.GetContext(), credrecs.StateDone)
	if err == nil {
		log.Printf("\n🔎 Exchanges in 'done' state: %d", len(done))
		for _, r := range done {
			log.Printf("  - id=%s role=%s connId=%s thid=%s",
				r.ID, r.Role, r.ConnectionId, r.ThreadId)
		}
	}
}
