package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"strings"

	"github.com/ajna-inc/essi/pkg/askar"
	"github.com/ajna-inc/essi/pkg/core/agent"
	"github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/core/di"
	corestorage "github.com/ajna-inc/essi/pkg/core/storage"
	"github.com/ajna-inc/essi/pkg/core/wallet"
	"github.com/ajna-inc/essi/pkg/dids"
	"github.com/ajna-inc/essi/pkg/dids/api"
	didsmodule "github.com/ajna-inc/essi/pkg/dids/module"
	kandids "github.com/ajna-inc/essi/pkg/kanon/dids"
)

func main() {
	// Reuse the same Askar database used by kanon-test so we can inspect existing data
	askarModule := askar.NewAskarModuleBuilder().
		WithSQLiteDatabase("./kanon-test-askar.db").
		WithStoreID("kanon-test").
		WithStoreKey("kanon-test-secure-key-123456").
		Build()

	cfg := &context.AgentConfig{Label: "list-dids"}

	// Create agent with DID module to have full DID support
	modules := []di.Module{
		askarModule,
		didsmodule.NewDidsModule(&didsmodule.DidsModuleConfig{
			EnableDidKey:  true,
			EnableDidPeer: true,
			Resolvers:     []dids.DidResolver{kandids.NewKanonDidResolver()},
			Registrars:    []dids.DidRegistrar{kandids.NewKanonDidRegistrar()},
		}),
	}

	// Create minimal agent with storage so repositories resolve correctly
	a, err := agent.NewAgent(&agent.AgentOptions{
		Config:  cfg,
		Modules: modules,
	})
	if err != nil {
		log.Fatalf("new agent: %v", err)
	}
	if err := a.Initialize(); err != nil {
		log.Fatalf("init: %v", err)
	}
	defer a.Shutdown()

	// Resolve DID repository and API
	dm := a.GetDependencyManager()

	var didsApi *api.DidsApi
	if any, err := dm.Resolve(di.TokenDidsApi); err == nil {
		didsApi, _ = any.(*api.DidsApi)
	}

	var storageSvc corestorage.StorageService
	if any, err := dm.Resolve(di.TokenStorageService); err == nil {
		storageSvc, _ = any.(corestorage.StorageService)
	}
	if storageSvc == nil {
		log.Fatalf("storage service not available")
	}

	// List DIDs from repository if available
	if didsApi != nil {
		log.Printf("\nDIDs from Repository:")
		log.Printf("=" + strings.Repeat("=", 100))

		createdDids, err := didsApi.GetCreatedDids("")
		if err == nil && len(createdDids) > 0 {
			log.Printf("\nCreated DIDs (%d):", len(createdDids))
			for _, didRec := range createdDids {
				log.Printf("  - %s", didRec.Did)
				if didRec.DidDocument != nil {
					log.Printf("    - Has document: Yes")
					log.Printf("    - Verification methods: %d", len(didRec.DidDocument.VerificationMethod))
				}
				if len(didRec.Keys) > 0 {
					log.Printf("    - Associated keys: %d", len(didRec.Keys))
				}
			}
		} else if err != nil {
			log.Printf("  Error getting created DIDs: %v", err)
		} else {
			log.Printf("  No created DIDs found in repository")
		}

		receivedDids, err := didsApi.GetReceivedDids("")
		if err == nil && len(receivedDids) > 0 {
			log.Printf("\nReceived DIDs (%d):", len(receivedDids))
			for _, didRec := range receivedDids {
				log.Printf("  - %s", didRec.Did)
				if didRec.DidDocument != nil {
					log.Printf("    - Has document: Yes")
				}
			}
		} else if err == nil {
			log.Printf("\n  No received DIDs found in repository")
		}

		allDids, err := didsApi.GetAllDids()
		if err == nil {
			log.Printf("\nTotal DIDs in repository: %d", len(allDids))
		}
	}

	// List all stored keys (which can represent DIDs)
	keys, err := storageSvc.GetAll(a.GetContext().Context, "Key")
	if err != nil {
		log.Printf("Failed to get keys: %v", err)
	} else {
		log.Printf("Stored Keys (potential DIDs): %d", len(keys))
		if len(keys) > 0 {
			log.Printf("\n%-40s %-15s %-50s", "Key ID", "Type", "Public Key (base64)")
			log.Printf("%s", strings.Repeat("-", 105))

			for _, rec := range keys {
				if keyRec, ok := rec.(*wallet.KeyRecord); ok && keyRec.Key != nil {
					pubKeyStr := base64.RawURLEncoding.EncodeToString(keyRec.Key.PublicKey)
					// Construct potential did:key from Ed25519 public key
					var didKey string
					if keyRec.Key.Type == wallet.KeyTypeEd25519 && len(keyRec.Key.PublicKey) == 32 {
						// did:key uses multicodec prefix 0xed01 for Ed25519
						// For now, just show the base64 encoded key
						didKey = fmt.Sprintf("did:key:z[base64:%s]", pubKeyStr[:20]+"...")
					}

					log.Printf("%-40s %-15s %-50s",
						keyRec.Key.Id,
						keyRec.Key.Type,
						pubKeyStr[:20]+"...")

					if didKey != "" {
						log.Printf("  Potential DID: %s", didKey)
					}
				}
			}
		}
	}

	// List all connections to see DIDs in use
	connections, err := storageSvc.GetAll(a.GetContext().Context, "ConnectionRecord")
	if err != nil {
		log.Printf("Failed to get connections: %v", err)
		return
	}

	log.Printf("\nConnections with DIDs: %d total", len(connections))

	// Collect unique DIDs from connections
	ourDids := make(map[string]bool)
	theirDids := make(map[string]bool)

	for _, rec := range connections {
		tags := rec.GetTags()
		if did := tags["did"]; did != "" {
			ourDids[did] = true
		}
		if theirDid := tags["theirDid"]; theirDid != "" {
			theirDids[theirDid] = true
		}
	}

	if len(ourDids) > 0 {
		log.Printf("\nOur DIDs used in connections (%d):", len(ourDids))
		for did := range ourDids {
			log.Printf("  - %s", did)
		}
	}

	if len(theirDids) > 0 {
		log.Printf("\nTheir DIDs from connections (%d):", len(theirDids))
		for did := range theirDids {
			log.Printf("  - %s", did)
		}
	}

	// Also check for any Kanon-specific DIDs
	log.Printf("\nDID Summary:")
	log.Printf("  - Keys stored: %d", len(keys))
	log.Printf("  - Our unique DIDs: %d", len(ourDids))
	log.Printf("  - Their unique DIDs: %d", len(theirDids))
}
