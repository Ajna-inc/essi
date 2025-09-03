package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/ajna-inc/essi/pkg/anoncreds"
	"github.com/ajna-inc/essi/pkg/anoncreds/registry"
	askar "github.com/ajna-inc/essi/pkg/askar"
	"github.com/ajna-inc/essi/pkg/core/agent"
	corectx "github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/core/di"
	didcommmodule "github.com/ajna-inc/essi/pkg/didcomm"
	"github.com/ajna-inc/essi/pkg/didcomm/module"
	"github.com/ajna-inc/essi/pkg/didcomm/modules/credentials/formats"
	formatanoncreds "github.com/ajna-inc/essi/pkg/didcomm/modules/credentials/formats/anoncreds"
	"github.com/ajna-inc/essi/pkg/didcomm/modules/credentials/protocols"
	protocolv2 "github.com/ajna-inc/essi/pkg/didcomm/modules/credentials/protocols/v2"
	oob "github.com/ajna-inc/essi/pkg/didcomm/modules/oob"
	oobmsgs "github.com/ajna-inc/essi/pkg/didcomm/modules/oob/messages"
	didsmodule "github.com/ajna-inc/essi/pkg/dids/module"
	kanonpkg "github.com/ajna-inc/essi/pkg/kanon"
)

func main() {
	host := flag.String("host", "127.0.0.1", "Inbound host")
	port := flag.Int("port", 3001, "Inbound port")
	label := flag.String("label", "Essi-Go", "Agent label")
	dbPath := flag.String("db", "./create-oob-askar.db", "Askar sqlite path")
	endpoint := flag.String("endpoint", "", "Public endpoint (default http://host:port)")
	invitationDid := flag.String("did", "", "Use a DID-based OOB invitation (services will be [did])")
	multiUse := flag.Bool("multiUse", false, "Create a multi-use invitation (disallowed with attachments)")
	imageUrl := flag.String("imageUrl", "", "Optional image URL for the invitation")
	flag.Parse()

	cfg := &corectx.AgentConfig{
		Label:       *label,
		InboundHost: *host,
		InboundPort: *port,
		ExtraConfig: map[string]interface{}{
			"askar.enabled":       true,
			"askar.database.type": "sqlite",
			"askar.database.path": *dbPath,
			"askar.storeId":       *label,
			"askar.storeKey":      "default-key",
		},
	}

	if *endpoint != "" {
		cfg.Endpoints = []string{*endpoint}
	} else {
		cfg.Endpoints = []string{fmt.Sprintf("http://%s:%d", *host, *port)}
	}

	// Assemble modules: Askar (storage) + Kanon (ledger/registry) + DIDs + DidComm + Credentials + AnonCreds

	// Configure credential protocol (v2) with anoncreds format
	formatService := formatanoncreds.NewAnonCredsCredentialFormatService()
	v2Protocol := protocolv2.NewV2CredentialProtocol([]formats.CredentialFormatService{formatService})

	modules := []di.Module{
		askar.NewAskarModuleBuilder().WithSQLiteDatabase(*dbPath).WithStoreID(*label).WithStoreKey("default-key").Build(),
		kanonpkg.KanonModule(kanonpkg.KanonModuleConfigOptions{
			Networks: []kanonpkg.NetworkConfig{{
				Network:         "testnet",
				RpcUrl:          "http://127.0.0.1:8545/",
				PrivateKey:      "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
				ChainId:         31337,
				ContractAddress: "0x5FbDB2315678afecb367f032d93F642f64180aa3",
			}},
		}),
		didsmodule.NewDidsModule(nil),
		anoncreds.NewAnonCredsModule(&anoncreds.AnonCredsModuleConfig{
			Registries: []registry.Registry{kanonpkg.NewRegistry(nil)},
		}),
		didcommmodule.NewDidCommModule(nil),
		module.NewCredentialsModule(&module.CredentialsModuleConfig{
			AutoAcceptCredentials: "always",
			CredentialProtocols:   []protocols.CredentialProtocol{v2Protocol},
		}),
		module.NewProofsModule(&module.ProofsModuleConfig{
			AutoAcceptProofs: "always",
		}),
	}

	a, err := agent.NewAgent(&agent.AgentOptions{Config: cfg, Modules: modules})
	if err != nil {
		log.Fatalf("create agent: %v", err)
	}

	if err := a.Initialize(); err != nil {
		log.Fatalf("init agent: %v", err)
	}
	defer a.Shutdown()

	// Resolve OOB API from DI
	dm := a.GetDependencyManager()
	if dm == nil {
		log.Fatalf("di not available")
	}
	dep, err := dm.Resolve(di.TokenOobApi)
	if err != nil {
		log.Fatalf("resolve OobApi: %v", err)
	}
	oobApi, ok := dep.(*oob.OutOfBandApi)
	if !ok || oobApi == nil {
		log.Fatalf("OobApi not available")
	}

	cfgCreate := oob.CreateOutOfBandInvitationConfig{Label: *label}
	if *imageUrl != "" {
		cfgCreate.ImageUrl = *imageUrl
	}
	if *invitationDid != "" {
		cfgCreate.InvitationDid = *invitationDid
	}
	if *multiUse {
		cfgCreate.MultiUseInvitation = multiUse
	}
	rec, err := oobApi.CreateInvitation(cfgCreate)
	if err != nil {
		log.Fatalf("create invitation: %v", err)
	}

	inv, ok := rec.OutOfBandInvitation.(*oobmsgs.OutOfBandInvitationMessage)
	if !ok || inv == nil {
		log.Fatalf("invalid invitation payload in record")
	}

	url, err := oobApi.InvitationToUrl(inv)
	if err != nil {
		log.Fatalf("build invitation url: %v", err)
	}

	fmt.Println(url)

	a.Run()
}
