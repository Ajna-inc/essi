package kanon

import (
	"encoding/json"

	"github.com/ajna-inc/essi/pkg/core/context"
	dids "github.com/ajna-inc/essi/pkg/dids"
	"github.com/ajna-inc/essi/pkg/kanon/ledger"
)

// DidRegistrar performs create/update of did:kanon DIDs on the Kanon ledger.
type DidRegistrar struct {
	ledger ledger.KanonLedger
}

func NewDidRegistrar(l ledger.KanonLedger) *DidRegistrar { return &DidRegistrar{ledger: l} }

// Create writes a DID Document. For simplicity, this assumes the DID id is provided in the doc.
func (r *DidRegistrar) Create(agentContext *context.AgentContext, doc *dids.DidDocument, metadata string) error {
	b, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	return r.ledger.RegisterDID(doc.Id, string(b), metadata)
}

func (r *DidRegistrar) Update(agentContext *context.AgentContext, doc *dids.DidDocument, metadata string) error {
	b, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	return r.ledger.UpdateDID(doc.Id, string(b), metadata)
}
