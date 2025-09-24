package dids

import (
	"encoding/json"

	ctxpkg "github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/core/di"
	coreDids "github.com/ajna-inc/essi/pkg/dids"
	"github.com/ajna-inc/essi/pkg/kanon"
)

// KanonDidResolver resolves did:kanon DIDs using the Kanon ledger
type KanonDidResolver struct {
	// no fields; resolves dependencies via agent context
}

// NewKanonDidResolver creates a new Kanon DID resolver
func NewKanonDidResolver() *KanonDidResolver { return &KanonDidResolver{} }

func (r *KanonDidResolver) SupportedMethods() []string { return []string{"kanon"} }

func (r *KanonDidResolver) Resolve(agentContext *ctxpkg.AgentContext, did string, options *coreDids.DidResolutionOptions) (*coreDids.DidResolutionResult, error) {
	// Resolve EthereumLedgerService from DI
	var eth *kanon.EthereumLedgerService
	if agentContext != nil && agentContext.DependencyManager != nil {
		if dm, ok := agentContext.DependencyManager.(di.DependencyManager); ok {
			if any, err := dm.Resolve(di.TokenKanonEthereumLedgerService); err == nil {
				eth, _ = any.(*kanon.EthereumLedgerService)
			}
		}
	}
	if eth == nil {
		return coreDids.NewBaseDidResolver([]string{"kanon"}).CreateDidResolutionError("internalError", "kanon ledger not available from DI"), nil
	}

	ledger := eth.GetLedger()
	docJson, _, err := ledger.GetDID(did)
	if err != nil {
		return &coreDids.DidResolutionResult{DidResolutionMetadata: &coreDids.DidResolutionMetadata{Error: coreDids.DidResolutionErrorNotFound, ErrorMessage: err.Error()}}, nil
	}
	var doc coreDids.DidDocument
	if err := json.Unmarshal([]byte(docJson), &doc); err != nil {
		return &coreDids.DidResolutionResult{DidResolutionMetadata: &coreDids.DidResolutionMetadata{Error: coreDids.DidResolutionErrorInternalError, ErrorMessage: err.Error()}}, nil
	}
	base := coreDids.NewBaseDidResolver([]string{"kanon"})
	return base.CreateDidResolutionResult(&doc), nil
}
