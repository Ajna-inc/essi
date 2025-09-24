package kanon

import (
	regsvc "github.com/ajna-inc/essi/pkg/anoncreds/registry"
	"github.com/ajna-inc/essi/pkg/core/di"
	"github.com/ajna-inc/essi/pkg/kanon/ledger"
)

func AnonCredsRegistryFactory() func(di.DependencyManager) regsvc.Registry {
	return func(dm di.DependencyManager) regsvc.Registry {
		any, err := dm.Resolve(di.TokenKanonLedger)
		if err != nil {
			return nil
		}
		l, ok := any.(ledger.KanonLedger)
		if !ok {
			return nil
		}
		return NewRegistry(l)
	}
}


