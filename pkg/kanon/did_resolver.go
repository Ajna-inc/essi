package kanon

import (
	"encoding/json"
	"regexp"

	"github.com/ajna-inc/essi/pkg/core/context"
	dids "github.com/ajna-inc/essi/pkg/dids"
	"github.com/ajna-inc/essi/pkg/kanon/ledger"
)

// DidResolver resolves did:kanon DIDs using the Kanon ledger.
type DidResolver struct {
	methods []string
	rx      *regexp.Regexp
	ledger  ledger.KanonLedger
}

func NewDidResolver(l ledger.KanonLedger) *DidResolver {
	return &DidResolver{
		methods: []string{"kanon"},
		rx:      regexp.MustCompile(`^did:kanon:`),
		ledger:  l,
	}
}

func (r *DidResolver) SupportedMethods() []string { return r.methods }

func (r *DidResolver) Resolve(ctx *context.AgentContext, did string, options *dids.DidResolutionOptions) (*dids.DidResolutionResult, error) {
	if !r.rx.MatchString(did) {
		return dids.NewBaseDidResolver(r.methods).CreateDidResolutionError(dids.DidResolutionErrorMethodNotSupported, "unsupported method"), nil
	}
	raw, _, err := r.ledger.GetDID(did)
	if err != nil {
		return dids.NewBaseDidResolver(r.methods).CreateDidResolutionError(dids.DidResolutionErrorNotFound, err.Error()), nil
	}
	var doc dids.DidDocument
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return dids.NewBaseDidResolver(r.methods).CreateDidResolutionError(dids.DidResolutionErrorInternalError, err.Error()), nil
	}
	return dids.NewBaseDidResolver(r.methods).CreateDidResolutionResult(&doc), nil
}
