package module

import (
	"github.com/ajna-inc/essi/pkg/didcomm/modules/proofs"
	"github.com/ajna-inc/essi/pkg/didcomm/modules/proofs/models"
)

// ProofsModuleConfig holds the configuration for the Proofs module
type ProofsModuleConfig struct {
	// AutoAcceptProofs defines the auto-acceptance strategy for proofs
	AutoAcceptProofs string // "always", "contentApproved", or "never"
}

// NewProofsModule creates a new proofs module with the given configuration
func NewProofsModule(config *ProofsModuleConfig) *proofs.ProofsModule {
	if config == nil {
		config = &ProofsModuleConfig{
			AutoAcceptProofs: "always",
		}
	}

	// Map string config to enum
	autoAccept := models.AutoAcceptNever
	switch config.AutoAcceptProofs {
	case "always":
		autoAccept = models.AutoAcceptAlways
	case "contentApproved":
		autoAccept = models.AutoAcceptContentApproved
	case "never":
		autoAccept = models.AutoAcceptNever
	}

	proofsConfig := &proofs.ProofsModuleConfig{
		AutoAcceptProofs: autoAccept,
	}

	return proofs.NewProofsModule(proofsConfig)
}