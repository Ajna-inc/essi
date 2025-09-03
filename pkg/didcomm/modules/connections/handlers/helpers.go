package handlers

import (
	"fmt"

	corectx "github.com/ajna-inc/essi/pkg/core/context"
	"github.com/ajna-inc/essi/pkg/core/di"
	coreevents "github.com/ajna-inc/essi/pkg/core/events"
	"github.com/ajna-inc/essi/pkg/core/encoding"
	"github.com/ajna-inc/essi/pkg/core/wallet"
	services "github.com/ajna-inc/essi/pkg/didcomm/modules/connections/services"
	oob "github.com/ajna-inc/essi/pkg/didcomm/modules/oob"
	"github.com/ajna-inc/essi/pkg/didcomm/transport"
	"github.com/ajna-inc/essi/pkg/dids"
)

// Local invitation key cache removed; derive per record/service
// var invitationKeys map[string]*wallet.Key

// Helpers to resolve services from the inbound context (DI)
func getConnectionService(ctx *transport.InboundMessageContext) *services.ConnectionService {
	if ctx != nil && ctx.TypedDI != nil {
		if dep, err := ctx.TypedDI.Resolve(di.TokenConnectionService); err == nil {
			if svc, ok := dep.(*services.ConnectionService); ok {
				return svc
			}
		}
	}
	return nil
}

func getDidExchangeProtocol(ctx *transport.InboundMessageContext) *services.DidExchangeProtocol {
	if ctx != nil && ctx.TypedDI != nil {
		if dep, err := ctx.TypedDI.Resolve(di.TokenDidExchangeProtocol); err == nil {
			if s, ok := dep.(*services.DidExchangeProtocol); ok {
				return s
			}
		}
	}
	return nil
}

func getMessageSender(ctx *transport.InboundMessageContext) *transport.MessageSender {
	if ctx != nil && ctx.TypedDI != nil {
		if dep, err := ctx.TypedDI.Resolve(di.TokenMessageSender); err == nil {
			if s, ok := dep.(*transport.MessageSender); ok {
				return s
			}
		}
	}
	return nil
}

func getWalletService(ctx *transport.InboundMessageContext) *wallet.WalletService {
	if ctx != nil && ctx.TypedDI != nil {
		if dep, err := ctx.TypedDI.Resolve(di.TokenWalletService); err == nil {
			if s, ok := dep.(*wallet.WalletService); ok {
				return s
			}
		}
	}
	return nil
}

func getEventBus(ctx *transport.InboundMessageContext) coreevents.Bus {
	if ctx != nil && ctx.TypedDI != nil {
		if dep, err := ctx.TypedDI.Resolve(di.TokenEventBusService); err == nil {
			if bus, ok := dep.(coreevents.Bus); ok {
				return bus
			}
		}
	}
	return nil
}

func getDidRotateService(ctx *transport.InboundMessageContext) *services.DidRotateService {
	if ctx != nil && ctx.TypedDI != nil {
		if dep, err := ctx.TypedDI.Resolve(di.TokenDidRotateService); err == nil {
			if s, ok := dep.(*services.DidRotateService); ok {
				return s
			}
		}
	}
	return nil
}

func getOobRepository(agentCtx *corectx.AgentContext) *oob.OutOfBandRepository {
	if agentCtx != nil && agentCtx.DependencyManager != nil {
		if dm, ok := agentCtx.DependencyManager.(di.DependencyManager); ok {
			if dep, err := dm.Resolve(di.TokenOutOfBandRepository); err == nil {
				if repo, ok := dep.(*oob.OutOfBandRepository); ok {
					return repo
				}
			}
		}
	}
	return nil
}

// Helper function to create a peer DID from an Ed25519 public key
func createPeerDidFromKey(publicKey []byte) (string, error) {
	if len(publicKey) == 0 {
		return "", fmt.Errorf("public key cannot be empty")
	}

	// Create peer:0 DID using the multibase encoding
	fingerprint := "z" + encoding.EncodeBase58(publicKey)
	return fmt.Sprintf("did:peer:0%s", fingerprint), nil
}

// Helper function to create a DID document for the peer DID
func createDidDocumentForPeerDid(peerDid string, publicKey []byte, serviceEndpoint string) (*dids.DidDoc, error) {
	didDoc := dids.NewDidDoc(peerDid)

	vmID := peerDid + "#key-1"
	pk := &dids.PublicKey{
		Id:              vmID,
		Type:            dids.VerificationMethodTypeEd25519VerificationKey2018,
		Controller:      peerDid,
		PublicKeyBase58: encoding.EncodeBase58(publicKey),
	}
	didDoc.AddPublicKey(pk)

	// Add authentication referencing the public key
	didDoc.AddAuthentication(&dids.Authentication{Type: dids.AuthenticationTypeEd25519Signature2018, PublicKey: pk})

	if serviceEndpoint != "" {
		vmId := peerDid + "#key-1"
		service := &dids.Service{
			Id:              peerDid + "#service-1",
			Type:            "did-communication",
			ServiceEndpoint: serviceEndpoint,
			// Use verification method id reference, not raw base58 key
			RecipientKeys: []string{vmId},
		}
		didDoc.AddService(service)
	}

	return didDoc, nil
}
