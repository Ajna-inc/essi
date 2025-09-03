package operations

import (
	"fmt"
	"log"
	"time"

	"github.com/ajna-inc/essi/pkg/dids"
	"github.com/ajna-inc/essi/pkg/dids/api"
)

// DIDOperations handles DID-related operations
type DIDOperations struct {
	api     *api.DidsApi
	metrics *Metrics
}

// NewDIDOperations creates a new DID operations handler
func NewDIDOperations(didsApi *api.DidsApi, metrics *Metrics) *DIDOperations {
	return &DIDOperations{
		api:     didsApi,
		metrics: metrics,
	}
}

// CreateDID creates a new DID with the specified method and options
func (d *DIDOperations) CreateDID(method string, options map[string]interface{}) (*dids.DidCreateResult, error) {
	startTime := time.Now()
	defer func() {
		if d.metrics != nil {
			d.metrics.Record(fmt.Sprintf("create_did_%s", method), time.Since(startTime))
		}
	}()

	result, err := d.api.Create(&dids.DidCreateOptions{
		Method:  method,
		Options: options,
	})
	
	if err != nil {
		return nil, fmt.Errorf("failed to create DID: %w", err)
	}
	
	log.Printf("✅ Created DID: %s", result.Did)
	return result, nil
}

// CreateKanonIssuerDID creates a new Kanon issuer DID
func (d *DIDOperations) CreateKanonIssuerDID(suffix string) (string, error) {
	issuerDid := fmt.Sprintf("did:kanon:testnet:issuer-%s", suffix)
	
	_, err := d.CreateDID("kanon", map[string]interface{}{
		"did": issuerDid,
	})
	
	if err != nil {
		return "", err
	}
	
	return issuerDid, nil
}

// CreateKanonIssuerDIDWithTimestamp creates a new Kanon issuer DID with a timestamp suffix
func (d *DIDOperations) CreateKanonIssuerDIDWithTimestamp() (string, error) {
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	return d.CreateKanonIssuerDID(suffix)
}

// CreatePeerDID creates a new peer DID
func (d *DIDOperations) CreatePeerDID() (*dids.DidCreateResult, error) {
	return d.CreateDID("peer", nil)
}

// CreateKeyDID creates a new key DID
func (d *DIDOperations) CreateKeyDID() (*dids.DidCreateResult, error) {
	return d.CreateDID("key", nil)
}

