package repository

import (
	"encoding/json"
	"fmt"
	"time"

	corectx "github.com/ajna-inc/essi/pkg/core/context"
	corestorage "github.com/ajna-inc/essi/pkg/core/storage"
	"github.com/ajna-inc/essi/pkg/dids"
)

// ReceivedDidRecord stores a DID and its DID Document received from a counterparty
type ReceivedDidRecord struct {
	*corestorage.BaseRecord
	Did    string            `json:"did"`
	DidDoc *dids.DidDocument `json:"didDoc,omitempty"`
}

func (r *ReceivedDidRecord) ToJSON() ([]byte, error)    { return json.Marshal(r) }
func (r *ReceivedDidRecord) FromJSON(data []byte) error { return json.Unmarshal(data, r) }

// ReceivedDidRepository provides CRUD for received DID documents
type ReceivedDidRepository struct{ repo *corestorage.BaseRepository }

func NewReceivedDidRepository(storage corestorage.StorageService) *ReceivedDidRepository {
	return &ReceivedDidRepository{repo: corestorage.NewBaseRepository(storage, "ReceivedDidRecord")}
}

func (r *ReceivedDidRepository) Save(ctx *corectx.AgentContext, did string, doc *dids.DidDocument) error {
	id := did
	rec := &ReceivedDidRecord{
		BaseRecord: &corestorage.BaseRecord{ID: id, Type: "ReceivedDidRecord", CreatedAt: time.Now(), UpdatedAt: time.Now(), Tags: map[string]string{"did": did}},
		Did:        did,
		DidDoc:     doc,
	}
	return r.repo.Save(ctx.Context, rec)
}

func (r *ReceivedDidRepository) Update(ctx *corectx.AgentContext, did string, doc *dids.DidDocument) error {
	if did == "" {
		return fmt.Errorf("did required")
	}
	rec, err := r.FindByDid(ctx, did)
	if err != nil {
		return err
	}
	if rec == nil {
		return r.Save(ctx, did, doc)
	}
	rec.DidDoc = doc
	rec.UpdatedAt = time.Now()
	return r.repo.Update(ctx.Context, rec)
}

func (r *ReceivedDidRepository) FindByDid(ctx *corectx.AgentContext, did string) (*ReceivedDidRecord, error) {
	all, err := r.repo.GetAll(ctx.Context)
	if err != nil {
		return nil, err
	}
	for _, rr := range all {
		if rec, ok := rr.(*ReceivedDidRecord); ok && rec.Did == did {
			return rec, nil
		}
	}
	return nil, nil
}
