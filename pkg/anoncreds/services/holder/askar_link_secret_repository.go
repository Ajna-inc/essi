package holder

import (
    "context"
    agentcontext "github.com/ajna-inc/essi/pkg/core/context"
    "github.com/ajna-inc/essi/pkg/core/storage"
)

// HolderLinkSecretRecord is a storage record for link secrets compatible with core/storage
type HolderLinkSecretRecord struct {
    *storage.BaseRecord
    LinkSecretId string `json:"linkSecretId"`
    Value        string `json:"value"`
}

func NewHolderLinkSecretRecord(id string, value string) *HolderLinkSecretRecord {
    br := storage.NewBaseRecord("HolderLinkSecretRecord")
    rec := &HolderLinkSecretRecord{ BaseRecord: br, LinkSecretId: id, Value: value }
    rec.BaseRecord.SetTag("linkSecretId", id)
    return rec
}

// Ensure HolderLinkSecretRecord implements storage.Record via BaseRecord methods

// AskarHolderLinkSecretRepository implements LinkSecretRepository using core/storage
type AskarHolderLinkSecretRepository struct {
    storage storage.StorageService
}

func NewAskarHolderLinkSecretRepository(storage storage.StorageService) *AskarHolderLinkSecretRepository {
    return &AskarHolderLinkSecretRepository{ storage: storage }
}

func (r *AskarHolderLinkSecretRepository) Save(ctx *agentcontext.AgentContext, id string, linkSecret string) error {
    rec := NewHolderLinkSecretRecord(id, linkSecret)
    return r.storage.Save(context.Background(), rec)
}

func (r *AskarHolderLinkSecretRepository) Get(ctx *agentcontext.AgentContext, id string) (string, error) {
    q := storage.NewQuery().WithTag("linkSecretId", id)
    rec, err := r.storage.FindSingleByQuery(context.Background(), "HolderLinkSecretRecord", *q)
    if err != nil { return "", err }
    if cast, ok := rec.(*HolderLinkSecretRecord); ok { return cast.Value, nil }
    // fallback to JSON
    var tmp HolderLinkSecretRecord
    if b, jerr := rec.ToJSON(); jerr == nil { _ = tmp.FromJSON(b); return tmp.Value, nil }
    return "", err
}

func (r *AskarHolderLinkSecretRepository) Delete(ctx *agentcontext.AgentContext, id string) error {
    // Not strictly needed for tests; implement by finding record id and deleting by id
    q := storage.NewQuery().WithTag("linkSecretId", id)
    rec, err := r.storage.FindSingleByQuery(context.Background(), "HolderLinkSecretRecord", *q)
    if err != nil { return err }
    return r.storage.Delete(context.Background(), rec)
}

func (r *AskarHolderLinkSecretRepository) GetAll(ctx *agentcontext.AgentContext) (map[string]string, error) {
    res := map[string]string{}
    list, err := r.storage.FindByQuery(context.Background(), "HolderLinkSecretRecord", *storage.NewQuery())
    if err != nil { return res, err }
    for _, rec := range list {
        if cast, ok := rec.(*HolderLinkSecretRecord); ok { res[cast.LinkSecretId] = cast.Value; continue }
        var tmp HolderLinkSecretRecord; if b, jerr := rec.ToJSON(); jerr == nil { _ = tmp.FromJSON(b); res[tmp.LinkSecretId] = tmp.Value }
    }
    return res, nil
}


