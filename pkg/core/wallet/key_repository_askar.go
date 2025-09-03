package wallet

import (
    "context"
    "encoding/json"
    "fmt"
    agentcontext "github.com/ajna-inc/essi/pkg/core/context"
    "github.com/ajna-inc/essi/pkg/core/storage"
)

// StorageKeyRepository stores KeyRecord via core/storage
type StorageKeyRepository struct{ storage storage.StorageService }

func NewStorageKeyRepository(storage storage.StorageService) *StorageKeyRepository { return &StorageKeyRepository{ storage: storage } }

func (r *StorageKeyRepository) ctxWithAgent(ctx *agentcontext.AgentContext) context.Context {
    return context.WithValue(context.Background(), "agentContext", ctx)
}

func (r *StorageKeyRepository) Save(ctx *agentcontext.AgentContext, record *KeyRecord) error {
    if record == nil || record.Key == nil { return fmt.Errorf("invalid key record") }
    if record.BaseRecord == nil { record.BaseRecord = storage.NewBaseRecord("Key") } else { record.BaseRecord.Type = "Key" }
    if record.Tags == nil { record.Tags = map[string]string{} }
    record.Tags["keyType"] = string(record.Key.Type)
    return r.storage.Save(r.ctxWithAgent(ctx), record)
}

func (r *StorageKeyRepository) FindById(ctx *agentcontext.AgentContext, id string) (*KeyRecord, error) {
    rec, err := r.storage.GetById(r.ctxWithAgent(ctx), "Key", id)
    if err != nil { return nil, err }
    return r.cast(rec)
}

func (r *StorageKeyRepository) FindByPublicKey(ctx *agentcontext.AgentContext, publicKey []byte) (*KeyRecord, error) {
    // Note: Binary match via tag isn’t feasible; store base58 in tags if needed. For now scan all.
    list, err := r.storage.FindByQuery(r.ctxWithAgent(ctx), "Key", *storage.NewQuery())
    if err != nil { return nil, err }
    for _, rec := range list {
        if kr, err := r.cast(rec); err == nil {
            if string(kr.Key.PublicKey) == string(publicKey) { return kr, nil }
        }
    }
    return nil, fmt.Errorf("not found")
}

func (r *StorageKeyRepository) Delete(ctx *agentcontext.AgentContext, id string) error {
    return r.storage.DeleteById(r.ctxWithAgent(ctx), "Key", id)
}

func (r *StorageKeyRepository) GetAll(ctx *agentcontext.AgentContext) ([]*KeyRecord, error) {
    list, err := r.storage.FindByQuery(r.ctxWithAgent(ctx), "Key", *storage.NewQuery())
    if err != nil { return nil, err }
    out := make([]*KeyRecord, 0, len(list))
    for _, rec := range list { if kr, err := r.cast(rec); err == nil { out = append(out, kr) } }
    return out, nil
}

func (r *StorageKeyRepository) cast(rec storage.Record) (*KeyRecord, error) {
    if kr, ok := rec.(*KeyRecord); ok { return kr, nil }
    var out KeyRecord
    b, err := rec.ToJSON(); if err != nil { return nil, err }
    if err := json.Unmarshal(b, &out); err != nil { return nil, err }
    return &out, nil
}


