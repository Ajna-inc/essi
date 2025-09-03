package services

import (
    "context"
    "encoding/json"
    "fmt"
    agentcontext "github.com/ajna-inc/essi/pkg/core/context"
    "github.com/ajna-inc/essi/pkg/core/storage"
)

// StorageConnectionRepository persists ConnectionRecord via core/storage
type StorageConnectionRepository struct {
    storage storage.StorageService
}

func NewStorageConnectionRepository(storage storage.StorageService) *StorageConnectionRepository {
    return &StorageConnectionRepository{ storage: storage }
}

func (r *StorageConnectionRepository) Save(ctx *agentcontext.AgentContext, record *ConnectionRecord) error {
    if record == nil { return fmt.Errorf("nil record") }
    // Ensure consistent record type and basic tags
    if record.BaseRecord == nil { record.BaseRecord = storage.NewBaseRecord("ConnectionRecord") } else { record.BaseRecord.Type = "ConnectionRecord" }
    if record.Tags == nil { record.Tags = map[string]string{} }
    if record.ID == "" && record.BaseRecord.GetId() != "" { record.ID = record.BaseRecord.GetId() }
    record.Tags["state"] = string(record.State)
    if record.Did != "" { record.Tags["did"] = record.Did }
    if record.TheirDid != "" { record.Tags["theirDid"] = record.TheirDid }
    if record.InvitationKey != "" { record.Tags["invitationKey"] = record.InvitationKey }
    if record.TheirRecipientKey != "" { record.Tags["theirRecipientKey"] = record.TheirRecipientKey }
    if record.OutOfBandId != "" { record.Tags["outOfBandId"] = record.OutOfBandId }
    return r.storage.Save(context.Background(), record)
}

func (r *StorageConnectionRepository) FindById(ctx *agentcontext.AgentContext, id string) (*ConnectionRecord, error) {
    rec, err := r.storage.GetById(context.Background(), "ConnectionRecord", id)
    if err != nil { return nil, err }
    return r.cast(rec)
}

func (r *StorageConnectionRepository) FindByOutOfBandId(ctx *agentcontext.AgentContext, oobId string) ([]*ConnectionRecord, error) {
    q := storage.NewQuery().WithTag("outOfBandId", oobId)
    list, err := r.storage.FindByQuery(context.Background(), "ConnectionRecord", *q)
    if err != nil { return nil, err }
    return r.castList(list), nil
}

func (r *StorageConnectionRepository) FindByDid(ctx *agentcontext.AgentContext, did string) (*ConnectionRecord, error) {
    // Search either Did or TheirDid by tags; store both as tags when saving
    q := storage.NewQuery().WithTag("did", did)
    rec, err := r.storage.FindSingleByQuery(context.Background(), "ConnectionRecord", *q)
    if err == nil { return r.cast(rec) }
    q2 := storage.NewQuery().WithTag("theirDid", did)
    rec2, err2 := r.storage.FindSingleByQuery(context.Background(), "ConnectionRecord", *q2)
    if err2 != nil { return nil, err2 }
    return r.cast(rec2)
}

func (r *StorageConnectionRepository) FindByInvitationKey(ctx *agentcontext.AgentContext, key string) (*ConnectionRecord, error) {
    q := storage.NewQuery().WithTag("invitationKey", key)
    rec, err := r.storage.FindSingleByQuery(context.Background(), "ConnectionRecord", *q)
    if err != nil { return nil, err }
    return r.cast(rec)
}

func (r *StorageConnectionRepository) GetAll(ctx *agentcontext.AgentContext) ([]*ConnectionRecord, error) {
    list, err := r.storage.FindByQuery(context.Background(), "ConnectionRecord", *storage.NewQuery())
    if err != nil { return nil, err }
    return r.castList(list), nil
}

func (r *StorageConnectionRepository) Update(ctx *agentcontext.AgentContext, record *ConnectionRecord) error {
    if record == nil { return fmt.Errorf("nil record") }
    if record.BaseRecord == nil { record.BaseRecord = storage.NewBaseRecord("ConnectionRecord") } else { record.BaseRecord.Type = "ConnectionRecord" }
    if record.Tags == nil { record.Tags = map[string]string{} }
    record.Tags["state"] = string(record.State)
    if record.Did != "" { record.Tags["did"] = record.Did }
    if record.TheirDid != "" { record.Tags["theirDid"] = record.TheirDid }
    if record.InvitationKey != "" { record.Tags["invitationKey"] = record.InvitationKey }
    if record.TheirRecipientKey != "" { record.Tags["theirRecipientKey"] = record.TheirRecipientKey }
    if record.OutOfBandId != "" { record.Tags["outOfBandId"] = record.OutOfBandId }
    return r.storage.Update(context.Background(), record)
}

func (r *StorageConnectionRepository) FindByTheirRecipientKey(ctx *agentcontext.AgentContext, key string) (*ConnectionRecord, error) {
    q := storage.NewQuery().WithTag("theirRecipientKey", key)
    rec, err := r.storage.FindSingleByQuery(context.Background(), "ConnectionRecord", *q)
    if err != nil { return nil, err }
    return r.cast(rec)
}

func (r *StorageConnectionRepository) Delete(ctx *agentcontext.AgentContext, id string) error {
    return r.storage.DeleteById(context.Background(), "ConnectionRecord", id)
}

func (r *StorageConnectionRepository) cast(rec storage.Record) (*ConnectionRecord, error) {
    if cr, ok := rec.(*ConnectionRecord); ok { return cr, nil }
    var out ConnectionRecord
    b, err := rec.ToJSON(); if err != nil { return nil, err }
    if err := json.Unmarshal(b, &out); err != nil { return nil, err }
    return &out, nil
}

func (r *StorageConnectionRepository) castList(list []storage.Record) []*ConnectionRecord {
    out := make([]*ConnectionRecord, 0, len(list))
    for _, rec := range list {
        if cr, err := r.cast(rec); err == nil { out = append(out, cr) }
    }
    return out
}


