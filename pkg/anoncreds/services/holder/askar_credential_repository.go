package holder

import (
    "context"
    "encoding/json"
    "fmt"
    agentcontext "github.com/ajna-inc/essi/pkg/core/context"
    "github.com/ajna-inc/essi/pkg/core/storage"
    svc "github.com/ajna-inc/essi/pkg/anoncreds/services"
)

// HolderCredentialRecord is a storage record for anoncreds credentials (processed JSON)
type HolderCredentialRecord struct {
    *storage.BaseRecord
    Id                     string                 `json:"id"`
    Credential             string                 `json:"credential"`
    CredentialDefinitionId string                 `json:"credentialDefinitionId"`
    SchemaId               string                 `json:"schemaId"`
    RevocationRegistryId   string                 `json:"revocationRegistryId,omitempty"`
    CredentialRevocationId string                 `json:"credentialRevocationId,omitempty"`
    Metadata               map[string]interface{} `json:"metadata,omitempty"`
}

func NewHolderCredentialRecord(id string) *HolderCredentialRecord {
    br := storage.NewBaseRecord("HolderCredentialRecord")
    rec := &HolderCredentialRecord{ BaseRecord: br, Id: id, Metadata: map[string]interface{}{} }
    rec.BaseRecord.SetTag("credentialId", id)
    return rec
}

type AskarHolderCredentialRepository struct{ storage storage.StorageService }

func NewAskarHolderCredentialRepository(storage storage.StorageService) *AskarHolderCredentialRepository {
    return &AskarHolderCredentialRepository{ storage: storage }
}

func (r *AskarHolderCredentialRepository) Save(ctx *agentcontext.AgentContext, record *CredentialRecord) error {
    rec := NewHolderCredentialRecord(record.Id)
    rec.Credential = record.Credential
    rec.CredentialDefinitionId = record.CredentialDefinitionId
    rec.SchemaId = record.SchemaId
    rec.RevocationRegistryId = record.RevocationRegistryId
    rec.CredentialRevocationId = record.CredentialRevocationId
    rec.Metadata = record.Metadata
    rec.BaseRecord.SetTag("credentialDefinitionId", record.CredentialDefinitionId)
    rec.BaseRecord.SetTag("schemaId", record.SchemaId)
    return r.storage.Save(context.Background(), rec)
}

func (r *AskarHolderCredentialRepository) Update(ctx *agentcontext.AgentContext, record *CredentialRecord) error {
    // Fetch existing record by credentialId tag
    q := storage.NewQuery().WithTag("credentialId", record.Id)
    existing, err := r.storage.FindSingleByQuery(context.Background(), "HolderCredentialRecord", *q)
    if err != nil { return err }
    var rec HolderCredentialRecord
    if cast, ok := existing.(*HolderCredentialRecord); ok { rec = *cast } else { b, _ := existing.ToJSON(); _ = json.Unmarshal(b, &rec) }
    rec.Credential = record.Credential
    rec.CredentialDefinitionId = record.CredentialDefinitionId
    rec.SchemaId = record.SchemaId
    rec.RevocationRegistryId = record.RevocationRegistryId
    rec.CredentialRevocationId = record.CredentialRevocationId
    rec.Metadata = record.Metadata
    return r.storage.Update(context.Background(), &rec)
}

func (r *AskarHolderCredentialRepository) GetById(ctx *agentcontext.AgentContext, id string) (*CredentialRecord, error) {
    q := storage.NewQuery().WithTag("credentialId", id)
    rec, err := r.storage.FindSingleByQuery(context.Background(), "HolderCredentialRecord", *q)
    if err != nil { return nil, err }
    return r.toCredentialRecord(rec)
}

func (r *AskarHolderCredentialRepository) GetByFilter(ctx *agentcontext.AgentContext, filter *svc.CredentialFilter) ([]*CredentialRecord, error) {
    q := storage.NewQuery()
    if filter != nil {
        if filter.SchemaId != "" { q.WithTag("schemaId", filter.SchemaId) }
        if filter.CredentialDefinitionId != "" { q.WithTag("credentialDefinitionId", filter.CredentialDefinitionId) }
    }
    list, err := r.storage.FindByQuery(context.Background(), "HolderCredentialRecord", *q)
    if err != nil { return nil, err }
    out := make([]*CredentialRecord, 0, len(list))
    for _, rec := range list {
        if cr, err := r.toCredentialRecord(rec); err == nil { out = append(out, cr) }
    }
    return out, nil
}

func (r *AskarHolderCredentialRepository) GetAll(ctx *agentcontext.AgentContext) ([]*CredentialRecord, error) {
    list, err := r.storage.FindByQuery(context.Background(), "HolderCredentialRecord", *storage.NewQuery())
    if err != nil { return nil, err }
    out := make([]*CredentialRecord, 0, len(list))
    for _, rec := range list { if cr, err := r.toCredentialRecord(rec); err == nil { out = append(out, cr) } }
    return out, nil
}

func (r *AskarHolderCredentialRepository) Delete(ctx *agentcontext.AgentContext, id string) error {
    q := storage.NewQuery().WithTag("credentialId", id)
    rec, err := r.storage.FindSingleByQuery(context.Background(), "HolderCredentialRecord", *q)
    if err != nil { return err }
    return r.storage.Delete(context.Background(), rec)
}

func (r *AskarHolderCredentialRepository) toCredentialRecord(rec storage.Record) (*CredentialRecord, error) {
    var tmp HolderCredentialRecord
    if cast, ok := rec.(*HolderCredentialRecord); ok { tmp = *cast } else { b, _ := rec.ToJSON(); _ = json.Unmarshal(b, &tmp) }
    if tmp.Id == "" { return nil, fmt.Errorf("invalid record") }
    return &CredentialRecord{
        Id: tmp.Id,
        Credential: tmp.Credential,
        CredentialDefinitionId: tmp.CredentialDefinitionId,
        SchemaId: tmp.SchemaId,
        RevocationRegistryId: tmp.RevocationRegistryId,
        CredentialRevocationId: tmp.CredentialRevocationId,
        Metadata: tmp.Metadata,
    }, nil
}


